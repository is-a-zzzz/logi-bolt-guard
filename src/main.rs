//! logi-bolt-guard — manage the pairing table of a Logi Bolt USB receiver (046D:C548)
//! via raw HID++ register access. No Logitech software required.
//!
//! Protocol cross-validated against Solaar (lib/logitech_receiver) and OpenLogi
//! (crates/openlogi-hidpp), then confirmed live against a receiver:
//!
//! - Register READS (request SubId 0x81/0x83) must go out as short messages
//!   (report 0x10, 7 bytes); the Bolt receiver answers long-framed reads with
//!   INVALID_SUB_ID (0x01). Register WRITES for the paging space (SubId 0x82)
//!   go out as long messages (report 0x11, 20 bytes); plain register-0 writes
//!   (SubId 0x80) go short.
//! - 16-bit registers fold the 0x200 paging bit into the request id:
//!   0x2B5 -> 0x83B5, 0x2C1 -> 0x82C1, 0x2FB -> 0x83FB.
//! - Replies come back on report 0x10 or 0x11, echoing the request id; error
//!   replies use SubId 0x8F + echoed id + one error code byte. An error 0x08
//!   on the pairing-info read means the slot is empty.
//! - Receiver-pushed notifications (report 0x10/0x11, SubId 0x40..=0x4F) must
//!   be enabled via register 0x00: WIRELESS 0x000100 | SOFTWARE_PRESENT
//!   0x000800. SubId 0x41 carries link up/down per device: address 0x10 = Bolt
//!   protocol, flags bit6 (0x40) set = link down, bit5 = encrypted, followed
//!   by the device wpid (little-endian).
//! - On macOS, timed HID reads are unreliable (may block forever), so the
//!   device is opened non-blocking and deadlines are enforced by polling.
//!
//! Usage:
//!   logi-bolt-guard                    list paired devices
//!   logi-bolt-guard ping               ping device slots 1..=6 (shows the live link)
//!   logi-bolt-guard unpair N           remove the pairing in slot N
//!   logi-bolt-guard verify             check the receiver is in a clean, sane state
//!   logi-bolt-guard guard [--allow <unit-id>[,<unit-id>...]] [--interval <secs>] [--once]
//!                              watch the pairing table and eject anything
//!                              that is not an allowed device (or duplicate
//!                              slots of one); `--once` does a single sweep

use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant};

use hidapi::HidApi;

const VID: u16 = 0x046D;
const PID: u16 = 0xC548;

const RECEIVER: u8 = 0xFF; // HID++ device number of the receiver itself
const MAX_SLOTS: u8 = 6;

const REG_NOTIFICATIONS: u16 = 0x00; // read/write: notification enable flags
const REG_RECEIVER_INFO: u16 = 0x2B5; // sub 0x50+n: pairing info, 0x60+n/0x01: name
const REG_BOLT_PAIRING: u16 = 0x2C1; // write [0x03, slot]: unpair
const REG_BOLT_UNIQUE_ID: u16 = 0x2FB;

const NOTIF_WIRELESS: u32 = 0x000100;
const NOTIF_SOFTWARE_PRESENT: u32 = 0x000800;

const READ_TIMEOUT: Duration = Duration::from_millis(1200);
const PING_TIMEOUT: Duration = Duration::from_millis(600);

const ERR_INVALID_SUB_ID: u8 = 0x01;
const ERR_UNKNOWN_DEVICE: u8 = 0x08;

#[derive(Debug)]
enum Error {
    NoReceiver,
    Hid(hidapi::HidError),
    WriteFailed,
    Hidpp { request: u16, code: u8 },
    Timeout { request: u16 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoReceiver => write!(f, "no Logitech Bolt receiver 046D:C548 found"),
            Error::Hid(e) => write!(f, "hid error: {e}"),
            Error::WriteFailed => write!(f, "hid write failed"),
            Error::Hidpp { request, code } => {
                let name = match *code {
                    ERR_INVALID_SUB_ID => "invalid sub-id",
                    ERR_UNKNOWN_DEVICE => "unknown device",
                    _ => "receiver error",
                };
                write!(f, "HID++ {name} ({code:#04x}) for request {request:#06x}")
            }
            Error::Timeout { request } => write!(f, "timeout on request {request:#06x}"),
        }
    }
}

impl From<hidapi::HidError> for Error {
    fn from(e: hidapi::HidError) -> Self {
        Error::Hid(e)
    }
}

/// Build the HID++ wire frame for a register request.
///
/// Short 7-byte frame for register reads (SubId 0x81/0x83) and plain
/// register-0 writes (SubId 0x80) with up to 3 param bytes; long 20-byte
/// frame for paging-space writes (SubId 0x82) or oversized params.
fn make_frame(devnum: u8, request_id: u16, params: &[u8]) -> Vec<u8> {
    let sub_id = (request_id >> 8) as u8;
    let short = (sub_id == 0x80 || sub_id == 0x81 || sub_id == 0x83) && params.len() <= 3;
    let mut frame = Vec::with_capacity(if short { 7 } else { 20 });
    frame.push(if short { 0x10 } else { 0x11 });
    frame.push(devnum);
    frame.push(sub_id);
    frame.push((request_id & 0xFF) as u8);
    frame.extend_from_slice(params);
    frame.resize(if short { 7 } else { 20 }, 0);
    frame
}

struct Bolt {
    dev: hidapi::HidDevice,
}

impl Bolt {
    fn open(api: &HidApi) -> Result<Self, Error> {
        let info = api
            .device_list()
            .find(|d| d.vendor_id() == VID && d.product_id() == PID && d.usage_page() == 0xFF00)
            .ok_or(Error::NoReceiver)?;
        let dev = api.open_path(info.path())?;
        // timed reads can hang forever on macOS; poll with our own deadline
        dev.set_blocking_mode(false)?;
        Ok(Bolt { dev })
    }

    fn drain(&self) {
        let mut buf = [0u8; 64];
        while matches!(self.dev.read(&mut buf), Ok(n) if n > 0) {}
    }

    /// Send one register request, return the reply payload (bytes after the
    /// two-byte request-id echo — for RECEIVER_INFO reads this still starts
    /// with the echoed sub-register byte).
    fn xfer(&self, devnum: u8, request_id: u16, params: &[u8], timeout: Duration) -> Result<Vec<u8>, Error> {
        let frame = make_frame(devnum, request_id, params);
        self.xfer_frame(&frame, devnum, request_id, timeout)
    }

    fn xfer_frame(
        &self,
        frame: &[u8],
        devnum: u8,
        request_id: u16,
        timeout: Duration,
    ) -> Result<Vec<u8>, Error> {
        self.drain();
        if self.dev.write(frame)? == 0 {
            return Err(Error::WriteFailed);
        }
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Timeout { request: request_id });
            }
            let mut buf = [0u8; 64];
            let n = match self.dev.read(&mut buf) {
                Ok(n) => n,
                Err(_) => {
                    sleep(Duration::from_millis(20));
                    continue;
                }
            };
            if n < 6 || (buf[0] != 0x10 && buf[0] != 0x11) || buf[1] != devnum {
                sleep(Duration::from_millis(5));
                continue; // unrelated traffic / notification
            }
            let echoed = u16::from_be_bytes([buf[2], buf[3]]);
            if buf[2] == 0x8F {
                if echoed == request_id {
                    return Err(Error::Hidpp { request: request_id, code: buf[5] });
                }
                continue;
            }
            if echoed == request_id {
                return Ok(buf[4..n].to_vec());
            }
        }
    }

    fn read_reg(&self, register: u16, params: &[u8]) -> Result<Vec<u8>, Error> {
        self.xfer(RECEIVER, 0x8100 | (register & 0x2FF), params, READ_TIMEOUT)
    }

    fn write_reg(&self, register: u16, params: &[u8]) -> Result<Vec<u8>, Error> {
        self.xfer(RECEIVER, 0x8000 | (register & 0x2FF), params, READ_TIMEOUT)
    }

    /// Enable/disable receiver notifications; returns the flags read back.
    /// Plain register-0 writes are normally short-framed, but fall back to a
    /// long frame if the receiver rejects the short one.
    fn set_notifications(&self, enable: bool) -> Result<Vec<u8>, Error> {
        let flags = if enable { NOTIF_WIRELESS | NOTIF_SOFTWARE_PRESENT } else { 0 };
        let params = [(flags >> 16) as u8, (flags >> 8) as u8, flags as u8];
        let request = 0x8000u16 | (REG_NOTIFICATIONS & 0x2FF);
        match self.xfer(RECEIVER, request, &params, READ_TIMEOUT) {
            Ok(_) => {}
            Err(Error::Hidpp { code: ERR_INVALID_SUB_ID, .. }) => {
                let mut long = make_frame(RECEIVER, request, &params);
                long[0] = 0x11;
                long.resize(20, 0);
                self.xfer_frame(&long, RECEIVER, request, READ_TIMEOUT)?;
            }
            Err(e) => return Err(e),
        }
        let readback = self.read_reg(REG_NOTIFICATIONS, &[])?;
        Ok(readback.iter().take(3).copied().collect())
    }

    /// HID++ 2.0 root ping on a device slot: `Some(version)` when a device is
    /// linked and awake, `None` when the slot stays silent.
    fn ping(&self, devnum: u8) -> Result<Option<String>, Error> {
        match self.xfer(devnum, 0x0010, &[0x00, 0x00, 0xAB], PING_TIMEOUT) {
            Ok(p) if p.len() >= 2 => Ok(Some(format!("{}.{}", p[0], p[1]))),
            Ok(_) => Ok(Some("?".into())),
            Err(Error::Hidpp { code, .. }) => Ok(Some(format!("1.0 (err {code:#04x})"))),
            Err(Error::Timeout { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list_paired(&self) -> Result<Vec<PairedDevice>, Error> {
        let mut out = Vec::new();
        for slot in 1..=MAX_SLOTS {
            let info = match self.read_reg(REG_RECEIVER_INFO, &[0x50 + slot]) {
                Ok(v) if v.len() >= 8 => v,
                _ => continue, // empty slot (error 0x08) or unusable reply
            };
            let kind = info[1] & 0x0F;
            let wpid = ((info[3] as u16) << 8) | info[2] as u16;
            let unit_id = [info[4], info[5], info[6], info[7]];
            let name = self
                .read_reg(REG_RECEIVER_INFO, &[0x60 + slot, 0x01])
                .ok()
                .filter(|cn| cn.len() >= 3)
                .map(|cn| {
                    let len = (cn[2] as usize).min(13).min(cn.len() - 3);
                    String::from_utf8_lossy(&cn[3..3 + len]).into_owned()
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "(unreadable)".into());
            out.push(PairedDevice { slot, name, kind, wpid, unit_id });
        }
        Ok(out)
    }

    fn unpair(&self, slot: u8) -> Result<(), Error> {
        self.write_reg(REG_BOLT_PAIRING, &[0x03, slot]).map(|_| ())
    }

    /// Non-blocking read of one receiver-pushed notification frame.
    /// Returns (sub_id, human-readable line) for SubId 0x40..=0x4F frames.
    fn read_event(&self) -> Option<(u8, String)> {
        let mut buf = [0u8; 64];
        let n = self.dev.read(&mut buf).ok()?;
        if n < 5 || (buf[0] != 0x10 && buf[0] != 0x11) {
            return None;
        }
        let sub = buf[2];
        if !(0x40..=0x4F).contains(&sub) {
            return None; // reply / error / other traffic
        }
        let line = match sub {
            0x40 => format!("slot {} disconnect/unpaired notification", buf[1]),
            0x41 => {
                let flags = buf[4];
                let wpid = ((buf[6] as u16) << 8) | buf[5] as u16;
                let link = if flags & 0x40 != 0 { "DOWN" } else { "UP" };
                let proto = match buf[3] {
                    0x02 => "27MHz",
                    0x10 => "Bolt",
                    other => return Some((sub, format!("slot {} link {link}, protocol {other:#04x}", buf[1]))),
                };
                format!("slot {0} link {link} ({proto}, encrypted, wpid {wpid:04x})", buf[1])
            }
            0x4A => format!("slot {} pairing-lock notification", buf[1]),
            0x4B => format!("slot {} power notification", buf[1]),
            0x53 => "discovery status notification".to_string(),
            0x54 => "pairing status notification".to_string(),
            _ => format!("notification sub {sub:#04x}"),
        };
        Some((sub, line))
    }
}

struct PairedDevice {
    slot: u8,
    name: String,
    kind: u8,
    wpid: u16,
    unit_id: [u8; 4],
}

impl PairedDevice {
    fn kind_name(&self) -> &'static str {
        match self.kind {
            0x01 => "keyboard",
            0x02 => "mouse",
            0x03 => "numpad",
            0x04 => "presenter",
            0x07 => "remote",
            0x08 => "trackball",
            0x09 => "touchpad",
            0x0A => "tablet",
            0x0B => "gamepad",
            _ => "unknown",
        }
    }

    fn print_row(&self) {
        println!(
            "{:<5}{:<16}{:<10}{:<7}{}",
            self.slot,
            self.name,
            self.kind_name(),
            format!("{:04x}", self.wpid),
            hex(&self.unit_id)
        );
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn open_bolt() -> Result<Bolt, Error> {
    let api = HidApi::new()?;
    Bolt::open(&api)
}

/// Pause-flag protocol so manual `logi-bolt-guard` commands coexist with a running
/// `guard` daemon: the receiver's HID node can only be opened by one process
/// on macOS, so a manual command drops the pause-flag file; guard sees it and
/// releases the device until the flag disappears. Flags older than
/// PAUSE_FLAG_STALE (writer died) are ignored.
///
/// The flag lives under HOME, NOT /tmp: sandboxed CLI sessions can get a
/// shadowed /tmp that background services (launchd) cannot see, while the
/// home directory is shared between both contexts.
const PAUSE_FLAG_STALE: Duration = Duration::from_secs(60);

fn pause_flag_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("Library/Application Support/logi-bolt-guard/guard.pause"))
        .unwrap_or_else(|| PathBuf::from("/tmp/logi-bolt-guard.pause"))
}

fn busy_str(s: &str) -> bool {
    s.contains("0xE00002C5") || s.contains("exclusive access")
}

fn is_busy(e: &Error) -> bool {
    matches!(e, Error::Hid(_)) && busy_str(&e.to_string())
}

fn pause_flag_fresh() -> bool {
    fs::metadata(pause_flag_path())
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < PAUSE_FLAG_STALE)
}

/// Open the receiver, retrying past a running guard daemon's hold phase
/// (it releases the device for RELEASE_WINDOW every cycle) and dropping the
/// pause flag as a best-effort shortcut. Enumeration is done once; only the
/// cheap open is retried, so the 400ms release window is caught reliably.
/// The flag is removed by `main` when the command finishes.
fn open_bolt_pausing() -> Result<Bolt, Error> {
    let api = HidApi::new()?;
    let info = api
        .device_list()
        .find(|d| d.vendor_id() == VID && d.product_id() == PID && d.usage_page() == 0xFF00)
        .ok_or(Error::NoReceiver)?;
    let path = info.path();
    let mut last = None;
    for _ in 0..200 {
        match api.open_path(&path) {
            Ok(dev) => {
                dev.set_blocking_mode(false)?;
                return Ok(Bolt { dev });
            }
            Err(e) if busy_str(&e.to_string()) => {
                let _ = fs::write(pause_flag_path(), b"logi-bolt-guard manual command");
                last = Some(Error::Hid(e));
                sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(Error::Hid(e)),
        }
    }
    Err(last.unwrap_or(Error::NoReceiver))
}

fn print_table(devices: &[PairedDevice]) {
    if devices.is_empty() {
        println!("pairing table: empty");
        return;
    }
    println!("{:<5}{:<16}{:<10}{:<7}{}", "slot", "name", "kind", "wpid", "unit_id");
    for d in devices {
        d.print_row();
    }
}

fn cmd_list() -> Result<(), Error> {
    let bolt = open_bolt_pausing()?;
    print_table(&bolt.list_paired()?);
    Ok(())
}

fn cmd_ping() -> Result<(), Error> {
    let bolt = open_bolt_pausing()?;
    for slot in 1..=MAX_SLOTS {
        match bolt.ping(slot)? {
            Some(v) => println!("device {slot}: {v}"),
            None => println!("device {slot}: no response"),
        }
    }
    Ok(())
}

fn cmd_unpair(slot: u8) -> Result<(), Error> {
    let bolt = open_bolt_pausing()?;
    let devices = bolt.list_paired()?;
    let Some(target) = devices.iter().find(|d| d.slot == slot) else {
        println!("slot {slot} is not paired; nothing to do");
        return Ok(());
    };
    println!("unpairing slot {slot} ({} / unit {})", target.name, hex(&target.unit_id));
    bolt.unpair(slot)?;
    println!("done; remaining:");
    print_table(&bolt.list_paired()?);
    Ok(())
}

/// Sanity check the receiver state: one entry per physical device, no
/// duplicate pairings, and the (only) paired device reachable.
fn cmd_verify() -> Result<bool, Error> {
    let bolt = open_bolt_pausing()?;

    let unique_id = bolt.read_reg(REG_BOLT_UNIQUE_ID, &[]).ok();
    println!(
        "receiver: 046D:C548 (Logi Bolt), unique-id register: {}",
        unique_id.as_deref().map(hex).unwrap_or_else(|| "unreadable".into())
    );

    let devices = bolt.list_paired()?;
    if devices.is_empty() {
        println!("pairing table: EMPTY — no mouse paired to this receiver");
        return Ok(false);
    }
    println!("pairing table: {} device(s)", devices.len());
    print_table(&devices);

    let mut clean = true;

    // duplicate unit_id = same physical mouse paired more than once
    for (i, a) in devices.iter().enumerate() {
        for b in devices.iter().skip(i + 1) {
            if a.unit_id == b.unit_id {
                println!(
                    "!! slots {} and {} hold the SAME device (unit {}) — duplicate pairing",
                    a.slot, b.slot, hex(&a.unit_id)
                );
                clean = false;
            }
        }
    }

    for d in &devices {
        match bolt.ping(d.slot)? {
            Some(v) => println!("slot {} live link: {} ({})", d.slot, v, d.name),
            None => println!(
                "slot {} ({}) not answering ping — mouse asleep, powered off, or out of range",
                d.slot, d.name
            ),
        }
    }

    if devices.len() > 1 {
        println!("!! more than one device is paired — expected exactly one (your mouse)");
        clean = false;
    }

    if clean {
        println!("verdict: OK — exactly one paired device, no duplicates");
    } else {
        println!("verdict: NEEDS CLEANUP — run `logi-bolt-guard ping`, then `logi-bolt-guard unpair <slot>` on the stale entry");
    }
    Ok(clean)
}

/// Battery of paired devices via HID++ 2.0. Root GetFeature is unreliable
/// through Bolt receivers (sleeping devices answer all-zeros), so the feature
/// table is enumerated through FEATURE_SET, which HID++ 2.0 pins at index 1.
/// Looks for UNIFIED_BATTERY (0x1004, reply [soc%, level, status]) or the
/// classic BATTERY_STATUS (0x1000, reply [level%, next, status-flags]).
fn cmd_battery() -> Result<(), Error> {
    let bolt = open_bolt_pausing()?;
    for slot in 1..=MAX_SLOTS {
        if bolt.read_reg(REG_RECEIVER_INFO, &[0x50 + slot]).is_err() {
            continue; // empty slot
        }
        // wake the link: shallow-sleeping devices answer zeros or nothing
        let mut awake = false;
        for _ in 0..10 {
            if matches!(bolt.ping(slot), Ok(Some(v)) if v.starts_with("4.")) {
                awake = true;
                break;
            }
            sleep(Duration::from_millis(300));
        }
        if !awake {
            println!("slot {slot}: not answering ping (asleep or off) — move the mouse and retry");
            continue;
        }
        let count = loop_retry(5, || bolt.xfer(slot, 0x0108, &[], READ_TIMEOUT));
        let Some(count) = count.filter(|p| !p.is_empty() && p[0] > 0).map(|p| p[0]) else {
            println!("slot {slot}: FeatureSet not answering");
            continue;
        };
        let mut found: Option<(u16, u8)> = None; // (feature id, index)
        for i in 1..=count {
            let Some(p) = loop_retry(3, || bolt.xfer(slot, 0x0118, &[i], READ_TIMEOUT)) else {
                break;
            };
            if p.len() < 2 {
                break;
            }
            let id = ((p[0] as u16) << 8) | p[1] as u16;
            if id == 0x1004 || id == 0x1000 {
                found = Some((id, i));
                break;
            }
        }
        let Some((id, idx)) = found else {
            println!("slot {slot}: no battery feature exposed");
            continue;
        };
        let Some(b) = loop_retry(3, || bolt.xfer(slot, ((idx as u16) << 8) | 0x08, &[], READ_TIMEOUT))
            .filter(|p| p.len() >= 3)
        else {
            println!("slot {slot}: battery read failed");
            continue;
        };
        if id == 0x1004 {
            let status = match b[2] {
                0 => "discharging",
                1 => "charging",
                2 => "charging slow",
                3 => "charging fast",
                4 => "charge complete",
                5 => "recharging below optimal",
                6 => "invalid battery",
                _ => "unknown",
            };
            println!("slot {slot}: battery {}% ({status})", b[0]);
        } else {
            let charging = b[2] & 0x80 != 0;
            println!("slot {slot}: battery {}%{}", b[0] & 0x7F, if charging { " (charging)" } else { "" });
        }
    }
    Ok(())
}

/// Retry an HID++ request a few times — needed while a device is waking up.
fn loop_retry<F>(tries: u8, mut f: F) -> Option<Vec<u8>>
where
    F: FnMut() -> Result<Vec<u8>, Error>,
{
    for k in 0..tries {
        match f() {
            Ok(v) if !v.is_empty() && v.iter().any(|&b| b != 0) => return Some(v),
            Ok(_) => sleep(Duration::from_millis(300)), // zeros = still waking
            Err(_) => sleep(Duration::from_millis(400)),
        }
        if k + 1 < tries {
            continue;
        }
    }
    f().ok()
}

/// Which slots should be ejected so that only allowlisted unit_ids remain,
/// each in a single slot (preferring the slot that holds the live link).
fn plan_ejections(devices: &[PairedDevice], allow: &[[u8; 4]], live_slots: &[u8]) -> Vec<u8> {
    let mut eject: Vec<u8> = devices.iter().filter(|d| !allow.contains(&d.unit_id)).map(|d| d.slot).collect();
    let mut seen: Vec<[u8; 4]> = Vec::new();
    for d in devices {
        if !allow.contains(&d.unit_id) || seen.contains(&d.unit_id) {
            continue;
        }
        seen.push(d.unit_id);
        let group: Vec<&PairedDevice> = devices.iter().filter(|x| x.unit_id == d.unit_id).collect();
        if group.len() > 1 {
            let keep = group
                .iter()
                .find(|x| live_slots.contains(&x.slot))
                .map(|x| x.slot)
                .unwrap_or_else(|| group.iter().map(|x| x.slot).min().unwrap());
            eject.extend(group.iter().filter(|x| x.slot != keep).map(|x| x.slot));
        }
    }
    eject.sort_unstable();
    eject.dedup();
    eject
}

fn has_duplicates(devices: &[PairedDevice]) -> bool {
    let mut seen = Vec::with_capacity(devices.len());
    devices.iter().any(|d| {
        if seen.contains(&d.unit_id) {
            true
        } else {
            seen.push(d.unit_id);
            false
        }
    })
}

/// One guard pass: find anything that must not be on this receiver and
/// unpair it immediately.
fn sweep(bolt: &Bolt, allow: &[[u8; 4]], since: Instant) -> Result<(), Error> {
    let devices = bolt.list_paired()?;
    let dirty = devices.iter().any(|d| !allow.contains(&d.unit_id)) || has_duplicates(&devices);
    if !dirty {
        if devices.is_empty() {
            println!("[{:>7.1}s] warning: pairing table is EMPTY — your mouse is not paired", since.elapsed().as_secs_f32());
        }
        return Ok(());
    }
    println!("[{:>7.1}s] pairing table changed:", since.elapsed().as_secs_f32());
    print_table(&devices);
    let mut live = Vec::new();
    for d in &devices {
        if bolt.ping(d.slot)?.is_some() {
            live.push(d.slot);
        }
    }
    for slot in plan_ejections(&devices, allow, &live) {
        let d = devices.iter().find(|d| d.slot == slot).unwrap();
        println!(
            "[{:>7.1}s] EJECT slot {} ({} / wpid {:04x} / unit {}) — not in allowlist{}",
            since.elapsed().as_secs_f32(),
            slot,
            d.name,
            d.wpid,
            hex(&d.unit_id),
            if allow.contains(&d.unit_id) { ", duplicate slot" } else { "" }
        );
        bolt.unpair(slot)?;
        println!("[{:>7.1}s] slot {slot} unpaired — link dropped", since.elapsed().as_secs_f32());
    }
    Ok(())
}

/// Open the receiver and pin its current table as the allowlist.
fn pin_allowlist() -> Result<Vec<[u8; 4]>, Error> {
    let bolt = open_bolt()?;
    let pinned = bolt.list_paired()?;
    println!(
        "no --allow given: PINNING the current pairing table as the allowlist{}",
        if pinned.is_empty() { " (empty!)" } else { "" }
    );
    print_table(&pinned);
    Ok(pinned.iter().map(|d| d.unit_id).collect())
}

/// Daemon guard loop: hold-and-release duty cycling. The macOS HID node can
/// only be open in one process, so the guard holds the receiver for one
/// poll/event cycle, then drops it for RELEASE_WINDOW so manual `logi-bolt-guard`
/// commands (which retry the open) can always get through within a few
/// seconds — no cross-process signalling needed. The pause flag is honored
/// between cycles as a best-effort shortcut in contexts where it is visible.
const RELEASE_WINDOW: Duration = Duration::from_millis(700);

/// One hold phase of the guard: re-arm notifications, sweep the table, then
/// listen for link/pairing events until the interval elapses.
fn guard_cycle(bolt: &Bolt, allow: &[[u8; 4]], interval: Duration, start: Instant, attached: bool) -> Result<(), Error> {
    if let Err(e) = bolt.set_notifications(true) {
        if attached {
            println!("[{:>7.1}s] note: notifications unavailable ({e}); polling only", start.elapsed().as_secs_f32());
        }
    }
    sweep(bolt, allow, start)?;
    let deadline = Instant::now() + interval;
    while Instant::now() < deadline {
        if let Some((_sub, line)) = bolt.read_event() {
            println!("[{:>7.1}s] {line}", start.elapsed().as_secs_f32());
        } else {
            sleep(Duration::from_millis(20));
        }
    }
    Ok(())
}

fn cmd_guard(mut allow: Vec<[u8; 4]>, interval: Duration, once: bool) -> Result<(), Error> {
    let start = Instant::now();

    if allow.is_empty() {
        loop {
            match pin_allowlist() {
                Ok(ids) => {
                    allow = ids;
                    break;
                }
                // daemon mode waits for the receiver to show up before pinning
                Err(Error::NoReceiver) if !once => {
                    println!("[{:>7.1}s] waiting for receiver to pin allowlist...", start.elapsed().as_secs_f32());
                    sleep(Duration::from_secs(3));
                }
                Err(e) => return Err(e),
            }
        }
    }
    println!("allowlist: {}", allow.iter().map(|id| hex(id)).collect::<Vec<_>>().join(", "));

    if once {
        let bolt = open_bolt_pausing()?;
        let _ = bolt.set_notifications(true);
        sweep(&bolt, &allow, start)?;
        println!("sweep complete");
        return Ok(());
    }
    println!("guarding (hold {interval:?} + {RELEASE_WINDOW:?} release window) — Ctrl-C to stop");

    let mut attached = false;
    let mut failures = 0u32;

    loop {
        while pause_flag_fresh() {
            sleep(Duration::from_millis(150));
        }
        let bolt = match open_bolt() {
            Ok(bolt) => {
                failures = 0;
                if !attached {
                    println!("[{:>7.1}s] attached to receiver", start.elapsed().as_secs_f32());
                    attached = true;
                }
                bolt
            }
            // a manual command is using the receiver right now — wait quietly
            Err(e) if is_busy(&e) => {
                sleep(Duration::from_millis(300));
                continue;
            }
            Err(e) => {
                failures += 1;
                if failures == 1 || failures % 20 == 0 {
                    println!(
                        "[{:>7.1}s] guard: {e}; re-checking for receiver every 3s (attempt {failures})",
                        start.elapsed().as_secs_f32()
                    );
                }
                attached = false;
                sleep(Duration::from_secs(3));
                continue;
            }
        };
        if let Err(e) = guard_cycle(&bolt, &allow, interval, start, attached) {
            failures += 1;
            if failures == 1 || failures % 20 == 0 {
                println!(
                    "[{:>7.1}s] guard: {e}; re-attaching in 3s (attempt {failures})",
                    start.elapsed().as_secs_f32()
                );
            }
            attached = false;
            sleep(Duration::from_secs(3));
            continue;
        }
        drop(bolt); // release the receiver so manual commands can use it
        sleep(RELEASE_WINDOW);
    }
}

fn parse_unit_ids(s: &str) -> Option<Vec<[u8; 4]>> {
    let mut out = Vec::new();
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.len() != 8 || !tok.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let mut id = [0u8; 4];
        for (i, b) in id.iter_mut().enumerate() {
            *b = u8::from_str_radix(&tok[i * 2..i * 2 + 2], 16).ok()?;
        }
        out.push(id);
    }
    Some(out)
}

fn usage() {
    println!(
        "usage: logi-bolt-guard [list | ping | verify | unpair <slot> | guard [opts]]\n\
         \x20 list                     show the receiver's pairing table (default)\n\
         \x20 ping                     ping device slots 1..=6 to find the live link\n\
         \x20 battery                  read battery level of paired devices\n\
         \x20 verify                   check the receiver is in a clean state\n\
         \x20 unpair <n>               remove the pairing in slot n\n\
         \x20 guard [--allow ids] [--interval secs] [--once]\n\
         \x20                          eject any paired device whose unit-id is not\n\
         \x20                          allowlisted, and duplicate slots of one device;\n\
         \x20                          unit-ids are 8 hex chars, comma separated"
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("list");
    let result = match cmd {
        "list" => cmd_list().map(|_| true),
        "ping" => cmd_ping().map(|_| true),
        "battery" => cmd_battery().map(|_| true),
        "unpair" => match args.get(2).and_then(|s| s.parse::<u8>().ok()) {
            Some(slot) if (1..=MAX_SLOTS).contains(&slot) => cmd_unpair(slot).map(|_| true),
            _ => {
                eprintln!("unpair needs a slot number 1..={MAX_SLOTS}");
                usage();
                return ExitCode::from(2);
            }
        },
        "guard" => {
            let mut allow = Vec::new();
            let mut interval = Duration::from_secs(2);
            let mut once = false;
            let mut it = args[2..].iter();
            let parse_err: Option<String> = loop {
                let Some(a) = it.next() else { break None };
                match a.as_str() {
                    "--allow" => match it.next().and_then(|v| parse_unit_ids(v)) {
                        Some(ids) => allow = ids,
                        None => break Some("--allow needs 8-hex-char unit-ids, comma separated".into()),
                    },
                    "--interval" => match it.next().and_then(|v| v.parse::<f64>().ok()) {
                        Some(secs) if secs >= 0.2 => interval = Duration::from_secs_f64(secs),
                        _ => break Some("--interval needs a number of seconds >= 0.2".into()),
                    },
                    "--once" => once = true,
                    other => break Some(format!("unknown guard option: {other}")),
                }
            };
            if let Some(msg) = parse_err {
                eprintln!("{msg}");
                usage();
                return ExitCode::from(2);
            }
            cmd_guard(allow, interval, once).map(|_| true)
        }
        "help" | "--help" | "-h" => {
            usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("unknown command: {other}");
            usage();
            return ExitCode::from(2);
        }
    };
    let code = match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            if is_busy(&e) {
                eprintln!("error: {e}\n(a running `guard` holds the receiver; it should release it within a second — retry)");
            } else {
                eprintln!("error: {e}");
            }
            ExitCode::from(1)
        }
    };
    let _ = fs::remove_file(pause_flag_path()); // release the guard daemon if we asked it to wait
    code
}

#[cfg(test)]
mod tests {
    use super::{hex, make_frame, parse_unit_ids, plan_ejections, PairedDevice};

    fn dev(slot: u8, unit: &str, name: &str) -> PairedDevice {
        PairedDevice {
            slot,
            name: name.into(),
            kind: 0x02,
            wpid: 0xB031,
            unit_id: parse_unit_ids(unit).unwrap()[0],
        }
    }

    #[test]
    fn register_read_uses_short_frame() {
        // 0x83B5 (receiver info, paged) sub 0x51 must be a 7-byte report 0x10
        let f = make_frame(0xFF, 0x83B5, &[0x51]);
        assert_eq!(f, vec![0x10, 0xFF, 0x83, 0xB5, 0x51, 0x00, 0x00]);
    }

    #[test]
    fn register_write_uses_long_frame() {
        // unpair slot 1: 0x82C1 with [0x03, 0x01] must be a 20-byte report 0x11
        let f = make_frame(0xFF, 0x82C1, &[0x03, 0x01]);
        assert_eq!(f.len(), 20);
        assert_eq!(&f[..6], &[0x11, 0xFF, 0x82, 0xC1, 0x03, 0x01]);
        assert!(f[6..].iter().all(|&b| b == 0));
    }

    #[test]
    fn plain_register_write_uses_short_frame() {
        // notifications enable: register 0 write, flags 0x000900
        let f = make_frame(0xFF, 0x8000, &[0x00, 0x09, 0x00]);
        assert_eq!(f, vec![0x10, 0xFF, 0x80, 0x00, 0x00, 0x09, 0x00]);
    }

    #[test]
    fn oversize_read_params_go_long() {
        let f = make_frame(0xFF, 0x81B5, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(f.len(), 20);
        assert_eq!(f[0], 0x11);
    }

    #[test]
    fn guard_ejects_foreign_device() {
        let devices = vec![dev(1, "deadbeef", "MX Master"), dev(2, "c57cbb29", "LIFT")];
        let allow = parse_unit_ids("c57cbb29").unwrap();
        assert_eq!(plan_ejections(&devices, &allow, &[2]), vec![1]);
    }

    #[test]
    fn guard_keeps_live_slot_on_duplicate() {
        // yesterday's failure mode: same mouse in slots 1 (stale) and 2 (live)
        let devices = vec![dev(1, "c57cbb29", "LIFT"), dev(2, "c57cbb29", "LIFT")];
        let allow = parse_unit_ids("c57cbb29").unwrap();
        assert_eq!(plan_ejections(&devices, &allow, &[2]), vec![1]);
    }

    #[test]
    fn guard_keeps_lowest_slot_when_none_live() {
        let devices = vec![dev(3, "c57cbb29", "LIFT"), dev(5, "c57cbb29", "LIFT")];
        let allow = parse_unit_ids("c57cbb29").unwrap();
        assert_eq!(plan_ejections(&devices, &allow, &[]), vec![5]);
    }

    #[test]
    fn guard_clean_table_needs_nothing() {
        let devices = vec![dev(2, "c57cbb29", "LIFT")];
        let allow = parse_unit_ids("c57cbb29").unwrap();
        assert!(plan_ejections(&devices, &allow, &[2]).is_empty());
    }

    #[test]
    fn unit_id_hex_roundtrip() {
        assert_eq!(hex(&parse_unit_ids("c57cbb29").unwrap()[0]), "c57cbb29");
        assert!(parse_unit_ids("xyz").is_none());
        assert!(parse_unit_ids("c57cbb2").is_none());
    }

    #[test]
    fn busy_error_detection() {
        use super::busy_str;
        assert!(busy_str("hid_open_path: (0xE00002C5) exclusive access and device already open"));
        assert!(busy_str("some hidapi error: exclusive access"));
        assert!(!busy_str("hid_open_path: device not found"));
    }
}
