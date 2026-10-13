# logi-bolt-guard · Logi Bolt 守护

> **Inspect and guard the pairing table of a Logitech Bolt USB receiver (`046D:C548`) — eject anything that isn't yours.**
> Pure Rust, raw HID++, zero Logitech software.

你有没有遇到过:同事的罗技鼠标"串"到了你的接收器上,他一动鼠标你的光标就跟着抽搐?或者你自己的鼠标被重复配对、链路变得不稳?这个工具就是为这种事故而生的——它直接和 Logi Bolt 接收器对话,把配对表摊开给你看,并且(作为一个常驻守护进程)确保**除了你允许的设备,任何东西在配对表里活不过三秒**。

## 功能

| 命令 | 作用 |
|---|---|
| `logi-bolt-guard` | 列出接收器配对表(槽位、设备名、类型、wpid、unit-id) |
| `logi-bolt-guard ping` | 逐槽位 HID++ ping,找出当前活跃链路(如 `4.5`) |
| `logi-bolt-guard battery` | 读取已配对设备电池电量(如 `slot 2: battery 15% (discharging)`) |
| `logi-bolt-guard unpair <n>` | 解绑指定槽位(解绑即断链) |
| `logi-bolt-guard verify` | 健康检查:恰好一台设备、无重复、链路在线;退出码 0/1,可脚本化 |
| `logi-bolt-guard guard --allow <id>` | 常驻守护:轮询 + 事件监听,自动踢出白名单以外的设备和重复槽位 |

设备身份用出厂唯一的 **unit-id**(8 位十六进制,如 `c57cbb29`)判定,不认槽位号、不认设备名——重连、换槽都不影响识别。

## 构建

需要 Rust 工具链(仅依赖 [`hidapi`](https://crates.io/crates/hidapi) 一个 crate):

```sh
cargo build --release
# 产物: target/release/logi-bolt-guard
```

macOS / Linux 可用(Windows 理论可行,未实测);目标设备为 Logi Bolt USB 接收器 `046D:C548`。

## 快速上手:清理一次串配对

```sh
logi-bolt-guard ping        # 找到活链路,比如槽 2 应答 4.5
logi-bolt-guard unpair 1    # 踢掉重复/外来槽位
logi-bolt-guard verify      # 复查:一台设备、无重复、在线
```

## 常驻守护(guard)

```sh
logi-bolt-guard guard --allow c57cbb29          # 前台运行
logi-bolt-guard guard --allow c57cbb29 --once   # 单次扫描(cron 友好)
```

- `--allow` 逗号分隔多个 unit-id;不给则把启动时的配对表钉为白名单(会打印出来);
- 每 2 秒(`--interval` 可调)扫描配对表,并监听接收器的链路/配对事件通知(SubId `0x41/0x40/0x54`)即时响应;
- 白名单外的设备一出现就解绑;同一设备的重复槽位自动收敛(保留活链路所在槽);
- 配对表被清空(自己的鼠标被解绑)也会告警;
- 接收器不在(坞没插)时静默等待,出现后自动挂上。

### 作为 macOS launchd 服务安装

保存为 `~/Library/LaunchAgents/com.<你>.logi-bolt-guard.plist` 后 `launchctl bootstrap gui/$(id -u) <plist>`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.example.logi-bolt-guard</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/logi-bolt-guard</string>
        <string>guard</string>
        <string>--allow</string>
        <string>c57cbb29</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/Users/YOU/Library/Logs/logi-bolt-guard.log</string>
    <key>StandardErrorPath</key><string>/Users/YOU/Library/Logs/logi-bolt-guard.log</string>
</dict>
</plist>
```

日志按事件写入(踢出、重连、接收器插拔),平时静默——**没消息就是好消息**。

### 与手动命令共存

macOS 上接收器的 HID 节点同一时刻只能被一个进程打开。守护进程采用**占-放循环**:占用约 2 秒(扫描 + 监听)后主动释放 700ms。手动执行 `list/verify/unpair` 时会自动重试并挤进放行窗口(最坏几秒)。手动命令还会落一个暂停旗标(`~/Library/Application Support/logi-bolt-guard/guard.pause`,60 秒自动过期)让守护立刻让位——在正常(非沙箱)终端里基本秒回。

## 威胁模型(诚实说明)

- **射频注入层不需要这个工具**:Bolt 链路按配对密钥加密,未配对设备的信号会被接收器硬件直接丢弃。想让"别人的鼠标控制你的光标",唯一途径是被**配进**你的接收器——这正是本工具防御的部分。
- **guard 是快速反应,不是预防锁**:它在轮询间隔(默认 2 秒)内发现并清除污染。同机的其他进程理论上也能对 USB HID 写指令,macOS 没有拦截手段。
- 睡眠期间无需防护:USB 总线挂起,配对不可能发生;唤醒后守护自动恢复。

## 协议笔记

实测验证(交叉参考 Solaar 与 OpenLogi 源码,并在真实接收器上确认):

- 寄存器**读**(SubId `0x81/0x83`)必须用**短报文**(report `0x10`,7 字节);长报文会被拒(`INVALID_SUB_ID 0x01`)。寄存器**写**(SubId `0x82`)用**长报文**(report `0x11`,20 字节)。
- 16 位寄存器把 `0x200` 分页位折进请求 id:`0x2B5 → 0x83B5`,`0x2C1 → 0x82C1`,`0x2FB → 0x83FB`。
- 配对表:读 `0x83B5` 子寄存器 `0x50+n`;设备名 `0x60+n,0x01`。应答 payload 首字节是子寄存器回显;`payload[1] & 0x0F` 是类型(2=鼠标),wpid = `payload[3]<<8 | payload[2]`,`payload[4..8]` 是设备唯一 id。空槽位返回错误 `0x08`。
- 解绑:长写 `0x82C1`,payload `[0x03, slot]`。
- 活链路探测:HID++ 2.0 根 ping `[0x10, dev, 0x00, 0x10, 0x00, 0x00, rand]`,应答形如 `4.5`。
- 通知使能:寄存器 `0x00` 写 `WIRELESS(0x000100) | SOFTWARE_PRESENT(0x000800)`,短帧。SubId `0x41` 携带链路起落:address `0x10` = Bolt 协议,flags bit6(`0x40`)置位 = 断链,bit5 = 加密,后跟 wpid(小端)。
- 设备侧 HID++ 2.0 坑:Bolt 接收器下 ROOT GetFeature 不可靠(设备浅睡时应答退化为全零)→ 功能表改由 **FeatureSet(HID++ 2.0 固定在索引 1)** 枚举,先 ping 唤醒再查询;电池读 UNIFIED_BATTERY (0x1004) fn0,应答 `[soc%, level, status]`。
- macOS 坑:pyhidapi/rust-hidapi 的带超时读可能永久阻塞 → 全程非阻塞 + 自管超时;两个 `0xFF00` vendor collection 共享同一 IOKit 路径。

## 致谢

- [Solaar](https://github.com/pwr-Solaar/Solaar)(GPLv2)—— 配对寄存器与通知处理的协议参考;
- [OpenLogi](https://github.com/AprilNEA/OpenLogi)(MIT/Apache-2.0)—— Bolt 协议实现的交叉验证,其"GUI 无解绑入口"正是本工具的起点之一。

本项目为独立实现,与 Logitech 无关;`Logi`、`Bolt` 及设备名称归 Logitech 所有。

## License

MIT OR Apache-2.0,任选其一。
