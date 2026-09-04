<div align="center">

<img src="docs/assets/logo.png" width="96" alt="">

# Aurora VPN

**开源 VPN 客户端，支持 VLESS、VMess、Trojan、Shadowsocks、Hysteria2 和 TUIC。**<br>
TUN 模式、按应用分流与基于规则的路由 —— 覆盖 Windows、Android、Linux 和 macOS。

[![Release](https://img.shields.io/github/v/release/JustRin/aurora-vpn?style=flat-square&color=7c3aed&label=release)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/JustRin/aurora-vpn/total?style=flat-square&color=7c3aed)](https://github.com/JustRin/aurora-vpn/releases)
[![License](https://img.shields.io/badge/license-MIT-7c3aed?style=flat-square)](LICENSE)
[![Core](https://img.shields.io/badge/core-sing--box%20%2B%20Xray-22d3ee?style=flat-square)](docs/architecture.md)
[![Site](https://img.shields.io/badge/site-aurora--vpn-1f2937?style=flat-square)](https://justrin.github.io/aurora-vpn/)

[English](README.md) · [Русский](README.ru.md) · **简体中文** · [日本語](README.ja.md) · [한국어](README.ko.md) · [العربية](README.ar.md) · [Português](README.pt.md)

<img src="docs/screenshots/dashboard.png" width="840" alt="Aurora VPN — 总览">

</div>

## 下载

[![Windows](https://img.shields.io/badge/Windows-x64_installer-0078d4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Android](https://img.shields.io/badge/Android-APK-3ddc84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Linux](https://img.shields.io/badge/Linux-AppImage_·_deb_·_rpm-e95420?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![macOS](https://img.shields.io/badge/macOS-Apple_Silicon_·_Intel-000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)

所有构建及其校验和都在[发布页](https://github.com/JustRin/aurora-vpn/releases/latest)。在 Windows 上，应用会从那里自动更新。

<details>
<summary><b>Windows 提示“Windows 已保护你的电脑”</b></summary>

<br>

构建尚未进行代码签名，因此 SmartScreen 会警告发布者未知 —— 这是缺少签名，而不是检测到恶意软件。点击**“更多信息” → “仍要运行”**。

本项目已向 [SignPath Foundation](https://signpath.org)（为开源项目提供免费代码签名）提交申请；CI 已经配置好，申请获批后即可自动签名发布版本。

</details>

<details>
<summary><b>macOS 提示“Apple 无法验证…”或“已损坏”</b></summary>

<br>

构建未使用 Apple Developer ID 签名。请下载 `.pkg`：首次打开被 macOS 拒绝时，点击**“完成”**，然后打开**“系统设置” → “隐私与安全性”**，向下滚动到“安全性”，点击**“仍要打开”**（在 macOS 13/14 上，右键点击 `.pkg` → “打开”效果相同）。安装后的应用启动时不会再有任何警告。

“已损坏，无法打开”是旧版本 `.dmg` 里的应用：浏览器给它打上了隔离标记，Gatekeeper 不允许绕过。请改用 `.pkg`，或手动去掉标记：`xattr -cr "/Applications/Aurora VPN.app"`。

</details>

## 功能

| | |
|---|---|
| **协议** | VLESS、VMess、Trojan、Shadowsocks、Hysteria2、TUIC |
| **安全** | 带 uTLS 指纹的 REALITY、TLS、VLESS Encryption（ML-KEM-768） |
| **传输** | TCP、WebSocket、gRPC、HTTP/2、HTTPUpgrade、XHTTP |
| **导入** | `vless://` 等链接、3x-ui / Marzban 订阅、后台自动刷新 |
| **套餐状态** | 剩余天数与流量，直接从面板读取 |
| **隧道模式** | 接管整个系统的 TUN，或无需管理员权限的系统代理 |
| **分应用代理** | 按应用设置 —— *仅这些走 VPN* 或 *除这些之外全部走 VPN* |
| **路由** | RU/CN 地理规则集、广告拦截、自定义域名与网段列表 |
| **切换** | 服务器与「规则 / 全局」模式实时切换，无需重启内核 |
| **负载均衡** | 故障转移、带阈值的最快选择或轮换 —— 由应用而非内核的 urltest 决定，延迟相近的服务器不会来回跳 |
| **开机自启** | 普通方式，或通过任务计划程序以管理员身份启动 —— 每次登录不再弹 UAC |
| **诊断** | 实时内核日志、延迟测试、生成的配置查看器 |
| **外观** | 6 套配色加*跟随系统*，多语言界面 |
| **Android** | 桌面小组件——开关、带速度的状态、含本次流量与时长的完整卡片——以及快捷设置图块；无需打开应用即可连接 |

## 截图

| | |
|:--:|:--:|
| <img src="docs/screenshots/servers.png" alt="服务器"><br>**服务器** | <img src="docs/screenshots/routing.png" alt="路由"><br>**路由** |
| <img src="docs/screenshots/split.png" alt="分应用代理"><br>**分应用代理** | <img src="docs/screenshots/settings.png" alt="设置"><br>**设置** |

## 快速上手

1. **安装**适合你系统的构建并启动它。
2. **添加服务器** —— 粘贴 `vless://` / `vmess://` / … 链接，或面板给出的订阅地址。所有内容会一次性导入；不支持的链接会给出原因并被拒绝，而不是稍后悄悄失效。
3. **连接。** TUN 模式接管整个系统，需要管理员权限 —— 应用会提供通过 UAC 一键重启。系统代理模式则不需要。

## 文档

- **[工作原理](docs/architecture.md)**（英文）—— 双引擎结构、路由规则顺序、分应用代理与 DNS、开机自启、Android/libbox。
- **[从源码构建](docs/architecture.md#building-from-source)**（英文）—— 各平台的环境要求与命令。

<details>
<summary><b>遇到问题</b></summary>

<br>

**内核在“正在连接…”之后立刻退出** —— 打开**日志**。配置在启动前会经过 `sing-box check` 校验，所以失败一定带着具体原因。

**TUN 模式下没有网络** —— 确认没有别的客户端留下未清理的系统代理，并尝试关闭*严格路由*（它与 VirtualBox、WSL 和部分反作弊冲突）。

**另一个 VPN 客户端正在运行** —— 两个 TUN 适配器无法共存。Hiddify 以及其他基于 sing-box 的客户端会占用同一个 `172.19.0.1` 和同一条默认路由；失败的一方会停留在“已连接”状态却没有流量。请彻底退出另一个客户端 —— 只要它的进程还在，适配器就还在。

**某个网站只在隧道里打不开** —— 启用 Fake-IP，或把该域名加入*始终直连*。

**延迟显示为“n/a”** —— 内核未运行时测的是到服务器的 TCP 握手，所以“n/a”意味着端口不可达。连接状态下探测会走代理，反映真实链路。

**看不到订阅状态** —— 面板没有返回 `subscription-userinfo` 响应头。在 3x-ui 中该响应头只存在于订阅，单条链接添加的服务器永远没有。

</details>

## 构建于

[sing-box](https://github.com/SagerNet/sing-box) · [Xray-core](https://github.com/XTLS/Xray-core) · [Wintun](https://www.wintun.net/) · [Slint](https://slint.dev) · [Tauri](https://tauri.app)

## 许可证

[MIT](LICENSE) © JustRin
