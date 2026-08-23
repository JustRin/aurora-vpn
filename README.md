<div align="center">

<img src="docs/assets/logo.png" width="96" alt="">

# Aurora VPN

**Open-source VPN client for VLESS, VMess, Trojan, Shadowsocks, Hysteria2 and TUIC.**<br>
TUN mode, per-app split tunneling and rule-based routing — on Windows, Android, Linux and macOS.

[![Release](https://img.shields.io/github/v/release/JustRin/aurora-vpn?style=flat-square&color=7c3aed&label=release)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/JustRin/aurora-vpn/total?style=flat-square&color=7c3aed)](https://github.com/JustRin/aurora-vpn/releases)
[![License](https://img.shields.io/badge/license-MIT-7c3aed?style=flat-square)](LICENSE)
[![Core](https://img.shields.io/badge/core-sing--box%20%2B%20Xray-22d3ee?style=flat-square)](docs/architecture.md)
[![Site](https://img.shields.io/badge/site-aurora--vpn-1f2937?style=flat-square)](https://justrin.github.io/aurora-vpn/)

**English** · [Русский](README.ru.md)

<img src="docs/screenshots/dashboard.png" width="840" alt="Aurora VPN — overview">

</div>

## Download

[![Windows](https://img.shields.io/badge/Windows-x64_installer-0078d4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Android](https://img.shields.io/badge/Android-APK-3ddc84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Linux](https://img.shields.io/badge/Linux-AppImage_·_deb_·_rpm-e95420?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![macOS](https://img.shields.io/badge/macOS-Apple_Silicon_·_Intel-000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)

Every build and its checksum lives on the [releases page](https://github.com/JustRin/aurora-vpn/releases/latest). On Windows the app updates itself from there.

<details>
<summary><b>Windows says “Windows protected your PC”</b></summary>

<br>

Builds are not code-signed yet, so SmartScreen warns about an unknown publisher — that is a missing signature, not a malware detection. Click **More info → Run anyway**.

The project has applied to the [SignPath Foundation](https://signpath.org) (free code signing for open source); CI is already wired to sign releases once the application is approved.

</details>

## Features

| | |
|---|---|
| **Protocols** | VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC |
| **Security** | REALITY with uTLS fingerprints, TLS, VLESS Encryption (ML-KEM-768) |
| **Transports** | TCP, WebSocket, gRPC, HTTP/2, HTTPUpgrade, XHTTP |
| **Import** | `vless://` and friends, 3x-ui / Marzban subscriptions, background auto-refresh |
| **Plan status** | days and traffic left, read straight from the panel |
| **Tunnel modes** | TUN for the whole system, or a system proxy that needs no admin rights |
| **Split tunneling** | per app — *only these through the VPN* or *everything but these* |
| **Routing** | RU/CN geo rule sets, ad blocking, your own domain and subnet lists |
| **Switching** | server and rules/everything-via-VPN mode change live, without restarting the core |
| **Autostart** | plain, or elevated through Task Scheduler — no UAC prompt at every login |
| **Diagnostics** | live core log, latency test, generated-config viewer |
| **Looks** | 6 palettes plus *follow system*, English and Russian |

## Screenshots

| | |
|:--:|:--:|
| <img src="docs/screenshots/servers.png" alt="Servers"><br>**Servers** | <img src="docs/screenshots/routing.png" alt="Routing"><br>**Routing** |
| <img src="docs/screenshots/split.png" alt="Split tunneling"><br>**Split tunneling** | <img src="docs/screenshots/settings.png" alt="Settings"><br>**Settings** |

## Getting started

1. **Install** the build for your system and launch it.
2. **Add servers** — paste a `vless://` / `vmess://` / … link, or a subscription URL from your panel. Everything imports at once; unsupported links are rejected with a reason instead of failing silently later.
3. **Connect.** TUN mode routes the whole system and needs administrator rights — the app offers a one-click restart through UAC. System proxy mode works without them.

## Documentation

- **[How it works](docs/architecture.md)** — the two-engine setup, routing rule order, split tunneling and DNS, autostart, Android/libbox.
- **[Building from source](docs/architecture.md#building-from-source)** — requirements and commands for every platform.

<details>
<summary><b>Something isn’t working</b></summary>

<br>

**The core dies right after “Connecting…”** — open the **Log**. The config is validated with `sing-box check` before launch, so the failure comes with a concrete reason.

**No internet in TUN mode** — make sure another client hasn’t left a system proxy behind, and try turning off *Strict routing* (it conflicts with VirtualBox, WSL and some anti-cheats).

**Another VPN client is running** — two TUN adapters don’t coexist. Hiddify and anything else built on sing-box claim the same `172.19.0.1` and the same default route; the loser stays “connected” with no traffic. Quit the other client completely — its adapter lives as long as its process does.

**A site only fails inside the tunnel** — enable Fake-IP, or add the domain to *always direct*.

**Latency shows “n/a”** — with the core off it measures a TCP handshake to the server, so “n/a” means the port is unreachable. While connected, the probe goes through the proxy and reflects the real route.

**No subscription status** — the panel didn’t send the `subscription-userinfo` header. In 3x-ui it exists for subscriptions only, never for servers added as a single link.

</details>

## Built on

[sing-box](https://github.com/SagerNet/sing-box) · [Xray-core](https://github.com/XTLS/Xray-core) · [Wintun](https://www.wintun.net/) · [Slint](https://slint.dev) · [Tauri](https://tauri.app)

## License

[MIT](LICENSE) © JustRin
