<div align="center">

<img src="docs/assets/logo.png" width="96" alt="">

# Aurora VPN

**VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC를 지원하는 오픈소스 VPN 클라이언트.**<br>
TUN 모드, 앱별 분할 터널링, 규칙 기반 라우팅 — Windows, Android, Linux, macOS에서.

[![Release](https://img.shields.io/github/v/release/JustRin/aurora-vpn?style=flat-square&color=7c3aed&label=release)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/JustRin/aurora-vpn/total?style=flat-square&color=7c3aed)](https://github.com/JustRin/aurora-vpn/releases)
[![License](https://img.shields.io/badge/license-MIT-7c3aed?style=flat-square)](LICENSE)
[![Core](https://img.shields.io/badge/core-sing--box%20%2B%20Xray-22d3ee?style=flat-square)](docs/architecture.md)
[![Site](https://img.shields.io/badge/site-aurora--vpn-1f2937?style=flat-square)](https://justrin.github.io/aurora-vpn/)

[English](README.md) · [Русский](README.ru.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · **한국어** · [العربية](README.ar.md) · [Português](README.pt.md)

<img src="docs/screenshots/dashboard.png" width="840" alt="Aurora VPN — 개요">

</div>

## 다운로드

[![Windows](https://img.shields.io/badge/Windows-x64_installer-0078d4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Android](https://img.shields.io/badge/Android-APK-3ddc84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Linux](https://img.shields.io/badge/Linux-AppImage_·_deb_·_rpm-e95420?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![macOS](https://img.shields.io/badge/macOS-Apple_Silicon_·_Intel-000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)

모든 빌드와 체크섬은 [릴리스 페이지](https://github.com/JustRin/aurora-vpn/releases/latest)에 있습니다. Windows에서는 앱이 그곳에서 스스로 업데이트합니다.

<details>
<summary><b>Windows에 "Windows의 PC 보호" 경고가 뜹니다</b></summary>

<br>

빌드에 아직 코드 서명이 되어 있지 않아 SmartScreen이 알 수 없는 게시자라고 경고합니다. 악성코드가 발견된 것이 아니라 서명이 없는 것입니다. **[추가 정보] → [실행]**을 누르세요.

이 프로젝트는 [SignPath Foundation](https://signpath.org)(오픈소스 무료 코드 서명)에 신청했습니다. 승인되는 대로 릴리스에 서명하도록 CI는 이미 구성되어 있습니다.

</details>

## 기능

| | |
|---|---|
| **프로토콜** | VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC |
| **보안** | uTLS 지문을 사용하는 REALITY, TLS, VLESS Encryption(ML-KEM-768) |
| **전송** | TCP, WebSocket, gRPC, HTTP/2, HTTPUpgrade, XHTTP |
| **가져오기** | `vless://` 등의 링크, 3x-ui / Marzban 구독, 백그라운드 자동 갱신 |
| **요금제 상태** | 남은 일수와 트래픽을 패널에서 바로 읽어옴 |
| **터널 모드** | 시스템 전체를 넘기는 TUN, 또는 관리자 권한이 필요 없는 시스템 프록시 |
| **분할 터널링** | 앱 단위로 — *선택한 앱만 VPN 경유* 또는 *선택한 앱만 VPN 제외* |
| **라우팅** | RU/CN 지역 규칙 세트, 광고 차단, 직접 만든 도메인·서브넷 목록 |
| **전환** | 서버와 규칙 / 전체 VPN 모드를 코어 재시작 없이 즉시 변경 |
| **밸런서** | 장애 조치, 임계값이 있는 최속 선택, 순환 — 코어의 urltest가 아니라 앱이 판단하므로 지연 시간이 비슷한 서버 사이를 오가지 않음 |
| **자동 시작** | 일반 실행 또는 작업 스케줄러를 통한 관리자 실행 — 로그인할 때마다 UAC가 뜨지 않음 |
| **진단** | 코어 실시간 로그, 지연 시간 측정, 생성된 설정 보기 |
| **디자인** | 6가지 팔레트와 *시스템 설정 따르기*, 여러 인터페이스 언어 |
| **Android** | 홈 화면 위젯(버튼, 속도가 표시되는 상태, 세션 트래픽과 시간까지 담은 전체 카드)과 빠른 설정 타일. 앱을 열지 않고 연결 |

## 스크린샷

| | |
|:--:|:--:|
| <img src="docs/screenshots/servers.png" alt="서버"><br>**서버** | <img src="docs/screenshots/routing.png" alt="라우팅"><br>**라우팅** |
| <img src="docs/screenshots/split.png" alt="분할 터널링"><br>**분할 터널링** | <img src="docs/screenshots/settings.png" alt="설정"><br>**설정** |

## 시작하기

1. 사용하는 시스템에 맞는 빌드를 **설치**하고 실행합니다.
2. **서버를 추가**합니다 — `vless://` / `vmess://` / … 링크나 패널의 구독 URL을 붙여넣으세요. 한 번에 모두 가져오며, 지원하지 않는 링크는 나중에 조용히 실패하는 대신 이유와 함께 거부됩니다.
3. **연결합니다.** TUN 모드는 시스템 전체를 터널로 보내므로 관리자 권한이 필요하고, 앱이 UAC를 통한 원클릭 재시작을 제안합니다. 시스템 프록시 모드는 권한 없이 동작합니다.

## 문서

- **[동작 방식](docs/architecture.md)** (영문) — 두 엔진 구성, 라우팅 규칙 순서, 분할 터널링과 DNS, 자동 시작, Android/libbox.
- **[소스에서 빌드하기](docs/architecture.md#building-from-source)** (영문) — 플랫폼별 요구 사항과 명령어.

<details>
<summary><b>무언가 동작하지 않을 때</b></summary>

<br>

**"연결 중…" 직후에 코어가 죽습니다** — **로그**를 열어 보세요. 설정은 실행 전에 `sing-box check`로 검증되므로 실패에는 항상 구체적인 이유가 함께 나옵니다.

**TUN 모드에서 인터넷이 되지 않습니다** — 다른 클라이언트가 시스템 프록시를 남겨두지 않았는지 확인하고, *엄격한 라우팅*을 꺼 보세요(VirtualBox, WSL, 일부 안티치트와 충돌합니다).

**다른 VPN 클라이언트가 실행 중입니다** — TUN 어댑터 두 개는 공존할 수 없습니다. Hiddify를 비롯한 sing-box 기반 클라이언트는 같은 `172.19.0.1`과 같은 기본 경로를 차지하며, 밀린 쪽은 트래픽 없이 "연결됨" 상태로 남습니다. 다른 클라이언트를 완전히 종료하세요 — 프로세스가 살아 있는 한 어댑터도 살아 있습니다.

**특정 사이트만 터널 안에서 열리지 않습니다** — Fake-IP를 켜거나 해당 도메인을 *항상 직접 연결*에 추가하세요.

**지연 시간이 "n/a"로 표시됩니다** — 코어가 꺼져 있을 때는 서버까지의 TCP 핸드셰이크를 측정하므로 "n/a"는 포트에 도달할 수 없다는 뜻입니다. 연결 중에는 프록시를 통해 측정하여 실제 경로를 반영합니다.

**구독 상태가 보이지 않습니다** — 패널이 `subscription-userinfo` 헤더를 보내지 않았습니다. 3x-ui에서는 이 헤더가 구독에만 존재하며, 단일 링크로 추가한 서버에는 없습니다.

</details>

## 기반 기술

[sing-box](https://github.com/SagerNet/sing-box) · [Xray-core](https://github.com/XTLS/Xray-core) · [Wintun](https://www.wintun.net/) · [Slint](https://slint.dev) · [Tauri](https://tauri.app)

## 라이선스

[MIT](LICENSE) © JustRin
