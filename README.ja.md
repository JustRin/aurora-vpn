<div align="center">

<img src="docs/assets/logo.png" width="96" alt="">

# Aurora VPN

**VLESS、VMess、Trojan、Shadowsocks、Hysteria2、TUIC に対応したオープンソースの VPN クライアント。**<br>
TUN モード、アプリ単位のスプリットトンネリング、ルールベースのルーティングを Windows・Android・Linux・macOS で。

[![Release](https://img.shields.io/github/v/release/JustRin/aurora-vpn?style=flat-square&color=7c3aed&label=release)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/JustRin/aurora-vpn/total?style=flat-square&color=7c3aed)](https://github.com/JustRin/aurora-vpn/releases)
[![License](https://img.shields.io/badge/license-MIT-7c3aed?style=flat-square)](LICENSE)
[![Core](https://img.shields.io/badge/core-sing--box%20%2B%20Xray-22d3ee?style=flat-square)](docs/architecture.md)
[![Site](https://img.shields.io/badge/site-aurora--vpn-1f2937?style=flat-square)](https://justrin.github.io/aurora-vpn/)

[English](README.md) · [Русский](README.ru.md) · [简体中文](README.zh-CN.md) · **日本語** · [한국어](README.ko.md) · [العربية](README.ar.md) · [Português](README.pt.md)

<img src="docs/screenshots/dashboard.png" width="840" alt="Aurora VPN — 概要">

</div>

## ダウンロード

[![Windows](https://img.shields.io/badge/Windows-x64_installer-0078d4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Android](https://img.shields.io/badge/Android-APK-3ddc84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![Linux](https://img.shields.io/badge/Linux-AppImage_·_deb_·_rpm-e95420?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)
[![macOS](https://img.shields.io/badge/macOS-Apple_Silicon_·_Intel-000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/JustRin/aurora-vpn/releases/latest)

すべてのビルドとチェックサムは[リリースページ](https://github.com/JustRin/aurora-vpn/releases/latest)にあります。Windows 版はそこから自動で更新されます。

<details>
<summary><b>Windows に「Windows によって PC が保護されました」と表示される</b></summary>

<br>

ビルドはまだコード署名されていないため、SmartScreen が発行元不明として警告します。マルウェアが検出されたのではなく、署名がないだけです。**［詳細情報］→［実行］**を選んでください。

本プロジェクトは [SignPath Foundation](https://signpath.org)（オープンソース向けの無償コード署名）に申請済みです。承認され次第リリースに署名できるよう、CI はすでに設定してあります。

</details>

## 機能

| | |
|---|---|
| **プロトコル** | VLESS、VMess、Trojan、Shadowsocks、Hysteria2、TUIC |
| **セキュリティ** | uTLS フィンガープリント付き REALITY、TLS、VLESS Encryption（ML-KEM-768） |
| **トランスポート** | TCP、WebSocket、gRPC、HTTP/2、HTTPUpgrade、XHTTP |
| **インポート** | `vless://` などのリンク、3x-ui / Marzban のサブスクリプション、バックグラウンド自動更新 |
| **プラン状況** | 残り日数と残りトラフィックをパネルから直接取得 |
| **トンネルモード** | システム全体を通す TUN、または管理者権限のいらないシステムプロキシ |
| **スプリットトンネリング** | アプリ単位で *選んだものだけ VPN 経由* または *選んだものだけ VPN 除外* |
| **ルーティング** | RU/CN の地域ルールセット、広告ブロック、独自のドメイン・サブネットリスト |
| **切り替え** | サーバーとルール／全体 VPN モードをコア再起動なしで即時変更 |
| **バランサー** | フェイルオーバー、しきい値付きの最速選択、ローテーション — コアの urltest ではなくアプリが判断するので、遅延の近いサーバー間で行き来しない |
| **自動起動** | 通常起動、またはタスク スケジューラ経由の管理者起動 — ログインのたびの UAC なし |
| **診断** | コアのライブログ、レイテンシ計測、生成された設定のビューア |
| **外観** | 6 種類のパレットと*システムに合わせる*、複数の表示言語 |
| **Android** | ホーム画面ウィジェット（ボタン、速度付きステータス、通信量とセッション時間を含むフルカード）とクイック設定タイル。アプリを開かずに接続 |

## スクリーンショット

| | |
|:--:|:--:|
| <img src="docs/screenshots/servers.png" alt="サーバー"><br>**サーバー** | <img src="docs/screenshots/routing.png" alt="ルーティング"><br>**ルーティング** |
| <img src="docs/screenshots/split.png" alt="スプリットトンネリング"><br>**スプリットトンネリング** | <img src="docs/screenshots/settings.png" alt="設定"><br>**設定** |

## はじめかた

1. お使いのシステム向けのビルドを**インストール**して起動します。
2. **サーバーを追加**します — `vless://` / `vmess://` / … のリンク、またはパネルのサブスクリプション URL を貼り付けます。すべて一度に取り込まれ、対応していないリンクは後から静かに壊れるのではなく、理由を添えてその場で弾かれます。
3. **接続します。** TUN モードはシステム全体を通すため管理者権限が必要で、アプリが UAC 経由のワンクリック再起動を提案します。システムプロキシモードなら権限は不要です。

## ドキュメント

- **[しくみ](docs/architecture.md)**（英語）— 2 つのエンジン構成、ルーティング規則の順序、スプリットトンネリングと DNS、自動起動、Android/libbox。
- **[ソースからのビルド](docs/architecture.md#building-from-source)**（英語）— 各プラットフォームの要件とコマンド。

<details>
<summary><b>うまく動かないとき</b></summary>

<br>

**「接続中…」の直後にコアが落ちる** — **ログ**を開いてください。設定は起動前に `sing-box check` で検証されるため、失敗には必ず具体的な理由が付きます。

**TUN モードでインターネットにつながらない** — 別のクライアントがシステムプロキシを残していないか確認し、*厳格なルーティング*をオフにしてみてください（VirtualBox、WSL、一部のアンチチートと競合します）。

**別の VPN クライアントが動いている** — TUN アダプターは 2 つ同時に共存できません。Hiddify をはじめ sing-box ベースのクライアントは同じ `172.19.0.1` と同じデフォルトルートを取り合い、負けた側は「接続済み」のままトラフィックが流れません。もう一方のクライアントは完全に終了してください — プロセスが生きている限りアダプターも生きています。

**特定のサイトだけトンネル内で開けない** — Fake-IP を有効にするか、そのドメインを*常に直接接続*に追加してください。

**レイテンシが「n/a」になる** — コア停止中はサーバーへの TCP ハンドシェイクを測るため、「n/a」はポートに到達できないことを意味します。接続中はプロキシ経由で測定され、実際の経路が反映されます。

**サブスクリプションの状況が出ない** — パネルが `subscription-userinfo` ヘッダーを返していません。3x-ui ではこのヘッダーはサブスクリプションにのみ存在し、単一リンクで追加したサーバーには存在しません。

</details>

## 使用しているもの

[sing-box](https://github.com/SagerNet/sing-box) · [Xray-core](https://github.com/XTLS/Xray-core) · [Wintun](https://www.wintun.net/) · [Slint](https://slint.dev) · [Tauri](https://tauri.app)

## ライセンス

[MIT](LICENSE) © JustRin
