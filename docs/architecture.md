# How it works

**English** · [Русский](architecture.ru.md) · [← back to README](../README.md)

Engineering notes: why there are two network engines, the order routing rules
are applied in, what happens to DNS and autostart, and how to build all of it.

---

## What the app is made of

| Layer | What it is |
|---|---|
| App core | Rust: link and subscription parsing, config generation, engine supervisor, Clash API client |
| UI on Windows | native **Slint** (`spike-slint/`) — no WebView2 |
| UI on Linux, macOS and Android | **Tauri v2** + React/TypeScript (`src/`, `src-tauri/`) |
| Network engines | **sing-box** as the main one, **Xray-core** for nodes sing-box can't handle |
| Engine on Android | the same sing-box, but as the **libbox** library inside `VpnService` — like Hiddify and NekoBox |

Logic is deliberately kept away from the platform: link parsing, config
generation and core supervision are shared, while everything platform-specific
sits in `sys/`. The core files (`link.rs`, `core/config.rs` and neighbours) are
identical in both builds, so the Windows client and the other platforms never
drift apart.

---

## Two engines

sing-box handles TUN, routing, split tunneling and a control API, but it misses
two things from the Xray world: **VLESS Encryption**
(`encryption=mlkem768x25519plus…`, the post-quantum ML-KEM-768 + X25519 layer
from Xray-core 25.x) and the **XHTTP** transport. It doesn't know the field at
all — it rejects the config with `unknown field "encryption"`.

Swapping the core out entirely would be a bad trade: Xray has no Hysteria2 or
TUIC, and per-app split tunneling would have to be rewritten on top of WFP. So
the engines work together:

```
[TUN / SOCKS] → sing-box (rules, split tunnel, DNS, Clash API)
                   ↓  a node it doesn't know
                127.0.0.1:24150+  →  Xray  →  server
```

Xray only starts when such a node exists, and gets one SOCKS listener per node.
To sing-box those are ordinary `socks` outbounds, so the selector, urltest and
latency probes behave identically for both engines. Detection is automatic:
`ServerNode::needs_xray()`.

### The second engine must bypass the tunnel

`auto_detect_interface` keeps only sing-box itself out of its own TUN. Xray is a
separate process, and its packets to the server are intercepted like any other
app's traffic: they reach `final: proxy`, land in the selector and come back to
the very SOCKS listener they left from. Xray calls itself in a circle.

That breaks silently — a connection to a local listener always succeeds, so the
core reports a healthy tunnel, the UI says “Connected”, and not a byte reaches
the server. Latency honestly shows “n/a”: the probe travels the same circle.

So routing gets a pair of rules sending the Xray process `direct` — by full path
and by file name (fields inside one rule are ANDed, hence two rules). They sit
right after `sniff`: before DNS hijacking, or name lookups would join the loop
too, and before Global mode, which would otherwise push everything into the
proxy.

Still unsupported by either engine: `kcp`, `quic` as a VLESS transport and
`headerType=http` obfuscation over TCP. Such links are rejected at import with a
reason, instead of sitting in the list silently broken.

---

## Routing rule order

sing-box applies the first matching rule, so the order *is* the product logic:

```
sniff → Xray bypass → DNS hijack → Rule/Global/Direct mode → blocklists
  → local network → “always direct” → “always through VPN”
  → geo rule sets → per-app rules → default route
```

Two consequences worth remembering:

1. **Explicit lists beat geo sets.** A domain in “always through VPN” goes into
   the tunnel even if it also matches `geosite-ru`.
2. **Per-app rules come last.** They only decide the fate of traffic the rules
   above didn't already claim.

### Geo sets are cached by the app, not fetched by the core

`type: remote` in sing-box is a hard startup dependency: if the `.srs` file
doesn't download, the service won't come up. On a network where GitHub is
unreachable — exactly the network you need a VPN for — enabling ad blocking or
the RU bypass would make the tunnel unstartable.

So the app downloads the sets itself (`core/ruleset.rs`), stores them in
`core/rulesets/` and hands them to the core as `type: local`. A stale copy beats
a missing one; a set that isn't there **disables its own rule** together with its
pair (geosite without geoip is never applied — otherwise domains would leave the
tunnel while direct IP connections entered it).

### Split tunneling and DNS

A per-app rule is mirrored into the DNS section. This matters: if the traffic
route and the DNS route disagree, an app outside the tunnel still reveals its
domains to the DNS server behind the VPN (or the other way round). That's why
`process_name` goes into both `route.rules` and `dns.rules`.

Matching by process name requires TUN mode — outside it the core has no idea
which app a connection belongs to.

---

## The driver and administrator rights

In TUN mode sing-box brings up a virtual network adapter through **Wintun** (the
driver by the WireGuard authors). Nothing has to be installed separately: the
sing-box build carries `wintun.dll` inside itself and loads it from memory
(`internal/wintun/memmod`), driver package included.

The one requirement is **administrator rights**: without them the adapter can't
be created. The app checks this up front and offers either a restart through UAC
or a switch to system proxy mode, which needs no elevation.

### Autostart

An entry in `HKCU\...\Run` is enough to start the app at login, but it **cannot**
start it elevated: Windows will not raise privileges without a UAC confirmation,
and there's nobody to click “Yes” during login. Plain autostart in TUN mode would
therefore hit an elevation prompt every single time.

Hence two mechanisms:

| Mode | Mechanism | Rights |
|---|---|---|
| Plain | `AuroraVPN` value in `HKCU\...\Run` | none |
| Elevated | `Aurora VPN Autostart` task in Task Scheduler, `RunLevel = HighestAvailable` | once, at registration |

They're mutually exclusive — otherwise the app would start twice. Registering and
removing the task needs administrator rights, so switching between them offers a
one-time restart through UAC.

While the task is registered, a manual launch goes through it as well: the plain
(unelevated) process notices the task, runs it via `schtasks /Run` — the
scheduler starts the same app elevated and without a UAC prompt — and exits
immediately. Before handing over, it verifies that the task points at the same
executable and that another instance isn't already running (otherwise the plain
path simply focuses the existing window).

The task is created from XML rather than a set of `schtasks` switches: the
command-line form silently applies two defaults that suit a VPN client badly — it
stops the task after 72 hours and forbids starting on battery.

The source of truth is the system itself, not the settings file: state is read
from the registry and the scheduler on every launch, so disabling autostart with
third-party tools is reflected correctly in the UI.

---

## Subscription status

Panels report plan status not in the response body but in the subscription's HTTP
headers:

```
subscription-userinfo: upload=0; download=42949672960; total=107374182400; expire=1767225600
profile-update-interval: 12
profile-title: base64:...
```

The client reads them on every refresh and shows the remaining days and traffic
on the main screen. If the panel sends no header, the app says the limits are
unknown instead of inventing a “0 of 0”. `expire` is normalised: some panels send
milliseconds instead of seconds.

Background refresh follows the schedule from settings (daily by default) and
checks once a minute whether the list has expired. The provider's
`profile-update-interval` is stored, but the user sets the period — so behaviour
stays predictable.

---

## Themes

Palettes: **Aurora** (default), **Midnight**, **Crimson**, **Emerald**, **Swamp**
and **Light**, plus *follow system*, which tracks the Windows setting including
its light/dark schedule.

The interface rests on three scales: geometry, typography and spacing in
multiples of four. Mixing radii of 7/9/10/12 and fonts across 11–15 pixels is the
clearest sign of an interface assembled by eye, so new elements take values from
the scales instead of guessing them. Hierarchy is built on contrast rather than
three shades of grey: the label is small, uppercase and letter-spaced; the value
is large, semibold, with tabular figures.

A theme is more than a set of colours. Beneath the whole interface lies the
`.ambient` layer: three soft glows drifting slowly along their own paths, plus a
light grain that hides banding on gradients this large. Every surface above is
translucent and blurred, so the glow tints cards, borders and labels instead of
sitting behind them as a picture. The drift animation is disabled under
`prefers-reduced-motion`.

Two rules when adding a palette:

1. `--on-accent` must be readable on `--accent`. A light accent with a white
   label is the most common way to make a theme unreadable — which is exactly why
   Swamp's accent is darkened relative to real moss.
2. Glow coordinates are expressed in the enlarged block's space (`inset: -25%`),
   not the screen's. `22% 19%` is the top-left corner of the visible area; read
   as screen coordinates, the light drifts out of frame.

In the Tauri builds the palette is mirrored into settings as `themeDark` and
`themeBackground` so Rust can paint the window **before** the WebView loads —
otherwise the previous theme's background would flash at startup.

---

## Android

The desktop scheme — a supervisor plus engine processes — is impossible on
Android: only `VpnService` hands out a tunnel interface, and its file descriptor
must be given to the engine inside the app's own process. So:

- sing-box is built into **libbox** (gomobile) and lives inside a Kotlin service
  (`gen/android/.../AuroraVpnService.kt`); it receives the TUN descriptor through
  `PlatformInterface.openTun`, and the same config `core/config.rs` builds;
- the Rust bridge is `core/android.rs`: a Tauri plugin calls the Kotlin
  start/stop/status commands, while the core writes logs to a file that Rust
  streams into the **Log** page;
- the Clash API on loopback stays the control plane — statistics, latency and
  server switching run the same code as on desktop;
- per-app split tunneling is done by `VpnService` itself
  (`include_package`/`exclude_package` in the tun inbound), and `PackageManager`
  provides the app list in place of a process list;
- Xray nodes are not supported: VLESS Encryption nodes fall back to classic VLESS
  automatically, and XHTTP nodes state the reason in the log. Building libxray is
  a separate task.

---

## Where the data lives

`%APPDATA%\com.aurora.vpn\` on Windows, the equivalent config directory
elsewhere:

```
settings.json          settings
servers.json           servers
subscriptions.json     subscriptions
split.json             split tunneling rules
core/config.json       the generated sing-box configuration
core/cache.db          core and geo set cache
```

The **Data folder** button in settings opens it directly. The **Show config**
button on the **Routing** page shows the final document — the first thing to look
at when debugging.

---

## Project layout

```
spike-slint/             native Windows client
  ui/                    Slint interface (pages, widgets, themes)
  src/                   app core + the bridge to the UI
  installer/             NSIS script and installer build

src/                     React interface (Linux, macOS, Android)
  lib/types.ts           types mirroring the Rust serde models
  store.ts               app state (zustand)
  pages/                 Overview, Servers, Split tunnel, Routing, Log, Settings

src-tauri/src/           Tauri build
  model.rs               server model → sing-box outbound
  link.rs                link and subscription parsing
  settings.rs            settings, split tunneling rules
  core/config.rs         sing-box configuration assembly  ← the main logic
  core/process.rs        core launch, log capture, shutdown (desktop)
  core/android.rs        bridge to VpnService/libbox (Android)
  core/clash.rs          Clash API client (stats, latency, switching)
  sys/                   elevation, system proxy, autostart, process list
  commands.rs            commands exposed to the UI

scripts/fetch-core.mjs   downloads the sing-box and Xray binaries for the platform
```

---

## Building from source

One step is shared by every platform — the engines:

```bash
node scripts/fetch-core.mjs
```

The script puts sing-box and Xray into `src-tauri/binaries/` under a name with
the target triple, which is how both builds pick them up.

### Windows (native Slint client)

You need: [Rust](https://rustup.rs/) stable (`x86_64-pc-windows-msvc`), Visual
Studio Build Tools 2022 with “Desktop development with C++” and the Windows SDK,
and [Node.js](https://nodejs.org/) 20+ (for the script above only).

```bash
cargo run --release --manifest-path spike-slint/Cargo.toml
```

The NSIS installer (needs `makensis`):

```bash
powershell -ExecutionPolicy Bypass -File spike-slint/installer/build.ps1
```

### Linux and macOS (Tauri)

You need: Rust stable, Node.js 20+, and the WebKitGTK system libraries (on Linux:
`libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`,
`libgtk-3-dev`, `libxdo-dev`, `patchelf`).

```bash
npm install
npm run app          # development run
npm run app:build    # AppImage / deb / rpm / dmg
```

### Android

You need: JDK 17+, the Android SDK and NDK, Go 1.24+, and the Rust targets
`aarch64-linux-android` and friends.

```bash
npm run libbox                        # libbox.aar, ~20 minutes, once per version
npm run tauri android build -- --apk
```

CI does the same in the `build-android` job; the resulting AAR is cached per
version. Release APK signing comes from the `ANDROID_KEYSTORE*` secrets; without
them the APK is signed with a debug key (it installs, but updates will require a
reinstall).

### Tests

```bash
npm run test:core    # core tests (cargo test)
```
