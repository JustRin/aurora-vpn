import type { ru } from "./ru";

export const en: Record<keyof typeof ru, string> = {
  // ------------------------------------------------------------------ shell
  "app.loading": "Loading…",
  "app.loadFailed": "The app failed to start",

  "nav.dashboard": "Overview",
  "nav.servers": "Servers",
  "nav.split": "Split tunneling",
  "nav.routing": "Routing",
  "nav.logs": "Log",
  "nav.settings": "Settings",

  "bar.systemProxy": "System proxy",
  "bar.connecting": "connecting…",
  "bar.disconnected": "disconnected",

  "side.update": "Update",
  "side.downloading": "Downloading…",
  "side.installing": "Installing…",
  "side.installVersion": "Install version {version}",
  "side.updateFailed": "Failed to install the update",
  "side.noCore": "core not found",
  "side.admin": "administrator rights",
  "side.user": "regular rights",
  "side.appVersion": "installed app version",

  // ------------------------------------------------------------------ toasts
  "toast.backendTimeout": "{label}: the backend did not answer within {s} s",
  "toast.disconnectFailed": "Failed to disconnect",
  "toast.settingsFailed": "Settings were not applied",
  "toast.rulesFailed": "Rules were not applied",
  "toast.serverSwitchFailed": "Failed to switch server",
  "toast.modeSwitchFailed": "Failed to switch mode",
  "toast.latencyFailed": "Latency test failed",
  "toast.reloadFailed": "Failed to refresh state",
  "toast.balancerOff": "Automatic selection is off: server picked by hand",

  // ------------------------------------------------------------------ themes
  "theme.dark": "Aurora",
  "theme.midnight": "Midnight",
  "theme.crimson": "Crimson",
  "theme.emerald": "Emerald",
  "theme.swamp": "Swamp",
  "theme.light": "Light",
  "theme.system": "Follow system",

  // ---------------------------------------------------------------- settings
  "set.title": "Settings",
  "set.subtitle":
    "Changes apply immediately; with an active connection the core restarts automatically.",
  "set.dataFolder": "Data folder",
  "set.tabCore": "Core",
  "set.tabClient": "Client",
  "set.autostartFailed": "Failed to change autostart",

  "set.tunnelSection": "Tunnel",
  "set.tunnelMode": "Mode",
  "set.tunnelModeTunDesc":
    "TUN — a Wintun virtual adapter captures traffic system-wide. Needs administrator rights, but per-app rules work.",
  "set.tunnelModeProxyDesc":
    "System proxy — no administrator rights, but only covers apps that honour the system proxy settings.",
  "set.systemProxy": "System proxy",
  "set.tunNeedsAdmin":
    "The app is running without administrator rights — connecting in TUN mode will offer a restart.",

  "set.tunSection": "TUN options",
  "set.tunStack": "Network stack",
  "set.tunStackHint":
    "mixed — gVisor for TCP and the system stack for UDP: the best speed/compatibility trade-off.",
  "set.tunStackMixed": "mixed (recommended)",
  "set.mtuHint": "Default is 9000.",
  "set.strictRoute": "Strict routing",
  "set.strictRouteDesc":
    "Blocks traffic from escaping the tunnel. Turn it off if VirtualBox/WSL or online games stop working.",
  "set.ipv6": "IPv6 support",
  "set.ipv6Desc":
    "Off — DNS answers with A records only. Enable when your ISP and the server actually support IPv6.",
  "set.fakeIpDesc":
    "Speeds up page opens: domains resolve instantly and the real address is resolved by the server. May confuse some local services.",

  "set.dnsRemote": "DNS via VPN",
  "set.dnsRemoteHint":
    "Used for domains going through the tunnel. tls:// and https:// work too.",
  "set.dnsDirect": "Direct DNS",
  "set.dnsDirectHint":
    "For domains bypassing the tunnel and for resolving the server's own address.",

  "set.connSection": "Connection",
  "set.mixedPort": "SOCKS/HTTP port",
  "set.mixedPortHint": "Local mixed proxy.",
  "set.clashPort": "Core control port",
  "set.clashPortHint": "Clash API on 127.0.0.1.",
  "set.latencyUrl": "Latency test URL",
  "set.latencyUrlHint": "The request goes through the selected server.",
  "set.logLevel": "Log level",
  "set.allowLan": "LAN access",
  "set.allowLanDesc":
    "The proxy listens on 0.0.0.0 so other devices on the network can use it. Enable only on a trusted network.",
  "set.balancer": "Server selection",
  "set.balancerManual": "Manual",
  "set.balancerFailover": "Failover",
  "set.balancerFastest": "Fastest",
  "set.balancerRotate": "Rotation",
  "set.balancerManualDesc": "The server you picked is used. Nothing switches on its own.",
  "set.balancerFailoverDesc":
    "Your pick is the primary. When it stops answering, traffic moves to the best live server and returns once the primary is back and stays up. Live connections are not cut.",
  "set.balancerFastestDesc":
    "Every server is checked on a schedule. Traffic moves only to one that beats the current server by the threshold in two consecutive rounds, so servers with similar latency don't swap back and forth.",
  "set.balancerRotateDesc":
    "Each round moves to the next live server down the list; dead ones are skipped.",
  "set.balancerInterval": "Check interval",
  "set.balancerIntervalHint":
    "How often all servers are checked. The current one is checked every 20 seconds.",
  "set.balancerTolerance": "Switch threshold",
  "set.balancerToleranceHint": "Another server has to be at least this much faster.",
  "set.everyMin": "every {n} min",

  "set.subsSection": "Subscriptions",
  "set.subAuto": "Refresh automatically",
  "set.subAutoDesc":
    "The server list, data allowance and expiry are pulled from the panel in the background. A silently stale list is the most common reason a client suddenly stops connecting.",
  "set.subEveryOff": "Never",
  "set.subEvery3h": "every 3 hours",
  "set.subEvery6h": "every 6 hours",
  "set.subEvery12h": "every 12 hours",
  "set.subEveryDay": "once a day",

  "set.languageSection": "Язык / Language",
  "set.language": "Interface language",
  "set.languageDesc":
    "“Follow system” tracks the operating system language. Core lines in the log stay in the engine's own language.",
  "set.langSystem": "Follow system",

  "set.themeSection": "Appearance",
  "set.theme": "Theme",
  "set.themeDesc":
    "“Follow system” tracks the OS setting and switches by itself, including on its light/dark schedule.",

  "set.startupSection": "Startup",
  "set.autostart": "Start with Windows",
  "set.autostartDesc": "The app starts when you sign in.",
  "set.autostartElevated": "Start with administrator rights",
  "set.autostartElevatedDesc":
    "Creates a Windows Task Scheduler task: the app starts elevated and brings TUN up right away — no UAC prompt. Manual launches go through the task too, so an “as administrator” restart is never needed.",
  "set.autostartElevatedNeedsAdmin":
    "Needs a one-time restart with administrator rights to register the scheduled task.",
  "set.autostartNormalWarn":
    "Plain autostart cannot bring TUN up: after sign-in the app will ask for rights. Enable the toggle above to avoid that.",
  "set.autoConnect": "Connect on launch",
  "set.startMinimized": "Start minimized to tray",
  "set.closeToTray": "Closing the window minimizes to tray",
  "set.closeToTrayDesc":
    "Off — the close button quits completely and drops the connection.",
  "set.resourcesSection": "Resource usage",
  "set.resourcesDesc":
    "The interface (WebView2) and the core run as separate processes, so Task Manager scatters the app across several rows. This is the whole process family combined; the figures match Task Manager's memory column.",
  "set.resApp": "Application",
  "set.resUi": "Interface (WebView2)",
  "set.resCore": "sing-box core",
  "set.resXray": "Xray core",
  "set.resTotal": "Total",
  "set.resProcs": "processes: {n}",

  "set.aboutSection": "About",
  "set.appVersion": "App version",
  "set.coreVersion": "Core",

  // -------------------------------------------------------------- formatters
  "fmt.byteUnits": "B|KB|MB|GB|TB",
  "fmt.perSecond": "/s",
  "fmt.never": "never",
  "fmt.justNow": "just now",
  "fmt.minAgo": "{n} min ago",
  "fmt.hoursAgo": "{n} h ago",
  "fmt.daysAgo": "{n} d ago",
  "fmt.dayForms": "day|days|days",
  "fmt.noExpiry": "no expiry",
  "fmt.expired": "expired",
  "fmt.expiresToday": "expires today",
  "fmt.noTls": "no TLS",

  // --------------------------------------------------------------- dashboard
  "dash.title": "Overview",
  "dash.subtitle": "Tunnel state, speed, and routing mode.",
  "dash.stateDisconnected": "Disconnected",
  "dash.stateConnecting": "Connecting",
  "dash.stateConnected": "Connected",
  "dash.stateError": "Error",
  "dash.modeRule": "Rules",
  "dash.modeGlobal": "Everything via VPN",
  "dash.modeRuleHelp":
    "Everyday mode: what goes through the VPN is decided by the “Split tunneling” and “Routing” pages.",
  "dash.modeGlobalHelp": "Every connection goes through the VPN, ignoring those pages.",
  "dash.tunNeedsAdmin":
    "TUN mode requires administrator rights — otherwise only the system proxy is available.",
  "dash.restart": "Restart",
  "dash.connect": "Connect",
  "dash.disconnect": "Disconnect",
  "dash.connectFailed": "Failed to connect",
  "dash.noServersTitle": "Nothing to connect to yet",
  "dash.noServersText":
    "Add a server link or a subscription from your panel — the connect button will appear here.",
  "dash.trafficDown": "Down",
  "dash.trafficUp": "Up",
  "dash.thisSession": "This session",
  "dash.closeAllConns": "Close all active connections",
  "dash.connsClosed": "Connections closed",
  "dash.connsCloseFailed": "Failed to close connections",
  "dash.connections": "Connections",
  "dash.clickToClose": "click to close",
  "dash.notConnected": "not connected",
  "dash.testLatency": "Test latency",
  "dash.latency": "Latency",
  "dash.na": "n/a",
  "dash.pingMs": "{ping} ms",
  "dash.clickToTest": "click to test",
  "dash.noServer": "no server selected",

  // ------------------------------------------------------ dashboard children
  "graph.down": "down",
  "graph.up": "up",
  "graph.peak": "peak",
  "graph.aria": "Speed graph",
  "pick.noServer": "No server selected",
  "pick.select": "Select server",
  "pick.testAll": "Test all",
  "pick.badgeFailover": "failover",
  "pick.badgeBackup": "backup server",
  "pick.badgeFastest": "fastest",
  "pick.badgeRotate": "rotation",

  // ------------------------------------------------------------------ servers
  "srv.title": "Servers",
  "srv.subtitleBefore": "Paste",
  "srv.subtitleAfter": "links from your panel — a subscription URL works too.",
  "srv.testLatency": "Test latency",
  "srv.subscriptionBtn": "Subscription",
  "srv.addBtn": "Add",
  "srv.serverDeleted": "Server “{name}” deleted",
  "srv.deleteFailed": "Failed to delete the server",
  "srv.noRawLink": "This server has no original link",
  "srv.linkCopied": "Link copied",
  "srv.subscriptions": "Subscriptions",
  "srv.refreshAll": "Refresh all",
  "srv.refreshFailed": "Refresh failed",
  "srv.deleteSubTitle": "Delete the subscription and its servers",
  "srv.emptyTitle": "No servers yet",
  "srv.emptyText":
    "Copy a server or subscription link from your panel (in 3x-ui, the “Share” button on the client) and paste it here. You can paste several lines at once.",
  "srv.pasteLinks": "Paste links",
  "srv.selectServer": "Select server",
  "srv.latencyNa": "n/a",
  "srv.latencyMs": "{ms} ms",
  "srv.copyLinkTitle": "Copy link",
  "srv.editTitle": "Edit",
  "srv.deleteTitle": "Delete",
  "srv.addManually": "Add a server manually",
  "srv.reportAdded": "added {n}",
  "srv.reportSkipped": "skipped {n} duplicates",
  "srv.reportNothing": "nothing added",
  "srv.reportErrors": "with errors: {n}",
  "srv.reportNoNew": "No new servers",
  "srv.importFailed": "Import failed",
  "srv.addServers": "Add servers",
  "srv.cancel": "Cancel",
  "srv.importBtn": "Import",
  "srv.linksLabel": "Links",
  "srv.linksHint":
    "One per line. Supports vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, or a whole base64 subscription block — and an http(s) subscription link will be added to “Subscriptions” and refresh on its own.",
  "srv.linkPlaceholder":
    "vless://uuid@server:443?type=tcp&security=reality&pbk=...#Name",
  "srv.subLoadFailed": "Failed to load the subscription",
  "srv.addSubscription": "Add subscription",
  "srv.loadBtn": "Load",
  "srv.nameLabel": "Name",
  "srv.subNameHint": "Optional — taken from the address by default.",
  "srv.subNamePlaceholder": "My server",
  "srv.subUrlLabel": "Subscription URL",
  "srv.subUrlHint":
    "For example, in 3x-ui it is the Subscription URL link from the client settings.",
  "srv.serverNotAdded": "Server not added",
  "srv.duplicateServer": "this server is already in the list",
  "srv.serverAdded": "Server added",
  "srv.serverSaved": "Server saved",
  "srv.saveFailed": "Failed to save",
  "srv.newServer": "New server",
  "srv.serverParams": "Server settings",
  "srv.saveBtn": "Save",
  "srv.protocolLabel": "Protocol",
  "srv.addressLabel": "Address",
  "srv.portLabel": "Port",
  "srv.passwordLabel": "Password",
  "srv.encryptionLabel": "Encryption",
  "srv.transportLabel": "Transport",
  "srv.channelEncryptionLabel": "Channel encryption",
  "srv.noTls": "no TLS",
  "srv.tlsFingerprintLabel": "TLS fingerprint (fp)",
  "srv.flowHint": "Usually xtls-rprx-vision or empty.",
  "srv.skipCertLabel": "Don't verify the certificate",
  "srv.skipCertDesc":
    "Only needed for a self-signed certificate on the server. The connection stays encrypted, but a substituted certificate cannot be detected.",
  "srv.muxLabel": "Multiplexing (mux)",
  "srv.muxDesc":
    "Several requests in one connection. Speeds up page loads, but is incompatible with XTLS Vision and interferes with torrents.",
  "srv.subRefreshFailed": "Failed to refresh “{name}”",
  "srv.refreshNow": "Refresh now",
  "srv.remaining": "Remaining",
  "srv.trafficLabel": "Data",
  "srv.expiredWarning":
    "The subscription has expired — the servers most likely no longer respond.",
  "srv.exhaustedWarning": "Data limit reached — renew your plan in the panel.",
  "srv.noUsageInfo": "The panel does not report data limits or expiry",
  "srv.serverOne": "server",
  "srv.serverFew": "servers",
  "srv.serverMany": "servers",
  "srv.updatedWhen": "updated {when}",

  // ------------------------------------------------------------ split tunnel
  "split.title": "Split tunneling",
  "split.subtitle":
    "Rules for specific apps. An app's route and DNS queries always take the same path, so the address never leaks outside the tunnel.",
  "split.modeOffHelp": "All system traffic goes through the VPN.",
  "split.modeIncludeHelp":
    "Only selected apps go via VPN. Everything else goes directly, bypassing the tunnel.",
  "split.modeExcludeHelp":
    "Selected apps bypass VPN and go directly. All other traffic goes through the tunnel.",
  "split.exeDialogTitle": "Choose a program",
  "split.exeDialogFilter": "Programs",
  "split.alreadyInList": "This program is already in the list",
  "split.tunOnlyTitle": "Works only in TUN mode",
  "split.tunOnlyText":
    "System proxy mode is currently on. Telling which app owns a connection is only possible when traffic goes through the virtual adapter — switch the mode in settings.",
  "split.mode": "Mode",
  "split.modeOff": "Off",
  "split.modeInclude": "Only selected",
  "split.modeExclude": "All except selected",
  "split.appsCount": "Apps ({count})",
  "split.addFromRunning": "From running apps",
  "split.pickExe": "Choose .exe",
  "split.clearList": "Clear list",
  "split.emptyTitle": "The list is empty",
  "split.emptyText":
    "Add apps — for example, a banking client and Steam bypassing the VPN, or only the browser via VPN.",
  "split.matchByName": "matched by process name",
  "split.procsFailed": "Failed to get the process list",
  "split.runningApps": "Running apps",
  "split.cancel": "Cancel",
  "split.addCount": "Add ({count})",
  "split.searchPlaceholder": "Search by name or path",
  "split.refresh": "Refresh",
  "split.showSystemProcs": "Show Windows system processes",
  "split.loading": "Loading…",
  "split.nothingFound": "Nothing found",
  "split.instancesCount": "{count} processes",
  "split.alreadyAdded": "already added",
  "split.selectedChip": "selected",

  // ------------------------------------------------------------------ routing
  "route.title": "Routing",
  "route.subtitle":
    "Rules apply top to bottom, the first match wins: blocks → local network → your lists → geo rules → app rules.",
  "route.showConfig": "Show config",
  "route.buildFailed": "Failed to build the configuration",
  "route.presets": "Presets",
  "route.bypassLan": "Don't touch the local network",
  "route.bypassLanDesc":
    "Router, printers, NAS and localhost go directly. Disable this only deliberately — otherwise devices on your home network will become unreachable.",
  "route.bypassRu": "Russian sites bypass VPN",
  "route.bypassRuDesc":
    "Domains and addresses from the geosite/geoip ru lists go directly. Speeds up access to local services and removes captchas.",
  "route.bypassCn": "Chinese sites bypass VPN",
  "route.bypassCnDesc": "The same for the geosite/geoip cn list.",
  "route.blockAds": "Block ads and trackers",
  "route.blockAdsDesc":
    "Requests to domains from the category-ads-all list are rejected at the core and DNS level.",
  "route.customRules": "Custom rules",
  "route.directDomains": "Always direct — domains",
  "route.directDomainsHint":
    "One per line. Suffix match: example.com also covers sub.example.com.",
  "route.proxyDomains": "Always via VPN — domains",
  "route.proxyDomainsHint":
    "Takes priority over geo rules, but yields to the “always direct” list.",
  "route.directIps": "Always direct — addresses",
  "route.directIpsHint": "IP or CIDR, e.g. 10.0.0.0/8.",
  "route.proxyIps": "Always via VPN — addresses",
  "route.proxyIpsHint": "IP or CIDR.",
  "route.blockDomains": "Block domains",
  "route.blockDomainsHint":
    "Connections are rejected and no DNS answer is returned.",
  "route.configTitle": "Generated sing-box configuration",
  "route.copied": "Copied",
  "route.copy": "Copy",
  "route.close": "Close",

  // --------------------------------------------------------------------- logs
  "logs.title": "Core log",
  "logs.subtitle":
    "Real-time sing-box output. Look here if the connection keeps dropping.",
  "logs.filterAll": "All",
  "logs.filterInfo": "Info",
  "logs.filterWarn": "Warn",
  "logs.filterErrors": "Errors",
  "logs.copyAll": "Copy all",
  "logs.copied": "Log copied",
  "logs.clear": "Clear",
  "logs.empty": "The log is empty — entries will appear after connecting.",
  "logs.toLatest": "To the latest entries",

  // ------------------------------------------------------------ elevate modal
  "elev.title": "Administrator rights required",
  "elev.relaunchFailed": "Restart failed",
  "elev.cancel": "Cancel",
  "elev.restart": "Restart",
  "elev.tunnelWhy":
    "TUN mode intercepts all system traffic through the Wintun virtual adapter. Creating it requires administrator rights — Windows will show a UAC prompt.",
  "elev.tunnelAlt":
    "If you don't want to elevate, switch to system proxy mode in settings: it works without UAC but only covers apps that respect the system proxy settings.",
  "elev.autostartWhy":
    "Autostart with administrator rights creates a task in the Windows Task Scheduler — a regular startup entry can't do that, the system won't elevate rights without confirmation.",
  "elev.autostartOnce":
    "Rights are needed only once, to register the task. After that the app will start with administrator rights on its own, without a UAC prompt at every sign-in.",
} as const;
