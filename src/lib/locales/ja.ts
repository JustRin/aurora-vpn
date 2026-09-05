import type { ru } from "./ru";

export const ja: Record<keyof typeof ru, string> = {
  // ------------------------------------------------------------------ shell
  "app.loading": "読み込み中…",
  "app.loadFailed": "アプリを起動できませんでした",

  "nav.dashboard": "概要",
  "nav.servers": "サーバー",
  "nav.split": "スプリットトンネリング",
  "nav.routing": "ルーティング",
  "nav.logs": "ログ",
  "nav.settings": "設定",

  "bar.systemProxy": "システムプロキシ",
  "bar.connecting": "接続中…",
  "bar.disconnected": "切断済み",

  "side.update": "更新",
  "side.downloading": "ダウンロード中…",
  "side.installing": "インストール中…",
  "side.installVersion": "バージョン {version} をインストール",
  "side.updateFailed": "更新をインストールできませんでした",
  "side.noCore": "コアが見つかりません",
  "side.admin": "管理者権限",
  "side.user": "通常の権限",
  "side.admin.unix": "root 権限",
  "side.admin.mac": "コアは root で動作",
  "side.appVersion": "インストール済みのアプリのバージョン",

  // ------------------------------------------------------------------ toasts
  "toast.backendTimeout": "{label}: バックエンドが {s} 秒以内に応答しませんでした",
  "toast.disconnectFailed": "切断できませんでした",
  "toast.settingsFailed": "設定が適用されませんでした",
  "toast.rulesFailed": "ルールが適用されませんでした",
  "toast.serverSwitchFailed": "サーバーを切り替えられませんでした",
  "toast.modeSwitchFailed": "モードを切り替えられませんでした",
  "toast.latencyFailed": "レイテンシの計測に失敗しました",
  "toast.reloadFailed": "状態を更新できませんでした",
  "toast.balancerOff": "自動選択をオフにしました。サーバーを手動で選びました",

  // ------------------------------------------------------------------ themes
  "theme.dark": "オーロラ",
  "theme.midnight": "ミッドナイト",
  "theme.crimson": "クリムゾン",
  "theme.emerald": "エメラルド",
  "theme.swamp": "スワンプ",
  "theme.light": "ライト",
  "theme.system": "システムに合わせる",

  // ---------------------------------------------------------------- settings
  "set.title": "設定",
  "set.subtitle":
    "変更はすぐに反映されます。接続中の場合はコアが自動で再起動します。",
  "set.dataFolder": "データフォルダー",
  "set.tabCore": "コア",
  "set.tabClient": "クライアント",
  "set.autostartFailed": "自動起動を変更できませんでした",

  "set.tunnelSection": "トンネル",
  "set.tunnelMode": "モード",
  "set.tunnelModeTunDesc":
    "TUN — Wintun 仮想アダプターがシステム全体の通信を受け取ります。管理者権限が必要ですが、アプリ単位のルールが使えます。",
  "set.tunnelModeTunDesc.unix":
    "TUN — 仮想ネットワークインターフェースがシステム全体の通信を受け取ります。root 権限（sudo での起動）が必要ですが、アプリ単位のルールが使えます。",
  "set.tunnelModeTunDesc.mac":
    "TUN — 仮想ネットワークインターフェースがシステム全体の通信を受け取ります。コアには root 権限（管理者パスワードで一度だけ付与）が必要ですが、アプリ単位のルールが使えます。",
  "set.tunnelModeProxyDesc":
    "システムプロキシ — 管理者権限は不要ですが、システムプロキシ設定に従うアプリしか対象になりません。",
  "set.tunnelModeProxyDesc.unix":
    "システムプロキシ — 現在は Windows のみ対応です。macOS と Linux では TUN を使ってください。",
  "set.systemProxy": "システムプロキシ",
  "set.tunNeedsAdmin":
    "アプリは管理者権限なしで動作しています。TUN モードで接続すると再起動を求められます。",
  "set.tunNeedsAdmin.unix": "アプリは root 権限なしで動作しているため、TUN モードは使えません。ターミナルから起動してください：",
  "set.tunNeedsAdmin.mac":
    "コアにまだ root 権限が付与されていないため、TUN モードは使えません。macOS が管理者パスワードを一度だけ求めます。ターミナルから起動する方法もあります：",

  "set.tunSection": "TUN の設定",
  "set.tunStack": "ネットワークスタック",
  "set.tunStackHint":
    "mixed — TCP は gVisor、UDP はシステムスタック。速度と互換性のバランスが最も良い設定です。",
  "set.tunStackMixed": "mixed（推奨）",
  "set.mtuHint": "既定値は 9000 です。",
  "set.strictRoute": "厳格なルーティング",
  "set.strictRouteDesc":
    "通信がトンネルの外に漏れるのを防ぎます。VirtualBox/WSL やオンラインゲームが動かなくなったらオフにしてください。",
  "set.ipv6": "IPv6 対応",
  "set.ipv6Desc":
    "オフのとき DNS は A レコードだけを返します。プロバイダーとサーバーが実際に IPv6 に対応している場合に有効にしてください。",
  "set.fakeIpDesc":
    "ページの表示を速くします。ドメインは即座に解決され、実際のアドレスはサーバー側で解決されます。一部のローカルサービスが誤動作することがあります。",

  "set.dnsRemote": "VPN 経由の DNS",
  "set.dnsRemoteHint":
    "トンネルを通るドメインに使われます。tls:// と https:// も指定できます。",
  "set.dnsDirect": "直接接続の DNS",
  "set.dnsDirectHint":
    "トンネルを迂回するドメインと、サーバー自身のアドレスの解決に使われます。",

  "set.connSection": "接続",
  "set.mixedPort": "SOCKS/HTTP ポート",
  "set.mixedPortHint": "ローカルの混合プロキシ。",
  "set.clashPort": "コア制御ポート",
  "set.clashPortHint": "127.0.0.1 上の Clash API。",
  "set.latencyUrl": "レイテンシ計測 URL",
  "set.latencyUrlHint": "リクエストは選択中のサーバーを経由します。",
  "set.logLevel": "ログレベル",
  "set.allowLan": "LAN からの利用",
  "set.allowLanDesc":
    "プロキシが 0.0.0.0 で待ち受け、同じネットワークの他の端末からも使えるようになります。信頼できるネットワークでのみ有効にしてください。",
  "set.balancer": "サーバーの選択",
  "set.balancerManual": "手動",
  "set.balancerFailover": "フェイルオーバー",
  "set.balancerFastest": "最速",
  "set.balancerRotate": "ローテーション",
  "set.balancerManualDesc": "選んだサーバーをそのまま使います。自動では切り替わりません。",
  "set.balancerFailoverDesc":
    "選んだサーバーがメインです。応答しなくなると最良の生きているサーバーへ移り、メインが復帰して安定したら戻ります。既存の接続は切れません。",
  "set.balancerFastestDesc":
    "すべてのサーバーを定期的に計測します。設定したしきい値以上に速いサーバーが 2 回続けて現れたときだけ切り替えるので、同じくらいの遅延のサーバー間で行き来しません。",
  "set.balancerRotateDesc":
    "毎回、リストの次の生きているサーバーへ移ります。落ちているサーバーは飛ばします。",
  "set.balancerInterval": "計測の間隔",
  "set.balancerIntervalHint":
    "すべてのサーバーを計測する間隔。使用中のサーバーは 20 秒ごとに計測します。",
  "set.balancerTolerance": "切り替えのしきい値",
  "set.balancerToleranceHint": "別のサーバーが少なくともこれだけ速い必要があります。",
  "set.everyMin": "{n} 分ごと",

  "set.subsSection": "サブスクリプション",
  "set.subAuto": "自動で更新する",
  "set.subAutoDesc":
    "サーバー一覧、データ量、有効期限をバックグラウンドでパネルから取得します。一覧が黙って古くなることは、クライアントが突然つながらなくなる最もよくある原因です。",
  "set.subEveryOff": "しない",
  "set.subEvery3h": "3 時間ごと",
  "set.subEvery6h": "6 時間ごと",
  "set.subEvery12h": "12 時間ごと",
  "set.subEveryDay": "1 日 1 回",

  "set.languageSection": "言語 / Language",
  "set.language": "表示言語",
  "set.languageDesc":
    "「システムに合わせる」は OS の言語に追従します。ログ中のコアの行はエンジン自身の言語のままです。",
  "set.langSystem": "システムに合わせる",

  "set.themeSection": "外観",
  "set.theme": "テーマ",
  "set.themeDesc":
    "「システムに合わせる」は OS の設定に追従し、ライト／ダークのスケジュールも含めて自動で切り替わります。",

  "set.startupSection": "起動",
  "set.autostart": "{os} と一緒に起動",
  "set.autostartDesc": "サインイン時にアプリが起動します。",
  "set.autostartElevated": "管理者権限で起動する",
  "set.autostartElevatedDesc":
    "Windows のタスク スケジューラにタスクを作成します。アプリが昇格した状態で起動して TUN をすぐ張るため、UAC のプロンプトは出ません。手動での起動もこのタスクを通るので、「管理者として」起動し直す必要はありません。",
  "set.autostartElevatedNeedsAdmin":
    "タスクを登録するため、一度だけ管理者権限での再起動が必要です。",
  "set.autostartNormalWarn":
    "通常の自動起動では TUN を張れません。サインイン後にアプリが権限を求めます。上のスイッチを入れれば回避できます。",
  "set.autostartNormalWarn.unix":
    "自動起動ではアプリが root 権限なしで立ち上がるため、サインイン後に TUN モードは自動では張られません。sudo での再起動が必要になります。",
  "set.autostartNormalWarn.mac": "コアに root 権限を付与するまで、サインイン後に TUN モードは自動では張られません。",
  "set.autoConnect": "起動時に接続する",
  "set.startMinimized": "最小化してトレイで起動する",
  "set.startMinimized.mac": "最小化してメニューバーで起動する",
  "set.closeToTray": "ウィンドウを閉じたらトレイへ最小化する",
  "set.closeToTray.mac": "ウィンドウを閉じたらメニューバーへ最小化する",
  "set.closeToTrayDesc": "オフのとき、閉じるボタンは完全に終了し接続も切れます。",
  "set.resourcesSection": "リソース使用量",
  "set.resourcesDesc":
    "インターフェース（WebView2）とコアは別々のプロセスとして動くため、タスク マネージャーではアプリが複数行に分かれて表示されます。ここに出るのはプロセス一式の合計で、タスク マネージャーのメモリ列と一致します。",
  "set.resourcesDesc.mac":
    "コアは別プロセスとして動くため、アクティビティモニタではアプリが複数行に分かれて表示されます。ここに出るのはプロセス一式の合計です。",
  "set.resourcesDesc.linux":
    "インターフェース（WebKitGTK）とコアは別々のプロセスとして動くため、システムモニターではアプリが複数行に分かれて表示されます。ここに出るのはプロセス一式の合計です。",
  "set.resApp": "アプリケーション",
  "set.resUi": "インターフェース（{engine}）",
  "set.resCore": "sing-box コア",
  "set.resXray": "Xray コア",
  "set.resTotal": "合計",
  "set.resProcs": "プロセス数: {n}",

  "set.aboutSection": "情報",
  "set.appVersion": "アプリのバージョン",
  "set.coreVersion": "コア",

  // -------------------------------------------------------------- formatters
  "fmt.byteUnits": "B|KB|MB|GB|TB",
  "fmt.perSecond": "/秒",
  "fmt.never": "なし",
  "fmt.justNow": "たった今",
  "fmt.minAgo": "{n} 分前",
  "fmt.hoursAgo": "{n} 時間前",
  "fmt.daysAgo": "{n} 日前",
  "fmt.dayForms": "日|日|日",
  "fmt.noExpiry": "無期限",
  "fmt.expired": "期限切れ",
  "fmt.expiresToday": "本日期限切れ",
  "fmt.noTls": "TLS なし",

  // --------------------------------------------------------------- dashboard
  "dash.title": "概要",
  "dash.subtitle": "トンネルの状態、速度、ルーティングモード。",
  "dash.stateDisconnected": "切断済み",
  "dash.stateConnecting": "接続中",
  "dash.stateConnected": "接続済み",
  "dash.stateError": "エラー",
  "dash.modeRule": "ルール",
  "dash.modeGlobal": "すべて VPN 経由",
  "dash.modeRuleHelp":
    "普段使いのモード。何を VPN に通すかは「スプリットトンネリング」と「ルーティング」のページで決まります。",
  "dash.modeGlobalHelp":
    "それらのページを無視して、すべての通信が VPN を通ります。",
  "dash.tunNeedsAdmin":
    "TUN モードには管理者権限が必要です。ない場合はシステムプロキシのみ利用できます。",
  "dash.tunNeedsAdmin.unix": "TUN モードには root 権限が必要です。sudo でアプリを起動してください。",
  "dash.tunNeedsAdmin.mac": "TUN モードには root 権限が必要です。コアに付与してください。macOS がパスワードを一度だけ求めます。",
  "dash.restart": "再起動",
  "dash.showCommand": "コマンドを表示",
  "dash.connect": "接続",
  "dash.disconnect": "切断",
  "dash.connectFailed": "接続できませんでした",
  "dash.noServersTitle": "まだ接続先がありません",
  "dash.noServersText":
    "サーバーのリンクか、パネルのサブスクリプションを追加すると、ここに接続ボタンが現れます。",
  "dash.trafficDown": "下り",
  "dash.trafficUp": "上り",
  "dash.thisSession": "今回のセッション",
  "dash.closeAllConns": "アクティブな接続をすべて閉じる",
  "dash.connsClosed": "接続を閉じました",
  "dash.connsCloseFailed": "接続を閉じられませんでした",
  "dash.connections": "接続数",
  "dash.clickToClose": "クリックで切断",
  "dash.notConnected": "未接続",
  "dash.testLatency": "レイテンシを測る",
  "dash.latency": "レイテンシ",
  "dash.na": "n/a",
  "dash.pingMs": "{ping} ms",
  "dash.clickToTest": "クリックで計測",
  "dash.noServer": "サーバー未選択",
  "dash.stateUnreachable": "サーバーが応答しません",
  "dash.stateReconnecting": "再接続中…",
  "dash.unreachableHint":
    "「{name}」経由の確認が通らず、通信が流れていません。ネットワークを確認するか、別のサーバーを選ぶか、フェイルオーバーを有効にしてください。",
  "dash.unreachableAuto":
    "サーバー経由の確認が通らず、通信が流れていません。バランサーは生きているサーバーが見つかり次第切り替えます。",

  // ------------------------------------------------------ dashboard children
  "graph.down": "下り",
  "graph.up": "上り",
  "graph.peak": "ピーク",
  "graph.aria": "速度グラフ",
  "pick.noServer": "サーバーが選ばれていません",
  "pick.select": "サーバーを選ぶ",
  "pick.testAll": "すべて計測",
  "pick.balancers": "バランサー",
  "pick.servers": "サーバー",
  "pick.badgeBackup": "予備サーバー",
  "pick.now": "現在: {name}",
  "pick.nowChip": "現在",
  "pick.primary": "メイン: {name}",
  "pick.primaryDown": "メインが応答しません",
  "pick.failoverMeta": "メインが沈黙している間だけ代役へ",
  "pick.fastestMeta": "遅延で選択、僅差では切り替えない",
  "pick.rotateMeta": "毎回、次の生きているサーバーへ",

  // ------------------------------------------------------------------ servers
  "srv.title": "サーバー",
  "srv.subtitleBefore": "パネルの",
  "srv.subtitleAfter": "リンクを貼り付けてください。サブスクリプション URL でも構いません。",
  "srv.testLatency": "レイテンシを測る",
  "srv.subscriptionBtn": "サブスクリプション",
  "srv.addBtn": "追加",
  "srv.serverDeleted": "サーバー「{name}」を削除しました",
  "srv.deleteFailed": "サーバーを削除できませんでした",
  "srv.noRawLink": "このサーバーには元のリンクがありません",
  "srv.linkCopied": "リンクをコピーしました",
  "srv.subscriptions": "サブスクリプション",
  "srv.refreshAll": "すべて更新",
  "srv.refreshFailed": "更新に失敗しました",
  "srv.deleteSubTitle": "サブスクリプションとそのサーバーを削除",
  "srv.emptyTitle": "サーバーがまだありません",
  "srv.emptyText":
    "パネルからサーバーまたはサブスクリプションのリンクをコピーして（3x-ui ならクライアントの「Share」ボタン）、ここに貼り付けてください。複数行をまとめて貼っても構いません。",
  "srv.pasteLinks": "リンクを貼り付ける",
  "srv.selectServer": "サーバーを選ぶ",
  "srv.latencyNa": "n/a",
  "srv.latencyMs": "{ms} ms",
  "srv.copyLinkTitle": "リンクをコピー",
  "srv.editTitle": "編集",
  "srv.deleteTitle": "削除",
  "srv.addManually": "サーバーを手動で追加",
  "srv.reportAdded": "{n} 件追加",
  "srv.reportSkipped": "重複 {n} 件をスキップ",
  "srv.reportNothing": "何も追加されませんでした",
  "srv.reportErrors": "エラー: {n} 件",
  "srv.reportNoNew": "新しいサーバーはありません",
  "srv.importFailed": "取り込みに失敗しました",
  "srv.addServers": "サーバーを追加",
  "srv.cancel": "キャンセル",
  "srv.importBtn": "取り込む",
  "srv.linksLabel": "リンク",
  "srv.linksHint":
    "1 行に 1 つ。vless://、vmess://、trojan://、ss://、hysteria2://、tuic://、base64 のサブスクリプション全体にも対応します。http(s) のサブスクリプションリンクは「サブスクリプション」に追加され、自動で更新されます。",
  "srv.linkPlaceholder":
    "vless://uuid@server:443?type=tcp&security=reality&pbk=...#名前",
  "srv.subLoadFailed": "サブスクリプションを読み込めませんでした",
  "srv.addSubscription": "サブスクリプションを追加",
  "srv.loadBtn": "読み込む",
  "srv.nameLabel": "名前",
  "srv.subNameHint": "任意 — 既定ではアドレスから取られます。",
  "srv.subNamePlaceholder": "マイサーバー",
  "srv.subUrlLabel": "サブスクリプション URL",
  "srv.subUrlHint":
    "たとえば 3x-ui では、クライアント設定にある Subscription URL のリンクです。",
  "srv.serverNotAdded": "サーバーは追加されませんでした",
  "srv.duplicateServer": "このサーバーはすでに一覧にあります",
  "srv.serverAdded": "サーバーを追加しました",
  "srv.serverSaved": "サーバーを保存しました",
  "srv.saveFailed": "保存できませんでした",
  "srv.newServer": "新しいサーバー",
  "srv.serverParams": "サーバーの設定",
  "srv.saveBtn": "保存",
  "srv.protocolLabel": "プロトコル",
  "srv.addressLabel": "アドレス",
  "srv.portLabel": "ポート",
  "srv.passwordLabel": "パスワード",
  "srv.encryptionLabel": "暗号化",
  "srv.transportLabel": "トランスポート",
  "srv.channelEncryptionLabel": "通信路の暗号化",
  "srv.noTls": "TLS なし",
  "srv.tlsFingerprintLabel": "TLS フィンガープリント（fp）",
  "srv.flowHint": "通常は xtls-rprx-vision か空欄です。",
  "srv.skipCertLabel": "証明書を検証しない",
  "srv.skipCertDesc":
    "サーバーが自己署名証明書を使っている場合にのみ必要です。通信は暗号化されたままですが、証明書のすり替えを検出できなくなります。",
  "srv.muxLabel": "多重化（mux）",
  "srv.muxDesc":
    "1 本の接続で複数のリクエストを流します。ページの読み込みは速くなりますが、XTLS Vision とは併用できず、トレントの邪魔にもなります。",
  "srv.subRefreshFailed": "「{name}」を更新できませんでした",
  "srv.refreshNow": "今すぐ更新",
  "srv.remaining": "残り",
  "srv.trafficLabel": "データ量",
  "srv.expiredWarning":
    "サブスクリプションの期限が切れています。サーバーはおそらくもう応答しません。",
  "srv.exhaustedWarning": "データ量を使い切りました。パネルでプランを更新してください。",
  "srv.noUsageInfo": "パネルはデータ量や有効期限を返していません",
  "srv.serverOne": "台のサーバー",
  "srv.serverFew": "台のサーバー",
  "srv.serverMany": "台のサーバー",
  "srv.updatedWhen": "{when}に更新",

  // ------------------------------------------------------------ split tunnel
  "split.title": "スプリットトンネリング",
  "split.subtitle":
    "特定のアプリ向けのルールです。アプリの経路と DNS クエリは常に同じ道を通るので、アドレスがトンネルの外に漏れることはありません。",
  "split.modeOffHelp": "システムのすべての通信が VPN を通ります。",
  "split.modeIncludeHelp":
    "選んだアプリだけが VPN を通ります。それ以外はトンネルを迂回して直接つながります。",
  "split.modeExcludeHelp":
    "選んだアプリは VPN を迂回して直接つながります。ほかの通信はすべてトンネルを通ります。",
  "split.exeDialogTitle": "プログラムを選ぶ",
  "split.exeDialogFilter": "プログラム",
  "split.alreadyInList": "このプログラムはすでに一覧にあります",
  "split.tunOnlyTitle": "TUN モードでのみ動作します",
  "split.tunOnlyText":
    "現在はシステムプロキシモードです。どのアプリの接続かを判別できるのは、通信が仮想アダプターを通るときだけです。設定でモードを切り替えてください。",
  "split.mode": "モード",
  "split.modeOff": "オフ",
  "split.modeInclude": "選んだアプリのみ",
  "split.modeExclude": "選んだアプリ以外すべて",
  "split.appsCount": "アプリ（{count}）",
  "split.addFromRunning": "実行中のアプリから",
  "split.pickExe": ".exe を選ぶ",
  "split.clearList": "一覧を空にする",
  "split.emptyTitle": "一覧が空です",
  "split.emptyText":
    "アプリを追加してください。たとえば銀行のクライアントと Steam を VPN の外に出したり、ブラウザーだけを VPN に通したり。",
  "split.matchByName": "プロセス名で照合",
  "split.procsFailed": "プロセス一覧を取得できませんでした",
  "split.runningApps": "実行中のアプリ",
  "split.cancel": "キャンセル",
  "split.addCount": "追加（{count}）",
  "split.searchPlaceholder": "名前かパスで検索",
  "split.refresh": "更新",
  "split.showSystemProcs": "{os} のシステムプロセスを表示",
  "split.loading": "読み込み中…",
  "split.nothingFound": "見つかりませんでした",
  "split.instancesCount": "{count} プロセス",
  "split.alreadyAdded": "追加済み",
  "split.selectedChip": "選択中",

  // ------------------------------------------------------------------ routing
  "route.title": "ルーティング",
  "route.subtitle":
    "ルールは上から順に評価され、最初に一致したものが勝ちます: ブロック → ローカルネットワーク → 自分のリスト → 地域ルール → アプリのルール。",
  "route.showConfig": "設定を見る",
  "route.buildFailed": "設定を組み立てられませんでした",
  "route.presets": "プリセット",
  "route.bypassLan": "ローカルネットワークには触れない",
  "route.bypassLanDesc":
    "ルーター、プリンター、NAS、localhost は直接つながります。意図がないかぎり無効にしないでください。家庭内の機器に届かなくなります。",
  "route.bypassRu": "ロシアのサイトは VPN を迂回",
  "route.bypassRuDesc":
    "geosite/geoip の ru リストにあるドメインとアドレスが直接つながります。国内サービスが速くなり、キャプチャも減ります。",
  "route.bypassCn": "中国のサイトは VPN を迂回",
  "route.bypassCnDesc": "geosite/geoip の cn リストについて同じことを行います。",
  "route.blockAds": "広告とトラッカーをブロック",
  "route.blockAdsDesc":
    "category-ads-all リストのドメインへのリクエストを、コアと DNS の両方で拒否します。",
  "route.customRules": "自分のルール",
  "route.directDomains": "常に直接 — ドメイン",
  "route.directDomainsHint":
    "1 行に 1 つ。後方一致です: example.com は sub.example.com も含みます。",
  "route.proxyDomains": "常に VPN 経由 — ドメイン",
  "route.proxyDomainsHint":
    "地域ルールより優先されますが、「常に直接」のリストには譲ります。",
  "route.directIps": "常に直接 — アドレス",
  "route.directIpsHint": "IP または CIDR（例: 10.0.0.0/8）。",
  "route.proxyIps": "常に VPN 経由 — アドレス",
  "route.proxyIpsHint": "IP または CIDR。",
  "route.blockDomains": "ドメインをブロック",
  "route.blockDomainsHint": "接続は拒否され、DNS も応答を返しません。",
  "route.configTitle": "生成された sing-box の設定",
  "route.copied": "コピーしました",
  "route.copy": "コピー",
  "route.close": "閉じる",

  // --------------------------------------------------------------------- logs
  "logs.title": "コアのログ",
  "logs.subtitle":
    "sing-box のリアルタイム出力です。接続が切れ続けるときはここを見てください。",
  "logs.filterAll": "すべて",
  "logs.filterInfo": "情報",
  "logs.filterWarn": "警告",
  "logs.filterErrors": "エラー",
  "logs.copyAll": "すべてコピー",
  "logs.copied": "ログをコピーしました",
  "logs.clear": "消去",
  "logs.empty": "ログは空です。接続すると行が現れます。",
  "logs.toLatest": "最新の行へ",

  // ------------------------------------------------------------ elevate modal
  "elev.title": "管理者権限が必要です",
  "elev.title.unix": "root 権限が必要です",
  "elev.relaunchFailed": "再起動できませんでした",
  "elev.cancel": "キャンセル",
  "elev.restart": "再起動",
  "elev.copy": "コマンドをコピー",
  "elev.copied": "コマンドをコピーしました",
  "elev.copyFailed": "コピーできませんでした。コマンドを選択して手動でコピーしてください。",
  "elev.close": "閉じる",
  "elev.altTerminal": "ターミナルから起動する方法もあります：",
  "elev.grant": "権限を付与",
  "elev.granted": "コアに root 権限を付与しました",
  "elev.grantFailed": "権限を付与できませんでした",
  "elev.tunnelWhy":
    "TUN モードは Wintun 仮想アダプターを通じてシステムのすべての通信を横取りします。その作成には管理者権限が必要で、Windows が UAC のプロンプトを表示します。",
  "elev.tunnelWhy.unix":
    "TUN モードは仮想ネットワークインターフェースを通じてシステムのすべての通信を横取りしますが、その作成は root にしかできません。{os} では実行中の昇格ができないため、ターミナルからアプリを起動してください：",
  "elev.tunnelWhy.mac":
    "TUN モードは仮想ネットワークインターフェースを作成しますが、それができるのは root だけです。macOS が管理者パスワードを一度だけ求めます。sing-box コアが root として起動する権限を得て、アプリ本体は通常の権限のままです。アップデートや再インストールの後は、再び確認されます。",
  "elev.tunnelAlt":
    "昇格したくない場合は、設定でシステムプロキシモードに切り替えてください。UAC は不要ですが、システムプロキシ設定に従うアプリしか対象になりません。",
  "elev.autostartWhy":
    "管理者権限での自動起動は Windows のタスク スケジューラにタスクを作ります。通常のスタートアップ項目ではこれができません。システムは確認なしに権限を昇格しないためです。",
  "elev.autostartOnce":
    "権限が必要なのはタスクを登録する一度だけです。以後はアプリが自分で管理者権限で起動し、サインインのたびに UAC が出ることはありません。",
} as const;
