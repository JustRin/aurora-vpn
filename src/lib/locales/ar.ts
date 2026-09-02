import type { ru } from "./ru";

export const ar: Record<keyof typeof ru, string> = {
  // ------------------------------------------------------------------ shell
  "app.loading": "جارٍ التحميل…",
  "app.loadFailed": "تعذّر تشغيل التطبيق",

  "nav.dashboard": "نظرة عامة",
  "nav.servers": "الخوادم",
  "nav.split": "تقسيم النفق",
  "nav.routing": "التوجيه",
  "nav.logs": "السجل",
  "nav.settings": "الإعدادات",

  "bar.systemProxy": "وكيل النظام",
  "bar.connecting": "جارٍ الاتصال…",
  "bar.disconnected": "غير متصل",

  "side.update": "تحديث",
  "side.downloading": "جارٍ التنزيل…",
  "side.installing": "جارٍ التثبيت…",
  "side.installVersion": "تثبيت الإصدار {version}",
  "side.updateFailed": "تعذّر تثبيت التحديث",
  "side.noCore": "لم يُعثر على النواة",
  "side.admin": "صلاحيات المسؤول",
  "side.user": "صلاحيات عادية",
  "side.appVersion": "إصدار التطبيق المثبَّت",

  // ------------------------------------------------------------------ toasts
  "toast.backendTimeout": "{label}: لم تستجب الخلفية خلال {s} ثانية",
  "toast.disconnectFailed": "تعذّر قطع الاتصال",
  "toast.settingsFailed": "لم تُطبَّق الإعدادات",
  "toast.rulesFailed": "لم تُطبَّق القواعد",
  "toast.serverSwitchFailed": "تعذّر تبديل الخادم",
  "toast.modeSwitchFailed": "تعذّر تبديل الوضع",
  "toast.latencyFailed": "فشل قياس زمن الاستجابة",
  "toast.reloadFailed": "تعذّر تحديث الحالة",
  "toast.balancerOff": "أُوقف الاختيار التلقائي: اخترتَ الخادم يدويًا",

  // ------------------------------------------------------------------ themes
  "theme.dark": "الشفق",
  "theme.midnight": "منتصف الليل",
  "theme.crimson": "قرمزي",
  "theme.emerald": "زمردي",
  "theme.swamp": "مستنقع",
  "theme.light": "فاتح",
  "theme.system": "اتّباع النظام",

  // ---------------------------------------------------------------- settings
  "set.title": "الإعدادات",
  "set.subtitle":
    "تسري التغييرات فورًا، وإن كان هناك اتصال قائم فستُعاد تشغيل النواة تلقائيًا.",
  "set.dataFolder": "مجلد البيانات",
  "set.tabCore": "النواة",
  "set.tabClient": "التطبيق",
  "set.autostartFailed": "تعذّر تغيير البدء التلقائي",

  "set.tunnelSection": "النفق",
  "set.tunnelMode": "الوضع",
  "set.tunnelModeTunDesc":
    "‏TUN — محوّل Wintun الافتراضي يلتقط حركة النظام كلها. يحتاج صلاحيات المسؤول، لكن قواعد التطبيقات تعمل معه.",
  "set.tunnelModeProxyDesc":
    "وكيل النظام — لا يحتاج صلاحيات المسؤول، لكنه لا يغطي إلا التطبيقات التي تحترم إعدادات وكيل النظام.",
  "set.systemProxy": "وكيل النظام",
  "set.tunNeedsAdmin":
    "التطبيق يعمل دون صلاحيات المسؤول — وسيعرض إعادة التشغيل عند الاتصال بوضع TUN.",

  "set.tunSection": "خيارات TUN",
  "set.tunStack": "حزمة الشبكة",
  "set.tunStackHint":
    "‏mixed — ‏gVisor لـ TCP وحزمة النظام لـ UDP: أفضل موازنة بين السرعة والتوافق.",
  "set.tunStackMixed": "‏mixed (موصى به)",
  "set.mtuHint": "القيمة الافتراضية 9000.",
  "set.strictRoute": "التوجيه الصارم",
  "set.strictRouteDesc":
    "يمنع تسرّب الحركة خارج النفق. أوقفه إذا توقّف VirtualBox/WSL أو ألعاب الإنترنت عن العمل.",
  "set.ipv6": "دعم IPv6",
  "set.ipv6Desc":
    "عند الإيقاف يردّ DNS بسجلات A فقط. فعّله حين يدعم مزوّدك والخادم IPv6 فعليًا.",
  "set.fakeIpDesc":
    "يسرّع فتح الصفحات: تُحلّ النطاقات فورًا ويتولّى الخادم تحليل العنوان الحقيقي. قد يربك بعض الخدمات المحلية.",

  "set.dnsRemote": "‏DNS عبر VPN",
  "set.dnsRemoteHint":
    "يُستخدم للنطاقات التي تمرّ عبر النفق. ويعمل معه ‎tls://‎ و‎https://‎ أيضًا.",
  "set.dnsDirect": "‏DNS المباشر",
  "set.dnsDirectHint":
    "للنطاقات التي تتجاوز النفق، ولتحليل عنوان الخادم نفسه.",

  "set.connSection": "الاتصال",
  "set.mixedPort": "منفذ SOCKS/HTTP",
  "set.mixedPortHint": "وكيل محلي مختلط.",
  "set.clashPort": "منفذ التحكم بالنواة",
  "set.clashPortHint": "واجهة Clash على 127.0.0.1.",
  "set.latencyUrl": "رابط قياس زمن الاستجابة",
  "set.latencyUrlHint": "يمرّ الطلب عبر الخادم المحدَّد.",
  "set.logLevel": "مستوى السجل",
  "set.allowLan": "الوصول من الشبكة المحلية",
  "set.allowLanDesc":
    "يستمع الوكيل على 0.0.0.0 ليستخدمه بقية أجهزة الشبكة. فعّله في الشبكات الموثوقة فقط.",
  "set.balancer": "اختيار الخادم",
  "set.balancerManual": "يدوي",
  "set.balancerFailover": "احتياطي",
  "set.balancerFastest": "الأسرع",
  "set.balancerRotate": "بالتناوب",
  "set.balancerManualDesc": "يُستخدم الخادم الذي اخترته، ولا يتبدّل شيء تلقائيًا.",
  "set.balancerFailoverDesc":
    "الخادم الذي اخترته هو الأساسي. إذا توقّف عن الاستجابة ينتقل التدفّق إلى أفضل خادم حي، ويعود حين يرجع الأساسي ويستقر. الاتصالات القائمة لا تُقطع.",
  "set.balancerFastestDesc":
    "تُفحص كل الخوادم وفق جدول. لا ينتقل التدفّق إلا إلى خادم يتفوّق على الحالي بالحدّ المضبوط في جولتين متتاليتين، فلا يتأرجح بين خوادم متقاربة الزمن.",
  "set.balancerRotateDesc": "في كل جولة ينتقل إلى الخادم الحي التالي في القائمة، متجاوزًا المعطّل.",
  "set.balancerInterval": "فترة الفحص",
  "set.balancerIntervalHint": "كم مرّة تُفحص كل الخوادم. الخادم الحالي يُفحص كل 20 ثانية.",
  "set.balancerTolerance": "حدّ التبديل",
  "set.balancerToleranceHint": "يجب أن يكون الخادم الآخر أسرع بهذا القدر على الأقل.",
  "set.everyMin": "كل {n} دقيقة",

  "set.subsSection": "الاشتراكات",
  "set.subAuto": "التحديث تلقائيًا",
  "set.subAutoDesc":
    "تُجلب قائمة الخوادم وحصة البيانات وتاريخ الانتهاء من اللوحة في الخلفية. وقِدَم القائمة بصمت هو أكثر أسباب توقّف العميل عن الاتصال فجأة.",
  "set.subEveryOff": "أبدًا",
  "set.subEvery3h": "كل 3 ساعات",
  "set.subEvery6h": "كل 6 ساعات",
  "set.subEvery12h": "كل 12 ساعة",
  "set.subEveryDay": "مرة يوميًا",

  "set.languageSection": "اللغة / Language",
  "set.language": "لغة الواجهة",
  "set.languageDesc":
    "«اتّباع النظام» يتتبّع لغة نظام التشغيل. أما أسطر النواة في السجل فتبقى بلغة المحرّك نفسه.",
  "set.langSystem": "اتّباع النظام",

  "set.themeSection": "المظهر",
  "set.theme": "السمة",
  "set.themeDesc":
    "«اتّباع النظام» يتتبّع إعداد نظام التشغيل ويبدّل من تلقاء نفسه، بما في ذلك جدول الفاتح والداكن.",

  "set.startupSection": "بدء التشغيل",
  "set.autostart": "التشغيل مع Windows",
  "set.autostartDesc": "يبدأ التطبيق عند تسجيل الدخول.",
  "set.autostartElevated": "التشغيل بصلاحيات المسؤول",
  "set.autostartElevatedDesc":
    "يُنشئ مهمة في «برنامج جدولة المهام» في Windows: يبدأ التطبيق بصلاحيات مرتفعة ويرفع نفق TUN فورًا — دون نافذة UAC. والتشغيل اليدوي يمرّ عبر المهمة نفسها، فلا حاجة أبدًا لإعادة التشغيل «كمسؤول».",
  "set.autostartElevatedNeedsAdmin":
    "يتطلّب إعادة تشغيل واحدة بصلاحيات المسؤول لتسجيل المهمة المجدولة.",
  "set.autostartNormalWarn":
    "البدء التلقائي العادي لا يستطيع رفع نفق TUN: سيطلب التطبيق الصلاحيات بعد تسجيل الدخول. فعّل المفتاح أعلاه لتفادي ذلك.",
  "set.autoConnect": "الاتصال عند التشغيل",
  "set.startMinimized": "البدء مصغَّرًا في شريط النظام",
  "set.closeToTray": "إغلاق النافذة يصغّرها إلى شريط النظام",
  "set.closeToTrayDesc":
    "عند الإيقاف، يُنهي زر الإغلاق التطبيق تمامًا ويقطع الاتصال.",
  "set.resourcesSection": "استهلاك الموارد",
  "set.resourcesDesc":
    "تعمل الواجهة (WebView2) والنواة كعمليات منفصلة، لذا يوزّع «مدير المهام» التطبيق على عدة أسطر. هذا مجموع عائلة العمليات كاملة، والأرقام تطابق عمود الذاكرة في «مدير المهام».",
  "set.resApp": "التطبيق",
  "set.resUi": "الواجهة (WebView2)",
  "set.resCore": "نواة sing-box",
  "set.resXray": "نواة Xray",
  "set.resTotal": "المجموع",
  "set.resProcs": "العمليات: {n}",

  "set.aboutSection": "حول",
  "set.appVersion": "إصدار التطبيق",
  "set.coreVersion": "النواة",

  // -------------------------------------------------------------- formatters
  "fmt.byteUnits": "بايت|ك.بايت|م.بايت|غ.بايت|ت.بايت",
  "fmt.perSecond": "/ث",
  "fmt.never": "أبدًا",
  "fmt.justNow": "الآن",
  "fmt.minAgo": "قبل {n} دقيقة",
  "fmt.hoursAgo": "قبل {n} ساعة",
  "fmt.daysAgo": "قبل {n} يوم",
  "fmt.dayForms": "يوم|أيام|يومًا",
  "fmt.noExpiry": "بلا انتهاء",
  "fmt.expired": "منتهية",
  "fmt.expiresToday": "تنتهي اليوم",
  "fmt.noTls": "بلا TLS",

  // --------------------------------------------------------------- dashboard
  "dash.title": "نظرة عامة",
  "dash.subtitle": "حالة النفق والسرعة ووضع التوجيه.",
  "dash.stateDisconnected": "غير متصل",
  "dash.stateConnecting": "جارٍ الاتصال",
  "dash.stateConnected": "متصل",
  "dash.stateError": "خطأ",
  "dash.modeRule": "بالقواعد",
  "dash.modeGlobal": "كل شيء عبر VPN",
  "dash.modeRuleHelp":
    "وضع الاستخدام اليومي: ما الذي يمرّ عبر VPN تقرّره صفحتا «تقسيم النفق» و«التوجيه».",
  "dash.modeGlobalHelp": "كل اتصال يمرّ عبر VPN، متجاهلًا تلك الصفحتين.",
  "dash.tunNeedsAdmin":
    "وضع TUN يحتاج صلاحيات المسؤول — وإلا فلن يتاح سوى وكيل النظام.",
  "dash.restart": "إعادة التشغيل",
  "dash.connect": "اتصال",
  "dash.disconnect": "قطع الاتصال",
  "dash.connectFailed": "تعذّر الاتصال",
  "dash.noServersTitle": "لا يوجد ما تتصل به بعد",
  "dash.noServersText":
    "أضف رابط خادم أو اشتراكًا من لوحتك — وسيظهر زر الاتصال هنا.",
  "dash.trafficDown": "التنزيل",
  "dash.trafficUp": "الرفع",
  "dash.thisSession": "هذه الجلسة",
  "dash.closeAllConns": "إغلاق كل الاتصالات النشطة",
  "dash.connsClosed": "أُغلقت الاتصالات",
  "dash.connsCloseFailed": "تعذّر إغلاق الاتصالات",
  "dash.connections": "الاتصالات",
  "dash.clickToClose": "انقر للإغلاق",
  "dash.notConnected": "غير متصل",
  "dash.testLatency": "قياس زمن الاستجابة",
  "dash.latency": "زمن الاستجابة",
  "dash.na": "غير متاح",
  "dash.pingMs": "{ping} م.ث",
  "dash.clickToTest": "انقر للقياس",
  "dash.noServer": "لم يُحدَّد خادم",

  // ------------------------------------------------------ dashboard children
  "graph.down": "تنزيل",
  "graph.up": "رفع",
  "graph.peak": "الذروة",
  "graph.aria": "مخطط السرعة",
  "pick.noServer": "لم يُحدَّد خادم",
  "pick.select": "اختيار خادم",
  "pick.testAll": "قياس الكل",
  "pick.badgeFailover": "احتياطي",
  "pick.badgeBackup": "خادم احتياطي",
  "pick.badgeFastest": "الأسرع",
  "pick.badgeRotate": "بالتناوب",

  // ------------------------------------------------------------------ servers
  "srv.title": "الخوادم",
  "srv.subtitleBefore": "الصق روابط",
  "srv.subtitleAfter": "من لوحتك — ورابط الاشتراك يصلح كذلك.",
  "srv.testLatency": "قياس زمن الاستجابة",
  "srv.subscriptionBtn": "اشتراك",
  "srv.addBtn": "إضافة",
  "srv.serverDeleted": "حُذف الخادم «{name}»",
  "srv.deleteFailed": "تعذّر حذف الخادم",
  "srv.noRawLink": "لا يملك هذا الخادم رابطًا أصليًا",
  "srv.linkCopied": "نُسخ الرابط",
  "srv.subscriptions": "الاشتراكات",
  "srv.refreshAll": "تحديث الكل",
  "srv.refreshFailed": "فشل التحديث",
  "srv.deleteSubTitle": "حذف الاشتراك وخوادمه",
  "srv.emptyTitle": "لا توجد خوادم بعد",
  "srv.emptyText":
    "انسخ رابط خادم أو اشتراك من لوحتك (في 3x-ui زر «Share» عند العميل) والصقه هنا. ويمكنك لصق عدة أسطر دفعة واحدة.",
  "srv.pasteLinks": "لصق الروابط",
  "srv.selectServer": "اختيار خادم",
  "srv.latencyNa": "غير متاح",
  "srv.latencyMs": "{ms} م.ث",
  "srv.copyLinkTitle": "نسخ الرابط",
  "srv.editTitle": "تحرير",
  "srv.deleteTitle": "حذف",
  "srv.addManually": "إضافة خادم يدويًا",
  "srv.reportAdded": "أُضيف {n}",
  "srv.reportSkipped": "تُخطّي {n} مكررًا",
  "srv.reportNothing": "لم يُضَف شيء",
  "srv.reportErrors": "بأخطاء: {n}",
  "srv.reportNoNew": "لا خوادم جديدة",
  "srv.importFailed": "فشل الاستيراد",
  "srv.addServers": "إضافة خوادم",
  "srv.cancel": "إلغاء",
  "srv.importBtn": "استيراد",
  "srv.linksLabel": "الروابط",
  "srv.linksHint":
    "رابط في كل سطر. يدعم ‎vless://‎ و‎vmess://‎ و‎trojan://‎ و‎ss://‎ و‎hysteria2://‎ و‎tuic://‎، أو كتلة اشتراك كاملة بترميز base64 — أما رابط اشتراك ‎http(s)‎ فيُضاف إلى «الاشتراكات» ويتحدّث وحده.",
  "srv.linkPlaceholder":
    "vless://uuid@server:443?type=tcp&security=reality&pbk=...#الاسم",
  "srv.subLoadFailed": "تعذّر تحميل الاشتراك",
  "srv.addSubscription": "إضافة اشتراك",
  "srv.loadBtn": "تحميل",
  "srv.nameLabel": "الاسم",
  "srv.subNameHint": "اختياري — يُؤخذ من العنوان افتراضيًا.",
  "srv.subNamePlaceholder": "خادمي",
  "srv.subUrlLabel": "رابط الاشتراك",
  "srv.subUrlHint":
    "في 3x-ui مثلًا هو رابط Subscription URL في إعدادات العميل.",
  "srv.serverNotAdded": "لم يُضَف الخادم",
  "srv.duplicateServer": "هذا الخادم موجود في القائمة أصلًا",
  "srv.serverAdded": "أُضيف الخادم",
  "srv.serverSaved": "حُفظ الخادم",
  "srv.saveFailed": "تعذّر الحفظ",
  "srv.newServer": "خادم جديد",
  "srv.serverParams": "إعدادات الخادم",
  "srv.saveBtn": "حفظ",
  "srv.protocolLabel": "البروتوكول",
  "srv.addressLabel": "العنوان",
  "srv.portLabel": "المنفذ",
  "srv.passwordLabel": "كلمة المرور",
  "srv.encryptionLabel": "التشفير",
  "srv.transportLabel": "النقل",
  "srv.channelEncryptionLabel": "تشفير القناة",
  "srv.noTls": "بلا TLS",
  "srv.tlsFingerprintLabel": "بصمة TLS (fp)",
  "srv.flowHint": "عادةً xtls-rprx-vision أو فارغ.",
  "srv.skipCertLabel": "عدم التحقق من الشهادة",
  "srv.skipCertDesc":
    "لا يلزم إلا مع شهادة موقّعة ذاتيًا على الخادم. يبقى الاتصال مشفّرًا، لكن لا يمكن كشف شهادة مستبدلة.",
  "srv.muxLabel": "التعددية (mux)",
  "srv.muxDesc":
    "عدة طلبات في اتصال واحد. يسرّع تحميل الصفحات، لكنه لا يتوافق مع XTLS Vision ويعيق التورنت.",
  "srv.subRefreshFailed": "تعذّر تحديث «{name}»",
  "srv.refreshNow": "تحديث الآن",
  "srv.remaining": "المتبقي",
  "srv.trafficLabel": "البيانات",
  "srv.expiredWarning":
    "انتهت صلاحية الاشتراك — والخوادم على الأرجح لم تعد تستجيب.",
  "srv.exhaustedWarning": "نفدت حصة البيانات — جدّد باقتك من اللوحة.",
  "srv.noUsageInfo": "لا تُبلغ اللوحة عن حصة البيانات ولا عن تاريخ الانتهاء",
  "srv.serverOne": "خادم",
  "srv.serverFew": "خوادم",
  "srv.serverMany": "خادمًا",
  "srv.updatedWhen": "حُدّث {when}",

  // ------------------------------------------------------------ split tunnel
  "split.title": "تقسيم النفق",
  "split.subtitle":
    "قواعد لتطبيقات بعينها. مسار التطبيق واستعلامات DNS الخاصة به يسلكان الطريق نفسه دائمًا، فلا يتسرّب العنوان خارج النفق.",
  "split.modeOffHelp": "كل حركة النظام تمرّ عبر VPN.",
  "split.modeIncludeHelp":
    "التطبيقات المحددة وحدها تمرّ عبر VPN. وكل ما عداها يتصل مباشرة متجاوزًا النفق.",
  "split.modeExcludeHelp":
    "التطبيقات المحددة تتجاوز VPN وتتصل مباشرة. وبقية الحركة تمرّ عبر النفق.",
  "split.exeDialogTitle": "اختيار برنامج",
  "split.exeDialogFilter": "البرامج",
  "split.alreadyInList": "هذا البرنامج في القائمة أصلًا",
  "split.tunOnlyTitle": "يعمل في وضع TUN فقط",
  "split.tunOnlyText":
    "وضع وكيل النظام مفعّل حاليًا. ولا يمكن معرفة صاحب الاتصال من التطبيقات إلا حين تمرّ الحركة عبر المحوّل الافتراضي — بدّل الوضع من الإعدادات.",
  "split.mode": "الوضع",
  "split.modeOff": "إيقاف",
  "split.modeInclude": "المحددة فقط",
  "split.modeExclude": "الكل ما عدا المحددة",
  "split.appsCount": "التطبيقات ({count})",
  "split.addFromRunning": "من التطبيقات العاملة",
  "split.pickExe": "اختيار ملف ‎.exe‎",
  "split.clearList": "إفراغ القائمة",
  "split.emptyTitle": "القائمة فارغة",
  "split.emptyText":
    "أضف تطبيقات — مثلًا تطبيق البنك وSteam خارج VPN، أو المتصفح وحده عبر VPN.",
  "split.matchByName": "المطابقة باسم العملية",
  "split.procsFailed": "تعذّر جلب قائمة العمليات",
  "split.runningApps": "التطبيقات العاملة",
  "split.cancel": "إلغاء",
  "split.addCount": "إضافة ({count})",
  "split.searchPlaceholder": "بحث بالاسم أو المسار",
  "split.refresh": "تحديث",
  "split.showSystemProcs": "إظهار عمليات نظام Windows",
  "split.loading": "جارٍ التحميل…",
  "split.nothingFound": "لم يُعثر على شيء",
  "split.instancesCount": "{count} عملية",
  "split.alreadyAdded": "مضاف سلفًا",
  "split.selectedChip": "محدَّد",

  // ------------------------------------------------------------------ routing
  "route.title": "التوجيه",
  "route.subtitle":
    "تُطبَّق القواعد من الأعلى إلى الأسفل، وأول تطابق يفوز: الحجب ← الشبكة المحلية ← قوائمك ← القواعد الجغرافية ← قواعد التطبيقات.",
  "route.showConfig": "عرض الإعداد",
  "route.buildFailed": "تعذّر بناء الإعداد",
  "route.presets": "الإعدادات الجاهزة",
  "route.bypassLan": "عدم المساس بالشبكة المحلية",
  "route.bypassLanDesc":
    "الموجّه والطابعات وأجهزة NAS و‎localhost‎ تتصل مباشرة. لا توقفه إلا عن قصد — وإلا فستتعذّر أجهزة شبكتك المنزلية.",
  "route.bypassRu": "المواقع الروسية تتجاوز VPN",
  "route.bypassRuDesc":
    "النطاقات والعناوين من قائمتي geosite/geoip‏ ru تتصل مباشرة. يسرّع الوصول إلى الخدمات المحلية ويقلّل اختبارات التحقق.",
  "route.bypassCn": "المواقع الصينية تتجاوز VPN",
  "route.bypassCnDesc": "المِثل لقائمتي geosite/geoip‏ cn.",
  "route.blockAds": "حجب الإعلانات والمتعقّبات",
  "route.blockAdsDesc":
    "تُرفض الطلبات إلى نطاقات قائمة category-ads-all على مستوى النواة وDNS معًا.",
  "route.customRules": "قواعدك الخاصة",
  "route.directDomains": "مباشر دائمًا — النطاقات",
  "route.directDomainsHint":
    "نطاق في كل سطر. المطابقة باللاحقة: ‎example.com‎ يشمل كذلك ‎sub.example.com‎.",
  "route.proxyDomains": "عبر VPN دائمًا — النطاقات",
  "route.proxyDomainsHint":
    "لها أولوية على القواعد الجغرافية، لكنها تتنازل لقائمة «مباشر دائمًا».",
  "route.directIps": "مباشر دائمًا — العناوين",
  "route.directIpsHint": "‏IP أو CIDR، مثل 10.0.0.0/8.",
  "route.proxyIps": "عبر VPN دائمًا — العناوين",
  "route.proxyIpsHint": "‏IP أو CIDR.",
  "route.blockDomains": "حجب النطاقات",
  "route.blockDomainsHint": "تُرفض الاتصالات ولا يُعاد أي ردّ من DNS.",
  "route.configTitle": "إعداد sing-box المُولَّد",
  "route.copied": "نُسخ",
  "route.copy": "نسخ",
  "route.close": "إغلاق",

  // --------------------------------------------------------------------- logs
  "logs.title": "سجل النواة",
  "logs.subtitle":
    "مخرجات sing-box لحظة بلحظة. انظر هنا إذا ظلّ الاتصال ينقطع.",
  "logs.filterAll": "الكل",
  "logs.filterInfo": "معلومات",
  "logs.filterWarn": "تحذير",
  "logs.filterErrors": "أخطاء",
  "logs.copyAll": "نسخ الكل",
  "logs.copied": "نُسخ السجل",
  "logs.clear": "مسح",
  "logs.empty": "السجل فارغ — ستظهر الأسطر بعد الاتصال.",
  "logs.toLatest": "إلى أحدث الأسطر",

  // ------------------------------------------------------------ elevate modal
  "elev.title": "مطلوب صلاحيات المسؤول",
  "elev.relaunchFailed": "فشلت إعادة التشغيل",
  "elev.cancel": "إلغاء",
  "elev.restart": "إعادة التشغيل",
  "elev.tunnelWhy":
    "وضع TUN يعترض حركة النظام كلها عبر محوّل Wintun الافتراضي. وإنشاؤه يتطلّب صلاحيات المسؤول — وسيعرض Windows نافذة UAC.",
  "elev.tunnelAlt":
    "إن لم ترغب في رفع الصلاحيات، بدّل إلى وضع وكيل النظام من الإعدادات: يعمل دون UAC لكنه لا يغطي إلا التطبيقات التي تحترم إعدادات وكيل النظام.",
  "elev.autostartWhy":
    "البدء التلقائي بصلاحيات المسؤول يُنشئ مهمة في «برنامج جدولة المهام» في Windows — ولا يقدر عنصر بدء تشغيل عادي على ذلك، فالنظام لا يرفع الصلاحيات دون تأكيد.",
  "elev.autostartOnce":
    "الصلاحيات مطلوبة مرة واحدة فقط لتسجيل المهمة. وبعدها يبدأ التطبيق بصلاحيات المسؤول من تلقاء نفسه، دون نافذة UAC عند كل تسجيل دخول.",
} as const;
