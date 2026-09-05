/** Reference dictionary. Every key the UI uses must exist here; the English
 * dictionary is type-checked against this one. */
export const ru = {
  // ------------------------------------------------------------------ shell
  "app.loading": "Загрузка…",
  "app.loadFailed": "Не удалось запустить приложение",

  "nav.dashboard": "Обзор",
  "nav.servers": "Серверы",
  "nav.split": "Раздельный туннель",
  "nav.routing": "Маршрутизация",
  "nav.logs": "Журнал",
  "nav.settings": "Настройки",

  "bar.systemProxy": "Системный прокси",
  "bar.connecting": "подключение…",
  "bar.disconnected": "отключено",

  "side.update": "Обновление",
  "side.downloading": "Загрузка…",
  "side.installing": "Установка…",
  "side.installVersion": "Установить версию {version}",
  "side.updateFailed": "Не удалось установить обновление",
  "side.noCore": "ядро не найдено",
  "side.admin": "права администратора",
  "side.user": "обычные права",
  "side.admin.unix": "права root",
  "side.admin.mac": "ядро с правами root",
  "side.appVersion": "установленная версия приложения",

  // ------------------------------------------------------------------ toasts
  "toast.backendTimeout": "{label}: бэкенд не ответил за {s} с",
  "toast.disconnectFailed": "Не удалось отключиться",
  "toast.settingsFailed": "Настройки не применены",
  "toast.rulesFailed": "Правила не применены",
  "toast.serverSwitchFailed": "Не удалось сменить сервер",
  "toast.modeSwitchFailed": "Не удалось сменить режим",
  "toast.latencyFailed": "Проверка задержки не удалась",
  "toast.reloadFailed": "Не удалось обновить состояние",
  "toast.balancerOff": "Автовыбор выключен: сервер выбран вручную",

  // ------------------------------------------------------------------ themes
  "theme.dark": "Аврора",
  "theme.midnight": "Полночь",
  "theme.crimson": "Багровая",
  "theme.emerald": "Изумруд",
  "theme.swamp": "Болотная",
  "theme.light": "Светлая",
  "theme.system": "Как в системе",

  // ---------------------------------------------------------------- settings
  "set.title": "Настройки",
  "set.subtitle":
    "Изменения применяются сразу; при активном подключении ядро перезапускается автоматически.",
  "set.dataFolder": "Папка данных",
  "set.tabCore": "Ядро",
  "set.tabClient": "Клиент",
  "set.autostartFailed": "Не удалось изменить автозапуск",

  "set.tunnelSection": "Туннель",
  "set.tunnelMode": "Режим работы",
  "set.tunnelModeTunDesc":
    "TUN — виртуальный адаптер Wintun перехватывает трафик всей системы. Нужны права администратора, зато работают правила по приложениям.",
  "set.tunnelModeTunDesc.unix":
    "TUN — виртуальный сетевой интерфейс перехватывает трафик всей системы. Нужны права root (запуск через sudo), зато работают правила по приложениям.",
  "set.tunnelModeTunDesc.mac":
    "TUN — виртуальный сетевой интерфейс перехватывает трафик всей системы. Ядру нужны права root — они выдаются один раз по паролю администратора, — зато работают правила по приложениям.",
  "set.tunnelModeProxyDesc":
    "Системный прокси — без прав администратора, но охватывает только приложения, которые читают системные настройки прокси.",
  "set.tunnelModeProxyDesc.unix":
    "Системный прокси — пока реализован только для Windows; на macOS и Linux используйте TUN.",
  "set.systemProxy": "Системный прокси",
  "set.tunNeedsAdmin":
    "Приложение запущено без прав администратора — подключение в режиме TUN предложит перезапуск.",
  "set.tunNeedsAdmin.unix":
    "Приложение запущено без прав root, поэтому режим TUN недоступен. Запустите его из терминала:",
  "set.tunNeedsAdmin.mac":
    "Ядру ещё не выданы права root, поэтому режим TUN недоступен. macOS спросит пароль администратора один раз; другой способ — запустить приложение из терминала:",

  "set.tunSection": "Параметры TUN",
  "set.tunStack": "Сетевой стек",
  "set.tunStackHint":
    "mixed — gVisor для TCP и системный для UDP: лучший баланс скорости и совместимости.",
  "set.tunStackMixed": "mixed (рекомендуется)",
  "set.mtuHint": "По умолчанию 9000.",
  "set.strictRoute": "Строгая маршрутизация",
  "set.strictRouteDesc":
    "Блокирует попытки трафика уйти в обход туннеля. Отключите, если перестают работать VirtualBox/WSL или сетевые игры.",
  "set.ipv6": "Поддержка IPv6",
  "set.ipv6Desc":
    "Выключено — DNS отдаёт только A-записи. Включайте, если провайдер и сервер действительно поддерживают IPv6.",
  "set.fakeIpDesc":
    "Ускоряет открытие сайтов: домен резолвится мгновенно, а настоящий адрес узнаёт уже сервер. Может мешать некоторым локальным сервисам.",

  "set.dnsRemote": "DNS через VPN",
  "set.dnsRemoteHint":
    "Используется для доменов, идущих в туннель. Можно указать tls:// или https://.",
  "set.dnsDirect": "DNS напрямую",
  "set.dnsDirectHint":
    "Для доменов в обход туннеля и для резолва адреса самого сервера.",

  "set.connSection": "Подключение",
  "set.mixedPort": "Порт SOCKS/HTTP",
  "set.mixedPortHint": "Локальный смешанный прокси.",
  "set.clashPort": "Порт панели управления ядром",
  "set.clashPortHint": "Clash API на 127.0.0.1.",
  "set.latencyUrl": "URL для проверки задержки",
  "set.latencyUrlHint": "Запрос уходит через выбранный сервер.",
  "set.logLevel": "Уровень журнала",
  "set.allowLan": "Доступ из локальной сети",
  "set.allowLanDesc":
    "Прокси слушает 0.0.0.0 — другие устройства в сети смогут им пользоваться. Включайте только в доверенной сети.",
  "set.balancer": "Выбор сервера",
  "set.balancerManual": "Вручную",
  "set.balancerFailover": "С резервом",
  "set.balancerFastest": "Самый быстрый",
  "set.balancerRotate": "По кругу",
  "set.balancerManualDesc":
    "Работает сервер, который вы выбрали. Само ничего не переключается.",
  "set.balancerFailoverDesc":
    "Выбранный сервер — основной. Перестал отвечать — переход на лучший из живых; когда основной вернётся и продержится, трафик вернётся на него. Живые соединения при этом не рвутся.",
  "set.balancerFastestDesc":
    "Все серверы проверяются по расписанию. Переход — только на тот, что быстрее нынешнего на заданный порог два обхода подряд: между серверами с одинаковой задержкой скакать не будет.",
  "set.balancerRotateDesc":
    "Каждый обход — следующий живой сервер по списку; упавшие пропускаются.",
  "set.balancerInterval": "Обход серверов",
  "set.balancerIntervalHint":
    "Как часто проверять все серверы. Текущий проверяется чаще — каждые 20 секунд.",
  "set.balancerTolerance": "Порог переключения",
  "set.balancerToleranceHint": "Другой сервер должен быть быстрее хотя бы на столько.",
  "set.everyMin": "каждые {n} мин",

  "set.subsSection": "Подписки",
  "set.subAuto": "Обновлять автоматически",
  "set.subAutoDesc":
    "Список серверов, остаток трафика и срок действия подтягиваются с панели в фоне. Устаревший список — самая частая причина, по которой клиент внезапно перестаёт подключаться.",
  "set.subEveryOff": "Не обновлять",
  "set.subEvery3h": "каждые 3 часа",
  "set.subEvery6h": "каждые 6 часов",
  "set.subEvery12h": "каждые 12 часов",
  "set.subEveryDay": "раз в сутки",

  "set.languageSection": "Язык / Language",
  "set.language": "Язык интерфейса",
  "set.languageDesc":
    "«Как в системе» следует за языком операционной системы. Тексты ядра в журнале остаются на языке движка.",
  "set.langSystem": "Как в системе",

  "set.themeSection": "Внешний вид",
  "set.theme": "Тема оформления",
  "set.themeDesc":
    "«Как в системе» следует за настройкой системы и переключается сама, в том числе по её расписанию светлой и тёмной темы.",

  "set.startupSection": "Запуск",
  "set.autostart": "Запускать вместе с {os}",
  "set.autostartDesc": "Приложение стартует при входе в систему.",
  "set.autostartElevated": "Запускать сразу с правами администратора",
  "set.autostartElevatedDesc":
    "Создаст задачу в планировщике Windows: приложение будет стартовать с правами администратора и сразу поднимать TUN — без запроса UAC. Ручной запуск ярлыком тоже пойдёт через неё, поэтому перезапуск «от администратора» больше не понадобится.",
  "set.autostartElevatedNeedsAdmin":
    "Требуется однократный перезапуск с правами администратора, чтобы зарегистрировать задачу в планировщике.",
  "set.autostartNormalWarn":
    "Обычная автозагрузка не может поднять режим TUN: после входа в систему приложение запросит права. Включите переключатель выше, чтобы этого не происходило.",
  "set.autostartNormalWarn.unix":
    "Автозагрузка стартует приложение без прав root, поэтому режим TUN при входе в систему сам не поднимется — понадобится перезапуск через sudo.",
  "set.autostartNormalWarn.mac":
    "Пока ядру не выданы права root, режим TUN при входе в систему сам не поднимется.",
  "set.autoConnect": "Подключаться при запуске",
  "set.startMinimized": "Запускать свёрнутым в трей",
  "set.startMinimized.mac": "Запускать свёрнутым в строку меню",
  "set.closeToTray": "Закрытие окна сворачивает в трей",
  "set.closeToTray.mac": "Закрытие окна сворачивает в строку меню",
  "set.closeToTrayDesc":
    "Выключено — крестик полностью завершает работу и разрывает соединение.",
  "set.resourcesSection": "Потребление ресурсов",
  "set.resourcesDesc":
    "Интерфейс (WebView2) и ядро работают отдельными процессами, поэтому в диспетчере задач приложение разбросано по нескольким строкам. Здесь — вся семья процессов вместе; цифры соответствуют колонке «Память» диспетчера задач.",
  "set.resourcesDesc.mac":
    "Ядро работает отдельным процессом, поэтому в Мониторинге системы приложение занимает несколько строк. Здесь — вся семья процессов вместе.",
  "set.resourcesDesc.linux":
    "Интерфейс (WebKitGTK) и ядро работают отдельными процессами, поэтому в системном мониторе приложение разбросано по нескольким строкам. Здесь — вся семья процессов вместе.",
  "set.resApp": "Приложение",
  "set.resUi": "Интерфейс ({engine})",
  "set.resCore": "Ядро sing-box",
  "set.resXray": "Ядро Xray",
  "set.resTotal": "Всего",
  "set.resProcs": "процессов: {n}",

  "set.aboutSection": "О приложении",
  "set.appVersion": "Версия приложения",
  "set.coreVersion": "Ядро",

  // -------------------------------------------------------------- formatters
  "fmt.byteUnits": "Б|КБ|МБ|ГБ|ТБ",
  "fmt.perSecond": "/с",
  "fmt.never": "никогда",
  "fmt.justNow": "только что",
  "fmt.minAgo": "{n} мин назад",
  "fmt.hoursAgo": "{n} ч назад",
  "fmt.daysAgo": "{n} дн назад",
  "fmt.dayForms": "день|дня|дней",
  "fmt.noExpiry": "бессрочно",
  "fmt.expired": "истекла",
  "fmt.expiresToday": "истекает сегодня",
  "fmt.noTls": "без TLS",

  // --------------------------------------------------------------- dashboard
  "dash.title": "Обзор",
  "dash.subtitle": "Состояние туннеля, скорость и режим маршрутизации.",
  "dash.stateDisconnected": "Отключено",
  "dash.stateConnecting": "Подключение",
  "dash.stateConnected": "Подключено",
  "dash.stateError": "Ошибка",
  "dash.modeRule": "По правилам",
  "dash.modeGlobal": "Всё через VPN",
  "dash.modeRuleHelp":
    "Обычный режим: что идёт через VPN, решают страницы «Раздельный туннель» и «Маршрутизация».",
  "dash.modeGlobalHelp": "Через VPN идёт всё подряд, эти страницы не учитываются.",
  "dash.tunNeedsAdmin":
    "Режим TUN требует прав администратора — иначе доступен только системный прокси.",
  "dash.tunNeedsAdmin.unix":
    "Режим TUN требует прав root — запустите приложение через sudo.",
  "dash.tunNeedsAdmin.mac":
    "Режим TUN требует прав root — выдайте их ядру, macOS спросит пароль один раз.",
  "dash.restart": "Перезапустить",
  "dash.showCommand": "Показать команду",
  "dash.connect": "Подключить",
  "dash.disconnect": "Отключить",
  "dash.connectFailed": "Не удалось подключиться",
  "dash.noServersTitle": "Подключаться пока не к чему",
  "dash.noServersText":
    "Добавьте ссылку сервера или подписку из вашей панели — и на этом месте появится кнопка подключения.",
  "dash.trafficDown": "Приём",
  "dash.trafficUp": "Отдача",
  "dash.thisSession": "За сессию",
  "dash.closeAllConns": "Разорвать все активные соединения",
  "dash.connsClosed": "Соединения разорваны",
  "dash.connsCloseFailed": "Не удалось разорвать соединения",
  "dash.connections": "Соединений",
  "dash.clickToClose": "нажмите, чтобы разорвать",
  "dash.notConnected": "нет подключения",
  "dash.testLatency": "Проверить задержку",
  "dash.latency": "Задержка",
  "dash.na": "н/д",
  "dash.pingMs": "{ping} мс",
  "dash.clickToTest": "нажмите, чтобы измерить",
  "dash.noServer": "сервер не выбран",
  "dash.stateUnreachable": "Сервер не отвечает",
  "dash.stateReconnecting": "Переподключение…",
  "dash.unreachableHint":
    "Проверки через «{name}» не проходят, трафик не идёт. Проверьте интернет, выберите другой сервер или включите «С резервом».",
  "dash.unreachableAuto":
    "Проверки через сервер не проходят, трафик не идёт. Балансировщик переключит трафик, как только найдёт живой сервер.",

  // ------------------------------------------------------ dashboard children
  "graph.down": "приём",
  "graph.up": "отдача",
  "graph.peak": "пик",
  "graph.aria": "График скорости",
  "pick.noServer": "Сервер не выбран",
  "pick.select": "Выбрать сервер",
  "pick.testAll": "Проверить все",
  "pick.balancers": "Балансировщики",
  "pick.servers": "Серверы",
  "pick.badgeBackup": "резервный сервер",
  "pick.now": "сейчас: {name}",
  "pick.nowChip": "сейчас",
  "pick.primary": "основной: {name}",
  "pick.primaryDown": "основной не отвечает",
  "pick.failoverMeta": "основной и замена на время его молчания",
  "pick.fastestMeta": "по задержке, без метаний между равными",
  "pick.rotateMeta": "следующий живой сервер каждый обход",

  // ------------------------------------------------------------------ servers
  "srv.title": "Серверы",
  "srv.subtitleBefore": "Вставьте ссылки",
  "srv.subtitleAfter": "из вашей панели — ссылка подписки тоже подойдёт.",
  "srv.testLatency": "Проверить задержку",
  "srv.subscriptionBtn": "Подписка",
  "srv.addBtn": "Добавить",
  "srv.serverDeleted": "Сервер «{name}» удалён",
  "srv.deleteFailed": "Не удалось удалить сервер",
  "srv.noRawLink": "У этого сервера нет исходной ссылки",
  "srv.linkCopied": "Ссылка скопирована",
  "srv.subscriptions": "Подписки",
  "srv.refreshAll": "Обновить все",
  "srv.refreshFailed": "Обновление не удалось",
  "srv.deleteSubTitle": "Удалить подписку и её серверы",
  "srv.emptyTitle": "Пока нет серверов",
  "srv.emptyText":
    "Скопируйте ссылку сервера или подписки из вашей панели (например, в 3x-ui — кнопка «Поделиться» у клиента) и вставьте её сюда. Можно вставить сразу несколько строк.",
  "srv.pasteLinks": "Вставить ссылки",
  "srv.selectServer": "Выбрать сервер",
  "srv.latencyNa": "н/д",
  "srv.latencyMs": "{ms} мс",
  "srv.copyLinkTitle": "Скопировать ссылку",
  "srv.editTitle": "Изменить",
  "srv.deleteTitle": "Удалить",
  "srv.addManually": "Добавить сервер вручную",
  "srv.reportAdded": "добавлено {n}",
  "srv.reportSkipped": "пропущено дубликатов {n}",
  "srv.reportNothing": "ничего не добавлено",
  "srv.reportErrors": "с ошибками: {n}",
  "srv.reportNoNew": "Новых серверов нет",
  "srv.importFailed": "Импорт не удался",
  "srv.addServers": "Добавить серверы",
  "srv.cancel": "Отмена",
  "srv.importBtn": "Импортировать",
  "srv.linksLabel": "Ссылки",
  "srv.linksHint":
    "По одной на строку. Поддерживаются vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, base64-блок подписки целиком — а http(s)-ссылка на подписку добавится в «Подписки» и будет обновляться сама.",
  "srv.linkPlaceholder":
    "vless://uuid@server:443?type=tcp&security=reality&pbk=...#Название",
  "srv.subLoadFailed": "Не удалось загрузить подписку",
  "srv.addSubscription": "Добавить подписку",
  "srv.loadBtn": "Загрузить",
  "srv.nameLabel": "Название",
  "srv.subNameHint": "Необязательно — по умолчанию берётся из адреса.",
  "srv.subNamePlaceholder": "Мой сервер",
  "srv.subUrlLabel": "Адрес подписки",
  "srv.subUrlHint":
    "Например, в 3x-ui это ссылка Subscription URL из настроек клиента.",
  "srv.serverNotAdded": "Сервер не добавлен",
  "srv.duplicateServer": "такой сервер уже есть в списке",
  "srv.serverAdded": "Сервер добавлен",
  "srv.serverSaved": "Сервер сохранён",
  "srv.saveFailed": "Не удалось сохранить",
  "srv.newServer": "Новый сервер",
  "srv.serverParams": "Параметры сервера",
  "srv.saveBtn": "Сохранить",
  "srv.protocolLabel": "Протокол",
  "srv.addressLabel": "Адрес",
  "srv.portLabel": "Порт",
  "srv.passwordLabel": "Пароль",
  "srv.encryptionLabel": "Шифрование",
  "srv.transportLabel": "Транспорт",
  "srv.channelEncryptionLabel": "Шифрование канала",
  "srv.noTls": "без TLS",
  "srv.tlsFingerprintLabel": "Отпечаток TLS (fp)",
  "srv.flowHint": "Обычно xtls-rprx-vision либо пусто.",
  "srv.skipCertLabel": "Не проверять сертификат",
  "srv.skipCertDesc":
    "Нужно только для самоподписанного сертификата на сервере. Соединение остаётся зашифрованным, но подмену сертификата отследить нельзя.",
  "srv.muxLabel": "Мультиплексирование (mux)",
  "srv.muxDesc":
    "Несколько запросов в одном соединении. Ускоряет открытие страниц, но несовместимо с XTLS Vision и мешает торрентам.",
  "srv.subRefreshFailed": "Не удалось обновить «{name}»",
  "srv.refreshNow": "Обновить сейчас",
  "srv.remaining": "Осталось",
  "srv.trafficLabel": "Трафик",
  "srv.expiredWarning":
    "Срок действия истёк — серверы, скорее всего, уже не отвечают.",
  "srv.exhaustedWarning": "Трафик исчерпан — продлите тариф в панели.",
  "srv.noUsageInfo": "Панель не сообщает лимиты и срок действия",
  "srv.serverOne": "сервер",
  "srv.serverFew": "сервера",
  "srv.serverMany": "серверов",
  "srv.updatedWhen": "обновлено {when}",

  // ------------------------------------------------------------ split tunnel
  "split.title": "Раздельный туннель",
  "split.subtitle":
    "Правила по конкретным приложениям. Маршрут и DNS-запросы программы всегда идут одним путём — так адрес не утекает мимо туннеля.",
  "split.modeOffHelp": "Весь трафик системы идёт через VPN.",
  "split.modeIncludeHelp":
    "Через VPN пойдут только выбранные приложения. Все остальные — напрямую, минуя туннель.",
  "split.modeExcludeHelp":
    "Выбранные приложения пойдут напрямую, минуя VPN. Весь остальной трафик — через туннель.",
  "split.exeDialogTitle": "Выберите программу",
  "split.exeDialogFilter": "Программы",
  "split.alreadyInList": "Эта программа уже в списке",
  "split.tunOnlyTitle": "Работает только в режиме TUN",
  "split.tunOnlyText":
    "Сейчас включён режим системного прокси. Определить, какому приложению принадлежит соединение, можно только когда трафик проходит через виртуальный адаптер — переключите режим в настройках.",
  "split.mode": "Режим",
  "split.modeOff": "Выключен",
  "split.modeInclude": "Только выбранные",
  "split.modeExclude": "Кроме выбранных",
  "split.appsCount": "Приложения ({count})",
  "split.addFromRunning": "Из запущенных",
  "split.pickExe": "Выбрать .exe",
  "split.clearList": "Очистить список",
  "split.emptyTitle": "Список пуст",
  "split.emptyText":
    "Добавьте приложения — например, банковский клиент и Steam мимо VPN, либо только браузер через VPN.",
  "split.matchByName": "совпадение по имени процесса",
  "split.procsFailed": "Не удалось получить список процессов",
  "split.runningApps": "Запущенные приложения",
  "split.cancel": "Отмена",
  "split.addCount": "Добавить ({count})",
  "split.searchPlaceholder": "Поиск по имени или пути",
  "split.refresh": "Обновить",
  "split.showSystemProcs": "Показывать системные процессы {os}",
  "split.loading": "Загрузка…",
  "split.nothingFound": "Ничего не найдено",
  "split.instancesCount": "{count} проц.",
  "split.alreadyAdded": "уже добавлено",
  "split.selectedChip": "выбрано",

  // ------------------------------------------------------------------ routing
  "route.title": "Маршрутизация",
  "route.subtitle":
    "Правила применяются сверху вниз, побеждает первое совпадение: блокировки → локальная сеть → ваши списки → гео-правила → правила по приложениям.",
  "route.showConfig": "Показать конфиг",
  "route.buildFailed": "Не удалось собрать конфигурацию",
  "route.presets": "Готовые наборы",
  "route.bypassLan": "Не трогать локальную сеть",
  "route.bypassLanDesc":
    "Роутер, принтеры, NAS и localhost идут напрямую. Отключать стоит только осознанно — иначе перестанут открываться устройства в домашней сети.",
  "route.bypassRu": "Российские сайты — мимо VPN",
  "route.bypassRuDesc":
    "Домены и адреса из списка geosite/geoip ru идут напрямую. Ускоряет доступ к локальным сервисам и снимает капчи.",
  "route.bypassCn": "Китайские сайты — мимо VPN",
  "route.bypassCnDesc": "То же самое для списка geosite/geoip cn.",
  "route.blockAds": "Блокировать рекламу и трекеры",
  "route.blockAdsDesc":
    "Запросы к доменам из списка category-ads-all отклоняются на уровне ядра и DNS.",
  "route.customRules": "Свои правила",
  "route.directDomains": "Всегда напрямую — домены",
  "route.directDomainsHint":
    "По одному на строку. Совпадение по суффиксу: example.com покроет и sub.example.com.",
  "route.proxyDomains": "Всегда через VPN — домены",
  "route.proxyDomainsHint":
    "Имеет приоритет над гео-правилами, но уступает списку «всегда напрямую».",
  "route.directIps": "Всегда напрямую — адреса",
  "route.directIpsHint": "IP или CIDR, например 10.0.0.0/8.",
  "route.proxyIps": "Всегда через VPN — адреса",
  "route.proxyIpsHint": "IP или CIDR.",
  "route.blockDomains": "Блокировать домены",
  "route.blockDomainsHint": "Соединения отклоняются, DNS-ответ не выдаётся.",
  "route.configTitle": "Сгенерированная конфигурация sing-box",
  "route.copied": "Скопировано",
  "route.copy": "Скопировать",
  "route.close": "Закрыть",

  // --------------------------------------------------------------------- logs
  "logs.title": "Журнал ядра",
  "logs.subtitle":
    "Вывод sing-box в реальном времени. Сюда стоит смотреть, если подключение обрывается.",
  "logs.filterAll": "Все",
  "logs.filterInfo": "Инфо",
  "logs.filterWarn": "Предупр.",
  "logs.filterErrors": "Ошибки",
  "logs.copyAll": "Скопировать всё",
  "logs.copied": "Журнал скопирован",
  "logs.clear": "Очистить",
  "logs.empty": "Журнал пуст — записи появятся после подключения.",
  "logs.toLatest": "К последним записям",

  // ------------------------------------------------------------ elevate modal
  "elev.title": "Требуются права администратора",
  "elev.title.unix": "Нужны права root",
  "elev.relaunchFailed": "Перезапуск не удался",
  "elev.cancel": "Отмена",
  "elev.restart": "Перезапустить",
  "elev.copy": "Скопировать команду",
  "elev.copied": "Команда скопирована",
  "elev.copyFailed":
    "Не удалось скопировать — выделите команду и скопируйте её вручную.",
  "elev.close": "Закрыть",
  "elev.altTerminal": "Другой способ — запустить приложение из терминала:",
  "elev.grant": "Выдать права",
  "elev.granted": "Ядру выданы права root",
  "elev.grantFailed": "Не удалось выдать права",
  "elev.tunnelWhy":
    "Режим TUN перехватывает трафик всей системы через виртуальный адаптер Wintun. Его создание требует прав администратора — Windows покажет запрос UAC.",
  "elev.tunnelWhy.unix":
    "Режим TUN перехватывает трафик всей системы через виртуальный сетевой интерфейс, а создать его может только root. Повысить права на ходу {os} не даёт — запустите приложение из терминала:",
  "elev.tunnelWhy.mac":
    "Режим TUN создаёт виртуальный сетевой интерфейс, а это может только root. macOS запросит пароль администратора один раз: ядро sing-box получит право запускаться от root, само приложение останется обычным. После обновления или переустановки запрос повторится.",
  "elev.tunnelAlt":
    "Если повышать права не нужно, переключитесь на режим системного прокси в настройках: он работает без UAC, но охватывает только те приложения, которые уважают системные настройки прокси.",
  "elev.autostartWhy":
    "Автозапуск с правами администратора создаёт задачу в планировщике Windows — обычная запись в автозагрузке так не умеет, система не даёт повышать права без подтверждения.",
  "elev.autostartOnce":
    "Права нужны только один раз, чтобы зарегистрировать задачу. После этого приложение будет стартовать с правами администратора само, без запроса UAC при каждом входе в систему.",
} as const;
