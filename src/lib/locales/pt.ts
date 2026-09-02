import type { ru } from "./ru";

export const pt: Record<keyof typeof ru, string> = {
  // ------------------------------------------------------------------ shell
  "app.loading": "Carregando…",
  "app.loadFailed": "O aplicativo não conseguiu iniciar",

  "nav.dashboard": "Visão geral",
  "nav.servers": "Servidores",
  "nav.split": "Túnel dividido",
  "nav.routing": "Roteamento",
  "nav.logs": "Log",
  "nav.settings": "Configurações",

  "bar.systemProxy": "Proxy do sistema",
  "bar.connecting": "conectando…",
  "bar.disconnected": "desconectado",

  "side.update": "Atualizar",
  "side.downloading": "Baixando…",
  "side.installing": "Instalando…",
  "side.installVersion": "Instalar a versão {version}",
  "side.updateFailed": "Falha ao instalar a atualização",
  "side.noCore": "núcleo não encontrado",
  "side.admin": "direitos de administrador",
  "side.user": "direitos comuns",
  "side.appVersion": "versão instalada do aplicativo",

  // ------------------------------------------------------------------ toasts
  "toast.backendTimeout": "{label}: o backend não respondeu em {s} s",
  "toast.disconnectFailed": "Falha ao desconectar",
  "toast.settingsFailed": "As configurações não foram aplicadas",
  "toast.rulesFailed": "As regras não foram aplicadas",
  "toast.serverSwitchFailed": "Falha ao trocar de servidor",
  "toast.modeSwitchFailed": "Falha ao trocar de modo",
  "toast.latencyFailed": "O teste de latência falhou",
  "toast.reloadFailed": "Falha ao atualizar o estado",
  "toast.balancerOff": "Seleção automática desligada: servidor escolhido à mão",

  // ------------------------------------------------------------------ themes
  "theme.dark": "Aurora",
  "theme.midnight": "Meia-noite",
  "theme.crimson": "Carmesim",
  "theme.emerald": "Esmeralda",
  "theme.swamp": "Pântano",
  "theme.light": "Claro",
  "theme.system": "Seguir o sistema",

  // ---------------------------------------------------------------- settings
  "set.title": "Configurações",
  "set.subtitle":
    "As mudanças valem na hora; com uma conexão ativa, o núcleo reinicia sozinho.",
  "set.dataFolder": "Pasta de dados",
  "set.tabCore": "Núcleo",
  "set.tabClient": "Cliente",
  "set.autostartFailed": "Falha ao alterar o início automático",

  "set.tunnelSection": "Túnel",
  "set.tunnelMode": "Modo",
  "set.tunnelModeTunDesc":
    "TUN — um adaptador virtual Wintun captura o tráfego de todo o sistema. Exige direitos de administrador, mas as regras por aplicativo funcionam.",
  "set.tunnelModeProxyDesc":
    "Proxy do sistema — sem direitos de administrador, mas cobre apenas os aplicativos que respeitam as configurações de proxy do sistema.",
  "set.systemProxy": "Proxy do sistema",
  "set.tunNeedsAdmin":
    "O aplicativo está rodando sem direitos de administrador — conectar em modo TUN vai oferecer um reinício.",

  "set.tunSection": "Opções do TUN",
  "set.tunStack": "Pilha de rede",
  "set.tunStackHint":
    "mixed — gVisor para TCP e a pilha do sistema para UDP: o melhor equilíbrio entre velocidade e compatibilidade.",
  "set.tunStackMixed": "mixed (recomendado)",
  "set.mtuHint": "O padrão é 9000.",
  "set.strictRoute": "Roteamento estrito",
  "set.strictRouteDesc":
    "Impede que o tráfego escape do túnel. Desligue se o VirtualBox/WSL ou jogos online pararem de funcionar.",
  "set.ipv6": "Suporte a IPv6",
  "set.ipv6Desc":
    "Desligado — o DNS responde apenas com registros A. Ligue quando o seu provedor e o servidor realmente suportarem IPv6.",
  "set.fakeIpDesc":
    "Acelera a abertura das páginas: os domínios são resolvidos na hora e o endereço real fica a cargo do servidor. Pode confundir alguns serviços locais.",

  "set.dnsRemote": "DNS pela VPN",
  "set.dnsRemoteHint":
    "Usado para os domínios que passam pelo túnel. tls:// e https:// também funcionam.",
  "set.dnsDirect": "DNS direto",
  "set.dnsDirectHint":
    "Para os domínios que contornam o túnel e para resolver o endereço do próprio servidor.",

  "set.connSection": "Conexão",
  "set.mixedPort": "Porta SOCKS/HTTP",
  "set.mixedPortHint": "Proxy misto local.",
  "set.clashPort": "Porta de controle do núcleo",
  "set.clashPortHint": "API Clash em 127.0.0.1.",
  "set.latencyUrl": "URL do teste de latência",
  "set.latencyUrlHint": "A requisição passa pelo servidor selecionado.",
  "set.logLevel": "Nível do log",
  "set.allowLan": "Acesso pela rede local",
  "set.allowLanDesc":
    "O proxy escuta em 0.0.0.0 para que outros dispositivos da rede possam usá-lo. Ative apenas em uma rede confiável.",
  "set.balancer": "Seleção de servidor",
  "set.balancerManual": "Manual",
  "set.balancerFailover": "Reserva",
  "set.balancerFastest": "Mais rápido",
  "set.balancerRotate": "Rodízio",
  "set.balancerManualDesc": "O servidor que você escolheu é usado. Nada muda sozinho.",
  "set.balancerFailoverDesc":
    "O servidor escolhido é o principal. Se ele parar de responder, o tráfego vai para o melhor servidor vivo e volta quando o principal retornar e se manter estável. As conexões ativas não são cortadas.",
  "set.balancerFastestDesc":
    "Todos os servidores são verificados periodicamente. O tráfego só muda para um servidor que supere o atual pelo limiar em duas rodadas seguidas, então servidores com latência parecida não ficam alternando.",
  "set.balancerRotateDesc":
    "A cada rodada passa para o próximo servidor vivo da lista; os que caíram são pulados.",
  "set.balancerInterval": "Intervalo de verificação",
  "set.balancerIntervalHint":
    "Com que frequência todos os servidores são verificados. O atual é verificado a cada 20 segundos.",
  "set.balancerTolerance": "Limiar de troca",
  "set.balancerToleranceHint": "Outro servidor precisa ser pelo menos isto mais rápido.",
  "set.everyMin": "a cada {n} min",

  "set.subsSection": "Assinaturas",
  "set.subAuto": "Atualizar automaticamente",
  "set.subAutoDesc":
    "A lista de servidores, a franquia de dados e o vencimento são buscados no painel em segundo plano. Uma lista que envelhece em silêncio é o motivo mais comum de um cliente parar de conectar do nada.",
  "set.subEveryOff": "Nunca",
  "set.subEvery3h": "a cada 3 horas",
  "set.subEvery6h": "a cada 6 horas",
  "set.subEvery12h": "a cada 12 horas",
  "set.subEveryDay": "uma vez por dia",

  "set.languageSection": "Idioma / Language",
  "set.language": "Idioma da interface",
  "set.languageDesc":
    "“Seguir o sistema” acompanha o idioma do sistema operacional. As linhas do núcleo no log continuam no idioma do próprio motor.",
  "set.langSystem": "Seguir o sistema",

  "set.themeSection": "Aparência",
  "set.theme": "Tema",
  "set.themeDesc":
    "“Seguir o sistema” acompanha a configuração do SO e troca sozinho, inclusive no horário de claro/escuro.",

  "set.startupSection": "Inicialização",
  "set.autostart": "Iniciar com o Windows",
  "set.autostartDesc": "O aplicativo abre quando você faz logon.",
  "set.autostartElevated": "Iniciar com direitos de administrador",
  "set.autostartElevatedDesc":
    "Cria uma tarefa no Agendador de Tarefas do Windows: o aplicativo inicia elevado e sobe o TUN de imediato — sem prompt do UAC. As aberturas manuais também passam pela tarefa, então nunca é preciso reiniciar “como administrador”.",
  "set.autostartElevatedNeedsAdmin":
    "Exige um único reinício com direitos de administrador para registrar a tarefa agendada.",
  "set.autostartNormalWarn":
    "O início automático comum não consegue subir o TUN: depois do logon o aplicativo vai pedir direitos. Ligue a chave acima para evitar isso.",
  "set.autoConnect": "Conectar ao abrir",
  "set.startMinimized": "Iniciar minimizado na bandeja",
  "set.closeToTray": "Fechar a janela minimiza para a bandeja",
  "set.closeToTrayDesc":
    "Desligado — o botão de fechar encerra tudo e derruba a conexão.",
  "set.resourcesSection": "Uso de recursos",
  "set.resourcesDesc":
    "A interface (WebView2) e o núcleo rodam como processos separados, então o Gerenciador de Tarefas espalha o aplicativo por várias linhas. Este é o conjunto de processos somado; os números batem com a coluna de memória do Gerenciador de Tarefas.",
  "set.resApp": "Aplicativo",
  "set.resUi": "Interface (WebView2)",
  "set.resCore": "núcleo sing-box",
  "set.resXray": "núcleo Xray",
  "set.resTotal": "Total",
  "set.resProcs": "processos: {n}",

  "set.aboutSection": "Sobre",
  "set.appVersion": "Versão do aplicativo",
  "set.coreVersion": "Núcleo",

  // -------------------------------------------------------------- formatters
  "fmt.byteUnits": "B|KB|MB|GB|TB",
  "fmt.perSecond": "/s",
  "fmt.never": "nunca",
  "fmt.justNow": "agora mesmo",
  "fmt.minAgo": "há {n} min",
  "fmt.hoursAgo": "há {n} h",
  "fmt.daysAgo": "há {n} d",
  "fmt.dayForms": "dia|dias|dias",
  "fmt.noExpiry": "sem validade",
  "fmt.expired": "expirada",
  "fmt.expiresToday": "expira hoje",
  "fmt.noTls": "sem TLS",

  // --------------------------------------------------------------- dashboard
  "dash.title": "Visão geral",
  "dash.subtitle": "Estado do túnel, velocidade e modo de roteamento.",
  "dash.stateDisconnected": "Desconectado",
  "dash.stateConnecting": "Conectando",
  "dash.stateConnected": "Conectado",
  "dash.stateError": "Erro",
  "dash.modeRule": "Regras",
  "dash.modeGlobal": "Tudo pela VPN",
  "dash.modeRuleHelp":
    "Modo do dia a dia: o que passa pela VPN é decidido pelas páginas “Túnel dividido” e “Roteamento”.",
  "dash.modeGlobalHelp":
    "Todas as conexões passam pela VPN, ignorando essas páginas.",
  "dash.tunNeedsAdmin":
    "O modo TUN exige direitos de administrador — sem eles, só o proxy do sistema fica disponível.",
  "dash.restart": "Reiniciar",
  "dash.connect": "Conectar",
  "dash.disconnect": "Desconectar",
  "dash.connectFailed": "Falha ao conectar",
  "dash.noServersTitle": "Ainda não há a que se conectar",
  "dash.noServersText":
    "Adicione um link de servidor ou uma assinatura do seu painel — o botão de conectar vai aparecer aqui.",
  "dash.trafficDown": "Descida",
  "dash.trafficUp": "Subida",
  "dash.thisSession": "Nesta sessão",
  "dash.closeAllConns": "Fechar todas as conexões ativas",
  "dash.connsClosed": "Conexões fechadas",
  "dash.connsCloseFailed": "Falha ao fechar as conexões",
  "dash.connections": "Conexões",
  "dash.clickToClose": "clique para fechar",
  "dash.notConnected": "não conectado",
  "dash.testLatency": "Testar latência",
  "dash.latency": "Latência",
  "dash.na": "n/d",
  "dash.pingMs": "{ping} ms",
  "dash.clickToTest": "clique para testar",
  "dash.noServer": "nenhum servidor selecionado",
  "dash.stateUnreachable": "Servidor não responde",
  "dash.stateReconnecting": "Reconectando…",
  "dash.unreachableHint":
    "As verificações por “{name}” falham e nenhum tráfego passa. Verifique a internet, escolha outro servidor ou ligue a Reserva.",
  "dash.unreachableAuto":
    "As verificações pelo servidor falham e nenhum tráfego passa. O balanceador muda o tráfego assim que achar um servidor vivo.",

  // ------------------------------------------------------ dashboard children
  "graph.down": "descida",
  "graph.up": "subida",
  "graph.peak": "pico",
  "graph.aria": "Gráfico de velocidade",
  "pick.noServer": "Nenhum servidor selecionado",
  "pick.select": "Escolher servidor",
  "pick.testAll": "Testar todos",
  "pick.balancers": "Balanceadores",
  "pick.servers": "Servidores",
  "pick.badgeBackup": "servidor reserva",
  "pick.now": "agora: {name}",
  "pick.nowChip": "agora",
  "pick.primary": "principal: {name}",
  "pick.primaryDown": "principal fora do ar",
  "pick.failoverMeta": "um principal e um substituto enquanto ele cala",
  "pick.fastestMeta": "por latência, sem alternar entre iguais",
  "pick.rotateMeta": "próximo servidor vivo a cada rodada",

  // ------------------------------------------------------------------ servers
  "srv.title": "Servidores",
  "srv.subtitleBefore": "Cole os links",
  "srv.subtitleAfter": "do seu painel — uma URL de assinatura também serve.",
  "srv.testLatency": "Testar latência",
  "srv.subscriptionBtn": "Assinatura",
  "srv.addBtn": "Adicionar",
  "srv.serverDeleted": "Servidor “{name}” excluído",
  "srv.deleteFailed": "Falha ao excluir o servidor",
  "srv.noRawLink": "Este servidor não tem link original",
  "srv.linkCopied": "Link copiado",
  "srv.subscriptions": "Assinaturas",
  "srv.refreshAll": "Atualizar todas",
  "srv.refreshFailed": "Falha ao atualizar",
  "srv.deleteSubTitle": "Excluir a assinatura e seus servidores",
  "srv.emptyTitle": "Ainda não há servidores",
  "srv.emptyText":
    "Copie um link de servidor ou de assinatura do seu painel (no 3x-ui, o botão “Share” no cliente) e cole aqui. Você pode colar várias linhas de uma vez.",
  "srv.pasteLinks": "Colar links",
  "srv.selectServer": "Escolher servidor",
  "srv.latencyNa": "n/d",
  "srv.latencyMs": "{ms} ms",
  "srv.copyLinkTitle": "Copiar link",
  "srv.editTitle": "Editar",
  "srv.deleteTitle": "Excluir",
  "srv.addManually": "Adicionar um servidor manualmente",
  "srv.reportAdded": "{n} adicionados",
  "srv.reportSkipped": "{n} duplicados ignorados",
  "srv.reportNothing": "nada adicionado",
  "srv.reportErrors": "com erros: {n}",
  "srv.reportNoNew": "Nenhum servidor novo",
  "srv.importFailed": "Falha na importação",
  "srv.addServers": "Adicionar servidores",
  "srv.cancel": "Cancelar",
  "srv.importBtn": "Importar",
  "srv.linksLabel": "Links",
  "srv.linksHint":
    "Um por linha. Aceita vless://, vmess://, trojan://, ss://, hysteria2://, tuic:// ou um bloco base64 inteiro de assinatura — e um link http(s) de assinatura vai para “Assinaturas” e se atualiza sozinho.",
  "srv.linkPlaceholder":
    "vless://uuid@servidor:443?type=tcp&security=reality&pbk=...#Nome",
  "srv.subLoadFailed": "Falha ao carregar a assinatura",
  "srv.addSubscription": "Adicionar assinatura",
  "srv.loadBtn": "Carregar",
  "srv.nameLabel": "Nome",
  "srv.subNameHint": "Opcional — por padrão vem do endereço.",
  "srv.subNamePlaceholder": "Meu servidor",
  "srv.subUrlLabel": "URL da assinatura",
  "srv.subUrlHint":
    "No 3x-ui, por exemplo, é o link Subscription URL nas configurações do cliente.",
  "srv.serverNotAdded": "Servidor não adicionado",
  "srv.duplicateServer": "este servidor já está na lista",
  "srv.serverAdded": "Servidor adicionado",
  "srv.serverSaved": "Servidor salvo",
  "srv.saveFailed": "Falha ao salvar",
  "srv.newServer": "Novo servidor",
  "srv.serverParams": "Configurações do servidor",
  "srv.saveBtn": "Salvar",
  "srv.protocolLabel": "Protocolo",
  "srv.addressLabel": "Endereço",
  "srv.portLabel": "Porta",
  "srv.passwordLabel": "Senha",
  "srv.encryptionLabel": "Criptografia",
  "srv.transportLabel": "Transporte",
  "srv.channelEncryptionLabel": "Criptografia do canal",
  "srv.noTls": "sem TLS",
  "srv.tlsFingerprintLabel": "Impressão digital TLS (fp)",
  "srv.flowHint": "Normalmente xtls-rprx-vision ou vazio.",
  "srv.skipCertLabel": "Não verificar o certificado",
  "srv.skipCertDesc":
    "Só é preciso com um certificado autoassinado no servidor. A conexão continua criptografada, mas um certificado trocado passa despercebido.",
  "srv.muxLabel": "Multiplexação (mux)",
  "srv.muxDesc":
    "Várias requisições em uma conexão. Acelera o carregamento de páginas, mas é incompatível com o XTLS Vision e atrapalha torrents.",
  "srv.subRefreshFailed": "Falha ao atualizar “{name}”",
  "srv.refreshNow": "Atualizar agora",
  "srv.remaining": "Restante",
  "srv.trafficLabel": "Dados",
  "srv.expiredWarning":
    "A assinatura expirou — os servidores provavelmente já não respondem.",
  "srv.exhaustedWarning":
    "Franquia de dados esgotada — renove o plano no painel.",
  "srv.noUsageInfo": "O painel não informa franquia de dados nem vencimento",
  "srv.serverOne": "servidor",
  "srv.serverFew": "servidores",
  "srv.serverMany": "servidores",
  "srv.updatedWhen": "atualizado {when}",

  // ------------------------------------------------------------ split tunnel
  "split.title": "Túnel dividido",
  "split.subtitle":
    "Regras para aplicativos específicos. A rota de um aplicativo e as suas consultas de DNS seguem sempre o mesmo caminho, então o endereço nunca vaza para fora do túnel.",
  "split.modeOffHelp": "Todo o tráfego do sistema passa pela VPN.",
  "split.modeIncludeHelp":
    "Só os aplicativos escolhidos passam pela VPN. O resto vai direto, contornando o túnel.",
  "split.modeExcludeHelp":
    "Os aplicativos escolhidos contornam a VPN e vão direto. Todo o resto do tráfego passa pelo túnel.",
  "split.exeDialogTitle": "Escolher um programa",
  "split.exeDialogFilter": "Programas",
  "split.alreadyInList": "Este programa já está na lista",
  "split.tunOnlyTitle": "Funciona apenas no modo TUN",
  "split.tunOnlyText":
    "O modo de proxy do sistema está ativo. Só dá para saber a qual aplicativo pertence uma conexão quando o tráfego passa pelo adaptador virtual — troque o modo nas configurações.",
  "split.mode": "Modo",
  "split.modeOff": "Desligado",
  "split.modeInclude": "Só os escolhidos",
  "split.modeExclude": "Todos, menos os escolhidos",
  "split.appsCount": "Aplicativos ({count})",
  "split.addFromRunning": "Dos aplicativos abertos",
  "split.pickExe": "Escolher .exe",
  "split.clearList": "Limpar a lista",
  "split.emptyTitle": "A lista está vazia",
  "split.emptyText":
    "Adicione aplicativos — por exemplo, o cliente do banco e a Steam fora da VPN, ou só o navegador pela VPN.",
  "split.matchByName": "identificado pelo nome do processo",
  "split.procsFailed": "Falha ao obter a lista de processos",
  "split.runningApps": "Aplicativos abertos",
  "split.cancel": "Cancelar",
  "split.addCount": "Adicionar ({count})",
  "split.searchPlaceholder": "Buscar por nome ou caminho",
  "split.refresh": "Atualizar",
  "split.showSystemProcs": "Mostrar processos de sistema do Windows",
  "split.loading": "Carregando…",
  "split.nothingFound": "Nada encontrado",
  "split.instancesCount": "{count} processos",
  "split.alreadyAdded": "já adicionado",
  "split.selectedChip": "selecionado",

  // ------------------------------------------------------------------ routing
  "route.title": "Roteamento",
  "route.subtitle":
    "As regras valem de cima para baixo e a primeira que casar vence: bloqueios → rede local → suas listas → regras geográficas → regras de aplicativo.",
  "route.showConfig": "Ver configuração",
  "route.buildFailed": "Falha ao montar a configuração",
  "route.presets": "Predefinições",
  "route.bypassLan": "Não mexer na rede local",
  "route.bypassLanDesc":
    "Roteador, impressoras, NAS e localhost vão direto. Desligue apenas de propósito — do contrário os dispositivos da sua rede ficam inalcançáveis.",
  "route.bypassRu": "Sites russos fora da VPN",
  "route.bypassRuDesc":
    "Domínios e endereços das listas geosite/geoip ru vão direto. Agiliza o acesso a serviços locais e elimina captchas.",
  "route.bypassCn": "Sites chineses fora da VPN",
  "route.bypassCnDesc": "O mesmo para a lista geosite/geoip cn.",
  "route.blockAds": "Bloquear anúncios e rastreadores",
  "route.blockAdsDesc":
    "Requisições a domínios da lista category-ads-all são recusadas no núcleo e no DNS.",
  "route.customRules": "Regras próprias",
  "route.directDomains": "Sempre direto — domínios",
  "route.directDomainsHint":
    "Um por linha. Casamento por sufixo: example.com cobre também sub.example.com.",
  "route.proxyDomains": "Sempre pela VPN — domínios",
  "route.proxyDomainsHint":
    "Tem prioridade sobre as regras geográficas, mas cede para a lista “sempre direto”.",
  "route.directIps": "Sempre direto — endereços",
  "route.directIpsHint": "IP ou CIDR, por exemplo 10.0.0.0/8.",
  "route.proxyIps": "Sempre pela VPN — endereços",
  "route.proxyIpsHint": "IP ou CIDR.",
  "route.blockDomains": "Bloquear domínios",
  "route.blockDomainsHint":
    "As conexões são recusadas e o DNS não devolve resposta.",
  "route.configTitle": "Configuração sing-box gerada",
  "route.copied": "Copiado",
  "route.copy": "Copiar",
  "route.close": "Fechar",

  // --------------------------------------------------------------------- logs
  "logs.title": "Log do núcleo",
  "logs.subtitle":
    "Saída do sing-box em tempo real. Olhe aqui se a conexão fica caindo.",
  "logs.filterAll": "Tudo",
  "logs.filterInfo": "Info",
  "logs.filterWarn": "Aviso",
  "logs.filterErrors": "Erros",
  "logs.copyAll": "Copiar tudo",
  "logs.copied": "Log copiado",
  "logs.clear": "Limpar",
  "logs.empty": "O log está vazio — as linhas aparecem depois de conectar.",
  "logs.toLatest": "Para as linhas mais recentes",

  // ------------------------------------------------------------ elevate modal
  "elev.title": "São necessários direitos de administrador",
  "elev.relaunchFailed": "Falha ao reiniciar",
  "elev.cancel": "Cancelar",
  "elev.restart": "Reiniciar",
  "elev.tunnelWhy":
    "O modo TUN intercepta todo o tráfego do sistema pelo adaptador virtual Wintun. Criá-lo exige direitos de administrador — o Windows vai mostrar um prompt do UAC.",
  "elev.tunnelAlt":
    "Se não quiser elevar, troque para o modo de proxy do sistema nas configurações: ele funciona sem UAC, mas cobre apenas os aplicativos que respeitam as configurações de proxy do sistema.",
  "elev.autostartWhy":
    "O início automático com direitos de administrador cria uma tarefa no Agendador de Tarefas do Windows — uma entrada comum de inicialização não dá conta disso, o sistema não eleva direitos sem confirmação.",
  "elev.autostartOnce":
    "Os direitos são necessários uma única vez, para registrar a tarefa. Depois disso o aplicativo passa a iniciar com direitos de administrador sozinho, sem prompt do UAC a cada logon.",
} as const;
