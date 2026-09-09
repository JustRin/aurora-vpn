//! Связывает разметку с ядром: снимок состояния в глобалы, колбэки разметки в
//! команды api.rs.
//!
//! Роль та же, что у store.ts и обработчиков в страницах веб-версии. Всё, что
//! здесь вызывается, уходит в рантайм tokio: команды асинхронные, а поток цикла
//! Slint блокировать нельзя.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use i_slint_backend_winit::WinitWindowAccessor;
use slint::{ComponentHandle, Model, ModelRc, VecModel};

use crate::api::{self, Snapshot};
use crate::app::{self, AppHandle};
use crate::error::Result;
use crate::model::{Network, Protocol, Security, ServerNode};
use crate::qr;
use crate::settings::{AppRule, Balancer, Settings, SplitConfig, SplitMode, TunStack, TunnelMode};
use crate::shell;
use crate::state::AppState;
use crate::sys::autostart::AutostartMode;
use crate::sys::{autostart, camera, clipboard, dialog, procs, screen};
use crate::view;
use crate::{AppWindow, Conf, Data, Draft, Ui};

/// Порядок вариантов в списках разметки — он же в PROTOCOLS/NETWORKS редактора.
const PROTOCOLS: [Protocol; 6] = [
    Protocol::Vless,
    Protocol::Vmess,
    Protocol::Trojan,
    Protocol::Shadowsocks,
    Protocol::Hysteria2,
    Protocol::Tuic,
];
const NETWORKS: [Network; 5] = [
    Network::Tcp,
    Network::Ws,
    Network::Grpc,
    Network::Http,
    Network::Httpupgrade,
];
const LOG_LEVELS: [&str; 5] = ["trace", "debug", "info", "warn", "error"];
/// Значения выпадающего списка автообновления подписок, в минутах.
const SUB_AUTO_MINUTES: [u32; 5] = [0, 180, 360, 720, 1440];
/// Период обхода серверов балансировщиком, в минутах, — по порядку списка в
/// settings.slint.
const BALANCER_MINUTES: [u32; 5] = [1, 3, 5, 10, 30];
/// Порог «самого быстрого», в миллисекундах, — тем же порядком.
const BALANCER_TOLERANCE: [u32; 4] = [50, 100, 200, 300];
/// Режимы переключателя на «Обзоре». Третий режим ядра, `Direct`, сюда не
/// вынесен: «весь трафик мимо VPN» — это и есть выключенный туннель, а кнопка
/// питания говорит об этом понятнее. Придёт он снаружи (Clash API) — строка
/// просто не найдётся, и переключатель покажет «По правилам».
const MODES: [&str; 2] = ["Rule", "Global"];
/// Пауза перед сохранением настроек после последней правки.
const SAVE_DELAY: std::time::Duration = std::time::Duration::from_millis(600);
/// Как часто спрашивать GitHub о новом релизе. API без токена лимитируется по
/// адресу, поэтому реже, а не чаще.
const UPDATE_CHECK: std::time::Duration = std::time::Duration::from_secs(10 * 60);

thread_local! {
    /// Полный список запущенных программ: строка поиска фильтрует его на месте,
    /// не тревожа систему. Здесь, а не в Local, потому что заполняет его
    /// рабочий поток — а Rc через границу потока не проходит.
    static PROCS: RefCell<Vec<procs::RunningApp>> = const { RefCell::new(Vec::new()) };

    /// Живая съёмка камеры. Одна на приложение — окно предпросмотра одно, — и
    /// уничтожение записи гасит камеру: лампочка рядом с объективом тоже.
    static CAMERA: RefCell<Option<camera::Session>> = const { RefCell::new(None) };
    /// Камеры, найденные при открытии окна: разметке достаются их названия, а
    /// открывать устройство надо по символической ссылке.
    static CAMERAS: RefCell<Vec<camera::Device>> = const { RefCell::new(Vec::new()) };

    /// Размер и место окна до ухода в полоску: вернуть надо ровно те же.
    static SCAN_RETURN: RefCell<Option<(slint::PhysicalSize, slint::PhysicalPosition)>> =
        const { RefCell::new(None) };
}

/// Отличаются ли настройки хоть чем-нибудь: сравнение по сериализованному виду,
/// чтобы не перечислять три десятка полей ради одной проверки.
fn settings_differ(a: &Settings, b: &Settings) -> bool {
    serde_json::to_string(a).ok() != serde_json::to_string(b).ok()
}

/// То же для правил. Нужно по той же причине: changed в разметке срабатывает и
/// на первую раскладку снимка по полям, а применение правил при живом
/// подключении перезапускает ядро — из-за пустой правки туннель моргать не
/// должен.
fn split_differs(a: &SplitConfig, b: &SplitConfig) -> bool {
    serde_json::to_string(a).ok() != serde_json::to_string(b).ok()
}

/// То, что интерфейсу нужно помнить между вызовами, но ядру знать незачем.
struct Local {
    /// Узел, открытый в редакторе: правки накладываются поверх него, чтобы не
    /// потерять поля, которых в форме нет (alpn, encryption, ссылку подписки).
    editing: RefCell<Option<ServerNode>>,
    /// Пока снимок раскладывается по глобалам, обработчики изменений молчат:
    /// иначе первая же запись в Conf прилетела бы обратно как «настройки
    /// изменил пользователь» и перезапустила ядро.
    loading: std::cell::Cell<bool>,
    /// Отложенное сохранение: поля формы правятся посимвольно, а сохранение
    /// перезапускает ядро. Таймер перезаводится на каждое изменение и стреляет,
    /// когда правки прекратились.
    save: slint::Timer,
}

/// Поднять ядро и подключить к нему интерфейс.
pub fn install(ui: &AppWindow) -> Result<AppHandle> {
    let core = app::locate_core().ok_or_else(|| {
        crate::error::AppError::msg(
            "не найден sing-box: положите его рядом с приложением или соберите с binaries/",
        )
    })?;
    let state = Arc::new(AppState::new(app::config_dir()?, core, app::locate_xray())?);
    let handle = AppHandle::new(state, ui.as_weak());
    let local = Rc::new(Local {
        editing: RefCell::new(None),
        loading: std::cell::Cell::new(false),
        save: slint::Timer::default(),
    });

    // Модели, которые правятся по месту, живут здесь: журнал и тосты дописывают
    // по строке, полная замена на каждую была бы заметно дороже.
    {
        let data = ui.global::<Data>();
        data.set_logs(ModelRc::new(VecModel::<crate::LogLine>::default()));
        data.set_toasts(ModelRc::new(VecModel::<crate::ToastMsg>::default()));
        data.set_procs(ModelRc::new(VecModel::<crate::RunningApp>::default()));
        data.set_app_version(app::VERSION.into());
    }

    // График рисуется по минуте отсчётов; пустая история дала бы одну ступень
    // во всю ширину, поэтому она начинается нулями — как и линия на экране.
    view::with(|v| v.graph.prefill());

    let snapshot = app::runtime().block_on(api::get_snapshot(handle.clone()))?;
    local.loading.set(true);
    apply_snapshot(ui, &snapshot);
    local.loading.set(false);

    let logs = app::runtime().block_on(api::get_logs(handle.clone()))?;
    view::render_logs(ui, &logs);

    wire(ui, &handle, &local);
    Ok(handle)
}

// ------------------------------------------------------------------ снимок

/// Разложить снимок состояния по глобалам. Делается один раз на старте: дальше
/// интерфейс живёт событиями.
fn apply_snapshot(ui: &AppWindow, snap: &Snapshot) {
    let data = ui.global::<Data>();
    data.set_core_version(snap.core_version.as_str().into());

    view::with(|v| {
        v.nodes = snap.nodes.clone();
        v.subs = snap.subscriptions.clone();
        v.latency = snap.latency.clone();
        v.status = snap.status.clone();
        v.traffic = snap.traffic;
        v.active_id = snap.active_id.clone();
    });
    view::render_status(ui);
    view::render_nodes(ui);
    view::render_subs(ui);
    view::render_traffic(ui);
    view::render_uptime(ui);

    write_settings(ui, &snap.settings, snap.autostart);
    write_warp(ui, snap.warp_registered, "");
    // Язык теперь известен — строки, которые собирает Rust, надо переснять:
    // первый снимок делался до того, как настройки были прочитаны.
    crate::reload_lang(ui);
    view::render_status(ui);
    view::render_nodes(ui);
    view::render_subs(ui);
    view::render_traffic(ui);

    write_split(ui, &snap.split);
    render_apps(ui, &snap.split);
    ui.global::<Ui>()
        .set_mode(MODES.iter().position(|m| *m == snap.status.mode).unwrap_or(0) as i32);
}

/// Настройки ядра → поля разметки.
/// Подпись под «Аккаунт Cloudflare»: тариф подставляется здесь, потому что
/// подстановок в разметке Slint нет — как и у остальных строк с {n}.
fn write_warp(ui: &AppWindow, registered: bool, account_type: &str) {
    let data = ui.global::<Data>();
    data.set_warp_registered(registered);
    data.set_warp_account_state(
        if registered {
            let plan = if account_type.is_empty() { "free" } else { account_type };
            crate::tr(|l| l.warp_account_on.replace("{type}", plan))
        } else {
            crate::tr(|l| l.warp_account_off.clone())
        }
        .into(),
    );
}

fn write_settings(ui: &AppWindow, s: &Settings, autostart: AutostartMode) {
    let conf = ui.global::<Conf>();
    conf.set_tunnel_mode(matches!(s.tunnel_mode, TunnelMode::SystemProxy) as i32);
    conf.set_tun_stack(match s.tun_stack {
        TunStack::Mixed => 0,
        TunStack::System => 1,
        TunStack::Gvisor => 2,
    });
    conf.set_tun_mtu(s.tun_mtu.to_string().into());
    conf.set_strict_route(s.strict_route);
    conf.set_ipv6(s.ipv6);
    conf.set_fake_ip(s.fake_ip);
    // Тумблер WARP живёт на «Обзоре», в Data, а не в форме настроек — но
    // хранится вместе с ними, и обновляться должен здесь же.
    ui.global::<Data>().set_warp_on(s.warp_over_proxy);
    conf.set_dns_remote(s.dns_remote.as_str().into());
    conf.set_dns_direct(s.dns_direct.as_str().into());
    conf.set_mixed_port(s.mixed_port.to_string().into());
    conf.set_clash_port(s.clash_port.to_string().into());
    conf.set_latency_url(s.latency_url.as_str().into());
    conf.set_log_level(LOG_LEVELS.iter().position(|l| *l == s.log_level).unwrap_or(2) as i32);
    conf.set_allow_lan(s.allow_lan);
    conf.set_balancer(match s.balancer {
        Balancer::Manual => 0,
        Balancer::Failover => 1,
        Balancer::Fastest => 2,
        Balancer::Rotate => 3,
    });
    conf.set_balancer_interval(
        BALANCER_MINUTES
            .iter()
            .position(|m| *m == s.balancer_interval_min)
            .unwrap_or(1) as i32,
    );
    conf.set_balancer_tolerance(
        BALANCER_TOLERANCE
            .iter()
            .position(|ms| *ms == s.balancer_tolerance_ms)
            .unwrap_or(1) as i32,
    );
    conf.set_sub_auto(
        SUB_AUTO_MINUTES
            .iter()
            .position(|m| *m == s.sub_auto_update_min)
            .unwrap_or(4) as i32,
    );
    // 0 — «как в системе», дальше по порядку crate::LANGS.
    conf.set_language(
        crate::LANGS
            .iter()
            .position(|lang| *lang == s.language)
            .map(|i| i as i32 + 1)
            .unwrap_or(0),
    );
    conf.set_theme(s.theme.as_str().into());
    conf.set_auto_connect(s.auto_connect);
    conf.set_start_minimized(s.start_minimized);
    conf.set_close_to_tray(s.close_to_tray);
    conf.set_notifications(s.notifications);
    // Автозапуск читается у системы, а не из настроек: пользователь мог убрать
    // задачу планировщика мимо приложения.
    conf.set_autostart(!matches!(autostart, AutostartMode::Off));
    conf.set_autostart_elevated(matches!(autostart, AutostartMode::Elevated));
}

/// Поля разметки → настройки ядра. Остальное (тема, язык) кладётся поверх того,
/// что уже лежит в состоянии: этих полей в форме нет.
fn read_settings(ui: &AppWindow, current: &Settings) -> Settings {
    let conf = ui.global::<Conf>();
    let number = |text: slint::SharedString, fallback: u32| text.parse::<u32>().unwrap_or(fallback);
    Settings {
        tunnel_mode: if conf.get_tunnel_mode() == 1 {
            TunnelMode::SystemProxy
        } else {
            TunnelMode::Tun
        },
        tun_stack: match conf.get_tun_stack() {
            1 => TunStack::System,
            2 => TunStack::Gvisor,
            _ => TunStack::Mixed,
        },
        tun_mtu: number(conf.get_tun_mtu(), current.tun_mtu).clamp(576, 65535),
        strict_route: conf.get_strict_route(),
        ipv6: conf.get_ipv6(),
        fake_ip: conf.get_fake_ip(),
        // Тумблер живёт на «Обзоре», а не в форме настроек: сюда он попадает
        // тем же путём, что тема и язык — из уже сохранённого состояния.
        warp_over_proxy: current.warp_over_proxy,
        dns_remote: conf.get_dns_remote().to_string(),
        dns_direct: conf.get_dns_direct().to_string(),
        mixed_port: number(conf.get_mixed_port(), current.mixed_port as u32).clamp(1, 65535) as u16,
        clash_port: number(conf.get_clash_port(), current.clash_port as u32).clamp(1, 65535) as u16,
        latency_url: conf.get_latency_url().to_string(),
        log_level: LOG_LEVELS
            .get(conf.get_log_level().max(0) as usize)
            .unwrap_or(&"info")
            .to_string(),
        allow_lan: conf.get_allow_lan(),
        balancer: match conf.get_balancer() {
            1 => Balancer::Failover,
            2 => Balancer::Fastest,
            3 => Balancer::Rotate,
            _ => Balancer::Manual,
        },
        balancer_interval_min: BALANCER_MINUTES
            .get(conf.get_balancer_interval().max(0) as usize)
            .copied()
            .unwrap_or(3),
        balancer_tolerance_ms: BALANCER_TOLERANCE
            .get(conf.get_balancer_tolerance().max(0) as usize)
            .copied()
            .unwrap_or(100),
        auto_select: false,
        sub_auto_update_min: SUB_AUTO_MINUTES
            .get(conf.get_sub_auto().max(0) as usize)
            .copied()
            .unwrap_or(1440),
        language: match conf.get_language() {
            n if n >= 1 => crate::LANGS
                .get(n as usize - 1)
                .map(|lang| (*lang).to_string())
                .unwrap_or_else(|| "system".into()),
            _ => "system".into(),
        },
        theme: conf.get_theme().to_string(),
        theme_dark: ui.global::<crate::Theme>().get_dark(),
        theme_background: hex(ui.global::<crate::Theme>().get_bg()),
        auto_connect: conf.get_auto_connect(),
        start_minimized: conf.get_start_minimized(),
        close_to_tray: conf.get_close_to_tray(),
        notifications: conf.get_notifications(),
        dns_strategy: current.dns_strategy.clone(),
    }
}

/// `#rrggbb` без альфы: цвет уходит в настройки, чтобы следующий запуск открыл
/// окно на нужном фоне ещё до первого кадра.
fn hex(color: slint::Color) -> String {
    format!("#{:02x}{:02x}{:02x}", color.red(), color.green(), color.blue())
}

fn write_split(ui: &AppWindow, split: &SplitConfig) {
    let conf = ui.global::<Conf>();
    conf.set_split_mode(match split.mode {
        SplitMode::Off => 0,
        SplitMode::Include => 1,
        SplitMode::Exclude => 2,
    });
    conf.set_bypass_private(split.bypass_private);
    conf.set_bypass_ru(split.bypass_ru);
    conf.set_bypass_cn(split.bypass_cn);
    conf.set_block_ads(split.block_ads);
    conf.set_direct_domains(split.direct_domains.join("\n").into());
    conf.set_proxy_domains(split.proxy_domains.join("\n").into());
    conf.set_direct_ips(split.direct_ips.join("\n").into());
    conf.set_proxy_ips(split.proxy_ips.join("\n").into());
    conf.set_block_domains(split.block_domains.join("\n").into());
}

fn read_split(ui: &AppWindow, current: &SplitConfig) -> SplitConfig {
    let conf = ui.global::<Conf>();
    let lines = |text: slint::SharedString| {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    SplitConfig {
        mode: match conf.get_split_mode() {
            1 => SplitMode::Include,
            2 => SplitMode::Exclude,
            _ => SplitMode::Off,
        },
        // Список программ правится своими кнопками, а не этой формой.
        apps: current.apps.clone(),
        direct_domains: lines(conf.get_direct_domains()),
        proxy_domains: lines(conf.get_proxy_domains()),
        direct_ips: lines(conf.get_direct_ips()),
        proxy_ips: lines(conf.get_proxy_ips()),
        block_domains: lines(conf.get_block_domains()),
        bypass_private: conf.get_bypass_private(),
        bypass_ru: conf.get_bypass_ru(),
        bypass_cn: conf.get_bypass_cn(),
        block_ads: conf.get_block_ads(),
    }
}

/// Строки программ раздельного туннеля. Иконка добывается отдельным потоком —
/// пока её нет, строка рисует букву.
fn render_apps(ui: &AppWindow, split: &SplitConfig) {
    let rows: Vec<crate::AppRule> = split
        .apps
        .iter()
        .map(|rule| crate::AppRule {
            id: rule.id.as_str().into(),
            name: rule.name.as_str().into(),
            initial: initial_of(&rule.name),
            icon: Default::default(),
            path: rule.path.as_str().into(),
            enabled: rule.enabled,
        })
        .collect();
    ui.global::<Data>().set_apps(ModelRc::new(VecModel::from(rows)));
    crate::sync_icons(ui);
}

fn initial_of(name: &str) -> slint::SharedString {
    name.chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default()
        .into()
}

// --------------------------------------------------------------- колбэки

/// Запустить команду и показать тост, если она не удалась.
fn run<F, Fut>(handle: &AppHandle, make: F)
where
    F: FnOnce(AppHandle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send,
{
    let handle = handle.clone();
    app::runtime().spawn(async move {
        let reporter = handle.clone();
        if let Err(err) = make(handle).await {
            let text = err.to_string();
            // Не ошибка, а вопрос: подключение прервано ради окна про ядро от
            // прошлого сеанса, и оно уже на экране. Всплывашка поверх него
            // сказала бы то же самое второй раз и мимо сути.
            if text.contains(api::ORPHAN_CORE) {
                return;
            }
            let text = human(text);
            reporter.with_ui(move |ui| view::toast(ui, "error", &text, ""));
        }
    });
}

/// Ошибка человеческими словами.
///
/// `ELEVATION_REQUIRED` — сговор ядра с интерфейсом: на него смотрят кнопка
/// питания и переключатель автозапуска, и до всплывашки он доходить не должен.
/// Но если дошёл, показывать константу нельзя — из неё непонятно ровно то, что
/// она и означает.
fn human(text: String) -> String {
    if text.contains(crate::sys::autostart::ELEVATION_REQUIRED) {
        return "нужны права администратора — перезапустите приложение от имени администратора"
            .into();
    }
    text
}

fn wire(ui: &AppWindow, handle: &AppHandle, local: &Rc<Local>) {
    let data = ui.global::<Data>();

    // ---- подключение ------------------------------------------------------
    data.on_toggle_power({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let connected = ui.global::<Data>().get_connected();
            // Режим TUN без прав администратора ядро не поднимет: сначала
            // спрашиваем, как в веб-версии, а перезапуск делает кнопка в окне.
            if !connected
                && ui.global::<Conf>().get_tunnel_mode() == 0
                && !ui.global::<Data>().get_elevated()
            {
                let ui_global = ui.global::<Ui>();
                ui_global.set_elevate_reason("tunnel".into());
                ui_global.set_modal(5);
                return;
            }
            run(&handle, move |h| async move {
                if connected {
                    api::disconnect(h).await
                } else {
                    api::connect(h).await
                }
            });
        }
    });

    // «Да» в окне про ядро от прошлого сеанса: снять его и подключиться.
    data.on_kill_orphan({
        let handle = handle.clone();
        move || run(&handle, |h| async move { api::kill_stale_core(h).await })
    });

    // Раздел подписки свернули или раскрыли.
    data.on_toggle_group({
        let weak = ui.as_weak();
        move |id| {
            if let Some(ui) = weak.upgrade() {
                view::toggle_group(&ui, &id);
            }
        }
    });

    data.on_close_conns({
        let handle = handle.clone();
        move || run(&handle, |h| async move { api::close_connections(h).await })
    });

    data.on_set_mode({
        let handle = handle.clone();
        move |index| {
            let mode = MODES.get(index.max(0) as usize).unwrap_or(&"Rule").to_string();
            run(&handle, move |h| async move { api::set_clash_mode(h, mode).await });
        }
    });

    // ---- серверы ----------------------------------------------------------
    data.on_select_server({
        let handle = handle.clone();
        move |id| {
            let id = id.to_string();
            let handle = handle.clone();
            app::runtime().spawn(async move {
                let reporter = handle.clone();
                match api::set_active_server(handle, id).await {
                    // Балансировщик пришлось выключить: показать это и в
                    // настройках, и всплывашкой — иначе список врёт.
                    Ok(true) => reporter.with_ui(|ui| {
                        ui.global::<Conf>().set_balancer(0);
                        let text = crate::tr(|l| l.balancer_off.clone());
                        view::toast(ui, "info", &text, "");
                    }),
                    Ok(false) => {}
                    Err(e) => {
                        let text = human(e.to_string());
                        reporter.with_ui(move |ui| view::toast(ui, "error", &text, ""));
                    }
                }
            });
        }
    });

    // Тумблер «Дополнительная защита через WARP». Первое включение заводит
    // анонимный аккаунт Cloudflare — на это уходит секунда-другая, и всё это
    // время переключатель погашен, чтобы по нему не щёлкали второй раз.
    data.on_warp_toggle({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move |on| {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<Data>().set_warp_busy(true);
            let reporter = handle.clone();
            let weak = weak.clone();
            app::runtime().spawn(async move {
                let done = api::enable_warp(reporter.clone(), on).await;
                reporter.with_ui(move |ui| {
                    let data = ui.global::<Data>();
                    data.set_warp_busy(false);
                    match &done {
                        Ok(info) => {
                            write_warp(ui, info.registered, &info.account_type);
                            data.set_warp_on(on);
                            if on {
                                view::toast(ui, "success", &crate::tr(|l| l.warp_enabled.clone()), "");
                            }
                        }
                        Err(e) => {
                            // Тумблер возвращается сам: включённым он выглядел
                            // бы обещанием, которого приложение не сдержало.
                            data.set_warp_on(false);
                            let detail = human(e.to_string());
                            view::toast(ui, "error", &crate::tr(|l| l.warp_register_failed.clone()), &detail);
                        }
                    }
                });
                let _ = weak;
            });
        }
    });

    data.on_warp_add_node({
        let handle = handle.clone();
        move || {
            let handle = handle.clone();
            app::runtime().spawn(async move {
                let reporter = handle.clone();
                match api::add_warp_node(handle).await {
                    Ok(()) => reporter.with_ui(move |ui| {
                        view::toast(ui, "success", &crate::tr(|l| l.warp_node_added.clone()), "")
                    }),
                    Err(e) => {
                        let detail = human(e.to_string());
                        reporter.with_ui(move |ui| {
                            view::toast(ui, "error", &crate::tr(|l| l.warp_register_failed.clone()), &detail)
                        })
                    }
                }
            });
        }
    });

    // Новая регистрация: другой ключ, а с ним и другой адрес на выходе.
    data.on_warp_reset({
        let handle = handle.clone();
        move || {
            let handle = handle.clone();
            app::runtime().spawn(async move {
                let reporter = handle.clone();
                reporter.with_ui(|ui| ui.global::<Data>().set_warp_busy(true));
                let done = api::reset_warp(handle).await;
                reporter.with_ui(move |ui| {
                    let data = ui.global::<Data>();
                    data.set_warp_busy(false);
                    match &done {
                        Ok(info) => {
                            write_warp(ui, info.registered, &info.account_type);
                            view::toast(ui, "success", &crate::tr(|l| l.warp_reset_done.clone()), "");
                        }
                        Err(e) => {
                            let detail = human(e.to_string());
                            view::toast(ui, "error", &crate::tr(|l| l.warp_register_failed.clone()), &detail);
                        }
                    }
                });
            });
        }
    });

    data.on_open_url(move |url| {
        let _ = crate::sys::open::uri(&url);
    });

    // Порядок, собранный перетаскиванием. Ядро не перезапускается: теги живого
    // документа держатся по идентификаторам узлов, а не по позициям.
    data.on_reorder_node({
        let handle = handle.clone();
        move |id, to| {
            let id = id.to_string();
            run(&handle, move |h| async move { api::reorder_node(h, id, to).await });
        }
    });

    data.on_delete_server({
        let handle = handle.clone();
        move |id| {
            let id = id.to_string();
            run(&handle, move |h| async move { api::delete_server(h, id).await });
        }
    });

    data.on_copy_link({
        let weak = ui.as_weak();
        move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let link = view::with(|v| {
                v.nodes
                    .iter()
                    .find(|n| n.id == id.as_str())
                    .map(|n| n.raw_link.clone())
                    .unwrap_or_default()
            });
            match clipboard::set_text(&link) {
                Ok(()) if !link.is_empty() => {
                    let text = crate::tr(|l| l.link_copied.clone());
                    view::toast(&ui, "success", &text, "");
                }
                Ok(()) => view::toast(&ui, "info", "у этого сервера нет исходной ссылки", ""),
                Err(e) => view::toast(&ui, "error", &e.to_string(), ""),
            }
        }
    });

    data.on_import_links({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move |text| {
            let text = text.to_string();
            let handle = handle.clone();
            let weak = weak.clone();
            let _ = weak.upgrade().map(|ui| {
                let ui_global = ui.global::<Ui>();
                ui_global.set_modal(0);
                ui_global.set_import_text("".into());
            });
            app::runtime().spawn(async move {
                let reporter = handle.clone();
                match api::add_links(handle, text).await {
                    Ok(report) => reporter.with_ui(move |ui| import_toast(ui, &report)),
                    Err(e) => {
                        let text = e.to_string();
                        reporter.with_ui(move |ui| view::toast(ui, "error", &text, ""));
                    }
                }
            });
        }
    });

    // -------------------------------------------------------------- qr
    data.on_paste_links({
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            match clipboard::text() {
                Ok(text) if !text.trim().is_empty() => {
                    // Без сообщения об успехе: вставленное видно в самом поле.
                    append_import(&ui, text.lines());
                }
                Ok(_) => {
                    let text = crate::tr(|l| l.clipboard_empty.clone());
                    view::toast(&ui, "info", &text, "");
                }
                Err(e) => {
                    let text = crate::tr(|l| l.paste_failed.clone());
                    view::toast(&ui, "error", &text, &e.to_string());
                }
            }
        }
    });

    data.on_scan_screen({
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            enter_scan_mode(&ui);
        }
    });

    data.on_scan_now({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let global = ui.global::<Ui>();
            global.set_qr_busy(true);
            global.set_scan_empty(false);
            // Полоска сама попала бы в кадр — на время снимка её нет.
            ui.window()
                .with_winit_window(|window| window.set_visible(false));
            let handle = handle.clone();
            app::runtime().spawn_blocking(move || {
                // Пауза, чтобы система успела перерисовать то, что было под нами.
                std::thread::sleep(SCREENSHOT_DELAY);
                let found = screen::capture()
                    .map(|shot| qr::decode_luma(shot.width, shot.height, &shot.luma));
                handle.with_ui(move |ui| {
                    shell::show(ui);
                    ui.global::<Ui>().set_qr_busy(false);
                    match found {
                        // Ничего не нашлось — режим остаётся: код, скорее всего,
                        // ещё не открыли, и повторить надо одной кнопкой.
                        Ok(codes) if codes.is_empty() => flash_nothing_found(ui),
                        Ok(codes) => {
                            leave_scan_mode(ui);
                            absorb_codes(ui, codes);
                        }
                        Err(e) => {
                            leave_scan_mode(ui);
                            view::toast(ui, "error", &e.to_string(), "");
                        }
                    }
                });
            });
        }
    });

    data.on_scan_move({
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.window().with_winit_window(|window| {
                let _ = window.drag_window();
            });
        }
    });

    data.on_scan_exit({
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            leave_scan_mode(&ui);
        }
    });

    data.on_scan_file({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<Ui>().set_qr_busy(true);
            let title = ui.global::<crate::Str>().get_qr_title().to_string();
            let handle = handle.clone();
            // Диалог блокирующий — уводим его с потока цикла.
            app::runtime().spawn_blocking(move || {
                let found = match dialog::pick_image(&title) {
                    // Отказ от выбора — не событие: ни сообщения, ни ошибки.
                    None => Ok(None),
                    Some(path) => std::fs::read(&path)
                        .map_err(crate::error::AppError::from)
                        .and_then(|bytes| qr::decode_image_file(&bytes))
                        .map(Some),
                };
                handle.with_ui(move |ui| {
                    ui.global::<Ui>().set_qr_busy(false);
                    match found {
                        Ok(Some(codes)) => absorb_codes(ui, codes),
                        Ok(None) => {}
                        Err(e) => view::toast(ui, "error", &e.to_string(), ""),
                    }
                });
            });
        }
    });

    data.on_open_camera({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let global = ui.global::<Ui>();
            global.set_camera_error(slint::SharedString::new());
            global.set_camera_live(false);
            global.set_camera_expanded(false);
            global.set_camera_frame(slint::Image::default());
            global.set_modal(7);

            let handle = handle.clone();
            // Перечисление устройств поднимает Media Foundation и опрашивает
            // драйверы: на потоке цикла это заметная пауза, а окно уже открыто.
            app::runtime().spawn_blocking(move || {
                let listed = camera::list();
                let reporter = handle.clone();
                reporter.with_ui(move |ui| {
                    let global = ui.global::<Ui>();
                    // «Не удалось поднять Media Foundation» и «камеры нет» —
                    // разные новости, и делать с ними надо разное.
                    let devices = match listed {
                        Ok(devices) => devices,
                        Err(e) => {
                            global.set_camera_error(e.to_string().into());
                            return;
                        }
                    };
                    let names: Vec<slint::SharedString> =
                        devices.iter().map(|d| d.name.as_str().into()).collect();
                    let empty = devices.is_empty();
                    CAMERAS.with(|slot| *slot.borrow_mut() = devices);
                    global.set_cameras(ModelRc::new(VecModel::from(names)));
                    if empty {
                        global.set_camera_error(ui.global::<crate::Str>().get_qr_no_camera());
                        return;
                    }
                    start_camera(&handle, ui, 0);
                });
            });
        }
    });

    data.on_close_camera({
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            close_camera(&ui);
        }
    });

    data.on_next_camera({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let count = CAMERAS.with(|slot| slot.borrow().len());
            if count < 2 {
                return;
            }
            let current = ui.global::<Ui>().get_camera_index().max(0) as usize;
            // Прежняя съёмка гасится до открытия следующей: устройство камеры
            // почти всегда исключительное.
            CAMERA.with(|slot| drop(slot.borrow_mut().take()));
            start_camera(&handle, &ui, (current + 1) % count);
        }
    });

    data.on_test_latency({
        let handle = handle.clone();
        move || {
            let handle = handle.clone();
            handle.with_ui(|ui| ui.global::<Data>().set_testing(true));
            app::runtime().spawn(async move {
                let reporter = handle.clone();
                let result = api::test_latency(handle, Vec::new()).await;
                reporter.with_ui(move |ui| {
                    ui.global::<Data>().set_testing(false);
                    match result {
                        Ok(_) => {
                            let text = crate::tr(|l| l.latency_updated.clone());
                            view::toast(ui, "success", &text, "");
                        }
                        Err(e) => view::toast(ui, "error", &e.to_string(), ""),
                    }
                });
            });
        }
    });

    // ---- редактор сервера -------------------------------------------------
    data.on_new_server({
        let weak = ui.as_weak();
        let local = local.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            *local.editing.borrow_mut() = None;
            write_draft(&ui, &ServerNode::default(), true);
            ui.global::<Ui>().set_modal(2);
        }
    });

    data.on_edit_server({
        let weak = ui.as_weak();
        let local = local.clone();
        move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let node = view::with(|v| v.nodes.iter().find(|node| node.id == id.as_str()).cloned());
            let Some(node) = node else { return };
            write_draft(&ui, &node, false);
            *local.editing.borrow_mut() = Some(node);
            ui.global::<Ui>().set_modal(2);
        }
    });

    data.on_save_draft({
        let handle = handle.clone();
        let weak = ui.as_weak();
        let local = local.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let base = local.editing.borrow().clone();
            let node = read_draft(&ui, base);
            ui.global::<Ui>().set_modal(0);
            run(&handle, move |h| async move { api::update_server(h, node).await });
        }
    });

    // ---- подписки ---------------------------------------------------------
    data.on_refresh_subs({
        let handle = handle.clone();
        move || {
            let handle = handle.clone();
            handle.with_ui(|ui| ui.global::<Data>().set_refreshing(true));
            app::runtime().spawn(async move {
                let reporter = handle.clone();
                let result = api::refresh_all_subscriptions(handle).await;
                reporter.with_ui(move |ui| {
                    ui.global::<Data>().set_refreshing(false);
                    match result {
                        Ok(report) => import_toast(ui, &report),
                        Err(e) => view::toast(ui, "error", &e.to_string(), ""),
                    }
                });
            });
        }
    });

    data.on_refresh_sub({
        let handle = handle.clone();
        move |id| {
            let id = id.to_string();
            let handle = handle.clone();
            app::runtime().spawn(async move {
                let reporter = handle.clone();
                let result = api::refresh_subscription(handle, id).await;
                reporter.with_ui(move |ui| match result {
                    Ok(report) => import_toast(ui, &report),
                    Err(e) => view::toast(ui, "error", &e.to_string(), ""),
                });
            });
        }
    });

    data.on_delete_sub({
        let handle = handle.clone();
        move |id| {
            let id = id.to_string();
            run(&handle, move |h| async move { api::delete_subscription(h, id).await });
        }
    });

    // ---- раздельный туннель ----------------------------------------------
    // Заход на страницу — повод поискать иконки, которых не нашлось раньше:
    // программу, не запущенную при старте клиента, за это время могли открыть.
    data.on_refresh_icons({
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            crate::icons::forget_missing();
            crate::sync_icons(&ui);
        }
    });

    data.on_remove_app({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move |index| {
            let Some(ui) = weak.upgrade() else { return };
            let mut split = handle.state().split.read().clone();
            let index = index.max(0) as usize;
            if index >= split.apps.len() {
                return;
            }
            split.apps.remove(index);
            render_apps(&ui, &split);
            run(&handle, move |h| async move { api::set_split(h, split).await });
        }
    });

    data.on_clear_apps({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let mut split = handle.state().split.read().clone();
            split.apps.clear();
            render_apps(&ui, &split);
            run(&handle, move |h| async move { api::set_split(h, split).await });
        }
    });

    data.on_toggle_app({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move |index, enabled| {
            let Some(ui) = weak.upgrade() else { return };
            let mut split = handle.state().split.read().clone();
            let Some(rule) = split.apps.get_mut(index.max(0) as usize) else { return };
            rule.enabled = enabled;
            render_apps(&ui, &split);
            run(&handle, move |h| async move { api::set_split(h, split).await });
        }
    });

    data.on_pick_exe({
        let handle = handle.clone();
        move || {
            let handle = handle.clone();
            // Диалог блокирующий — уводим его с потока цикла.
            app::runtime().spawn_blocking(move || {
                let Some(path) = dialog::pick_executable("Выберите программу") else { return };
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let mut split = handle.state().split.read().clone();
                if split.apps.iter().any(|a| a.name.eq_ignore_ascii_case(&name)) {
                    let text = crate::tr(|l| l.already_in_list.clone());
                    handle.with_ui(move |ui| view::toast(ui, "info", &text, ""));
                    return;
                }
                split.apps.push(AppRule {
                    id: uuid::Uuid::new_v4().to_string(),
                    name,
                    path: path.to_string_lossy().to_string(),
                    enabled: true,
                });
                push_split(&handle, split);
            });
        }
    });

    data.on_load_procs({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let include_system = ui.global::<Ui>().get_proc_system();
            ui.global::<Ui>().set_proc_loading(true);
            let handle = handle.clone();
            let weak = weak.clone();
            // Перебор процессов и чтение их путей — работа для рабочего потока.
            app::runtime().spawn_blocking(move || {
                let list = procs::running_apps(include_system);
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.global::<Ui>().set_proc_loading(false);
                    PROCS.with(|procs| *procs.borrow_mut() = list);
                    render_procs(&ui, &handle);
                });
            });
        }
    });

    data.on_filter_procs({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                render_procs(&ui, &handle);
            }
        }
    });

    data.on_add_selected_procs({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let model = ui.global::<Data>().get_procs();
            let picked: Vec<crate::RunningApp> = model.iter().filter(|p| p.selected).collect();
            let ui_global = ui.global::<Ui>();
            ui_global.set_modal(0);
            ui_global.set_proc_selected(0);
            if picked.is_empty() {
                return;
            }

            let mut split = handle.state().split.read().clone();
            for proc in &picked {
                if split
                    .apps
                    .iter()
                    .any(|a| a.name.eq_ignore_ascii_case(proc.name.as_str()))
                {
                    continue;
                }
                split.apps.push(AppRule {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: proc.name.to_string(),
                    path: String::new(),
                    enabled: true,
                });
            }
            let added = picked.len();
            render_apps(&ui, &split);
            let text = crate::tr(|l| l.apps_added.replace("{n}", &added.to_string()));
            view::toast(&ui, "success", &text, "");
            push_split(&handle, split);
        }
    });

    // ---- журнал -----------------------------------------------------------
    data.on_clear_logs({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                view::render_logs(&ui, &[]);
            }
            run(&handle, |h| async move { api::clear_logs(h).await });
        }
    });

    data.on_copy_logs({
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let text = ui
                .global::<Data>()
                .get_logs()
                .iter()
                .map(|line| format!("{} {}", line.level, line.text))
                .collect::<Vec<_>>()
                .join("\n");
            match clipboard::set_text(&text) {
                Ok(()) => {
                    let text = crate::tr(|l| l.log_copied.clone());
                    view::toast(&ui, "success", &text, "");
                }
                Err(e) => view::toast(&ui, "error", &e.to_string(), ""),
            }
        }
    });

    data.on_set_log_filter({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move |_| {
            let handle = handle.clone();
            let weak = weak.clone();
            app::runtime().spawn(async move {
                let Ok(lines) = api::get_logs(handle).await else { return };
                let _ = weak.upgrade_in_event_loop(move |ui| view::render_logs(&ui, &lines));
            });
        }
    });

    // ---- настройки и служебное -------------------------------------------
    data.on_preview_config({
        let handle = handle.clone();
        move || {
            let handle = handle.clone();
            app::runtime().spawn(async move {
                let reporter = handle.clone();
                match api::preview_config(handle).await {
                    Ok(text) => reporter.with_ui(move |ui| {
                        let ui_global = ui.global::<Ui>();
                        ui_global.set_config_text(text.into());
                        ui_global.set_modal(4);
                    }),
                    Err(e) => {
                        let text = e.to_string();
                        reporter.with_ui(move |ui| view::toast(ui, "error", &text, ""));
                    }
                }
            });
        }
    });

    data.on_open_config_dir({
        let handle = handle.clone();
        move || run(&handle, |h| async move { api::open_config_dir(h).await })
    });

    data.on_relaunch_elevated({
        let handle = handle.clone();
        move || run(&handle, |h| async move { api::relaunch_elevated(h).await })
    });

    data.on_install_update({
        let handle = handle.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let url = ui.global::<Data>().get_update_url().to_string();
            if url.is_empty() {
                return;
            }
            ui.global::<Data>().set_update_busy(true);
            let handle = handle.clone();
            app::runtime().spawn(async move {
                let reporter = handle.clone();
                if let Err(e) = api::install_update(handle, url).await {
                    let text = e.to_string();
                    reporter.with_ui(move |ui| {
                        ui.global::<Data>().set_update_busy(false);
                        view::toast(ui, "error", &text, "");
                    });
                }
            });
        }
    });

    // Язык переключили: строки, собранные Rust, надо сложить заново — разметка
    // свои перечитает сама.
    data.on_relabel({
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            crate::reload_lang(&ui);
            view::render_status(&ui);
            view::render_nodes(&ui);
            view::render_subs(&ui);
            view::render_traffic(&ui);
            view::render_uptime(&ui);
            crate::shell::relabel();
        }
    });

    data.on_dismiss_toast({
        let weak = ui.as_weak();
        move |id| {
            if let Some(ui) = weak.upgrade() {
                view::dismiss_toast(&ui, id);
            }
        }
    });

    data.on_notify({
        let weak = ui.as_weak();
        move |kind, text| {
            if let Some(ui) = weak.upgrade() {
                view::toast(&ui, kind.as_str(), text.as_str(), "");
            }
        }
    });

    // Любое поле настроек изменилось: разметка сводит их в одну строку, и
    // changed срабатывает на всё сразу.
    data.on_settings_changed({
        let handle = handle.clone();
        let weak = ui.as_weak();
        let local = local.clone();
        move || {
            if local.loading.get() {
                return;
            }
            // Всё откладывается на паузу после последней правки. Автозапуск —
            // тоже: он зовёт schtasks, а поправленные им же галочки прилетают
            // сюда снова, и без паузы получался каскад попыток.
            local.save.start(slint::TimerMode::SingleShot, SAVE_DELAY, {
                let handle = handle.clone();
                let weak = weak.clone();
                move || {
                    let Some(ui) = weak.upgrade() else { return };
                    sync_autostart(&ui);
                    let current = handle.state().settings.read().clone();
                    let next = read_settings(&ui, &current);
                    if !settings_differ(&current, &next) {
                        return;
                    }
                    // Галочку только что включили — самое время завести ярлык.
                    if next.notifications && !current.notifications {
                        app::runtime().spawn_blocking(|| {
                            let _ = crate::sys::notify::ensure_registered();
                        });
                    }
                    run(&handle, move |h| async move { api::save_settings(h, next).await });
                }
            });
        }
    });

    data.on_split_changed({
        let handle = handle.clone();
        let weak = ui.as_weak();
        let local = local.clone();
        move || {
            if local.loading.get() {
                return;
            }
            let Some(ui) = weak.upgrade() else { return };
            let current = handle.state().split.read().clone();
            let next = read_split(&ui, &current);
            if !split_differs(&current, &next) {
                return;
            }
            run(&handle, move |h| async move { api::set_split(h, next).await });
        }
    });
}

/// Привести автозапуск в системе к тому, что стоит в форме.
///
/// Режим с правами регистрирует задачу планировщика, а на это нужны права
/// администратора. Без них не ругаемся впустую: включаем обычный автозапуск и
/// предлагаем перезапуск — ровно как делает переключатель рядом, когда его
/// трогают напрямую.
fn sync_autostart(ui: &AppWindow) {
    let conf = ui.global::<Conf>();
    let mut desired = if conf.get_autostart() {
        if conf.get_autostart_elevated() {
            AutostartMode::Elevated
        } else {
            AutostartMode::Normal
        }
    } else {
        AutostartMode::Off
    };

    if desired == AutostartMode::Elevated && !ui.global::<Data>().get_elevated() {
        desired = AutostartMode::Normal;
        conf.set_autostart_elevated(false);
        let ui_global = ui.global::<Ui>();
        ui_global.set_elevate_reason("autostart".into());
        ui_global.set_modal(5);
    }

    // Сверка с системой и сама правка — в рабочем потоке: schtasks поднимает
    // процесс, и на потоке интерфейса это заметная пауза.
    let weak = ui.as_weak();
    app::runtime().spawn_blocking(move || {
        if desired == autostart::current() {
            return;
        }
        let applied = autostart::apply(desired).is_ok();
        let actual = autostart::current();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            let conf = ui.global::<Conf>();
            conf.set_autostart(!matches!(actual, AutostartMode::Off));
            conf.set_autostart_elevated(matches!(actual, AutostartMode::Elevated));
            if !applied {
                let text = crate::tr(|l| l.autostart_failed.clone());
                view::toast(&ui, "error", &text, "");
            }
        });
    });
}

/// Отправить новый список правил в ядро и перерисовать строки.
fn push_split(handle: &AppHandle, split: SplitConfig) {
    let shown = split.clone();
    handle.with_ui(move |ui| render_apps(ui, &shown));
    run(handle, move |h| async move { api::set_split(h, split).await });
}

/// Список запущенных программ с учётом строки поиска и уже добавленных правил.
fn render_procs(ui: &AppWindow, handle: &AppHandle) {
    let query = ui.global::<Ui>().get_proc_query().to_lowercase();
    let added: Vec<String> = handle
        .state()
        .split
        .read()
        .apps
        .iter()
        .map(|a| a.name.to_lowercase())
        .collect();
    let rows: Vec<crate::RunningApp> = PROCS.with(|procs| procs.borrow().iter()
        .filter(|p| query.is_empty() || p.name.to_lowercase().contains(&query))
        .map(|p| crate::RunningApp {
            name: p.name.as_str().into(),
            initial: initial_of(&p.name),
            icon: Default::default(),
            path: p.path.as_str().into(),
            instances: if p.instances > 1 {
                crate::tr(|l| l.instances.replace("{count}", &p.instances.to_string())).into()
            } else {
                Default::default()
            },
            added: added.contains(&p.name.to_lowercase()),
            selected: false,
        })
        .collect());
    ui.global::<Data>().set_procs(ModelRc::new(VecModel::from(rows)));
    ui.global::<Ui>().set_proc_selected(0);
    crate::sync_icons(ui);
}

/// Итог импорта одним тостом: сколько добавилось и почему остальное — нет.
fn import_toast(ui: &AppWindow, report: &api::ImportReport) {
    if report.added == 0 {
        let text = crate::tr(|l| l.report_no_new.clone());
        let detail = report
            .errors
            .first()
            .map(|(_, why)| why.clone())
            .unwrap_or_default();
        view::toast(ui, "info", &text, &detail);
        return;
    }
    let text = crate::tr(|l| l.report_added.replace("{n}", &report.added.to_string()));
    view::toast(ui, "success", &text, "");
}

// ------------------------------------------------------- редактор сервера

fn write_draft(ui: &AppWindow, node: &ServerNode, is_new: bool) {
    let draft = ui.global::<Draft>();
    draft.set_is_new(is_new);
    draft.set_name(node.name.as_str().into());
    draft.set_protocol(PROTOCOLS.iter().position(|p| *p == node.protocol).unwrap_or(0) as i32);
    draft.set_address(node.address.as_str().into());
    draft.set_port(node.port.to_string().into());
    draft.set_uuid(node.uuid.as_str().into());
    draft.set_password(node.password.as_str().into());
    draft.set_method(node.method.as_str().into());
    draft.set_network(NETWORKS.iter().position(|n| *n == node.network).unwrap_or(0) as i32);
    draft.set_security(match node.security {
        Security::None => 0,
        Security::Tls => 1,
        Security::Reality => 2,
    });
    draft.set_path(node.path.as_str().into());
    draft.set_host(node.host.as_str().into());
    draft.set_service_name(node.service_name.as_str().into());
    draft.set_sni(node.sni.as_str().into());
    draft.set_fingerprint(node.fingerprint.as_str().into());
    draft.set_public_key(node.public_key.as_str().into());
    draft.set_short_id(node.short_id.as_str().into());
    draft.set_flow(node.flow.as_str().into());
    draft.set_allow_insecure(node.allow_insecure);
    draft.set_mux(node.mux);
}

/// Правки формы поверх исходного узла: поля, которых в форме нет (alpn,
/// encryption, ссылка подписки), должны пережить сохранение.
fn read_draft(ui: &AppWindow, base: Option<ServerNode>) -> ServerNode {
    let draft = ui.global::<Draft>();
    let mut node = base.unwrap_or_else(|| ServerNode {
        id: uuid::Uuid::new_v4().to_string(),
        ..Default::default()
    });
    if node.id.is_empty() {
        node.id = uuid::Uuid::new_v4().to_string();
    }
    node.name = draft.get_name().to_string();
    node.protocol = PROTOCOLS
        .get(draft.get_protocol().max(0) as usize)
        .copied()
        .unwrap_or_default();
    node.address = draft.get_address().to_string();
    node.port = draft.get_port().parse().unwrap_or(node.port);
    node.uuid = draft.get_uuid().to_string();
    node.password = draft.get_password().to_string();
    node.method = draft.get_method().to_string();
    // Транспорт, которого нет в списке формы (xhttp), сохраняется как был:
    // индекс её списка на него не указывает.
    if !matches!(node.network, Network::Xhttp) || draft.get_network() != 0 {
        node.network = NETWORKS
            .get(draft.get_network().max(0) as usize)
            .copied()
            .unwrap_or_default();
    }
    node.security = match draft.get_security() {
        1 => Security::Tls,
        2 => Security::Reality,
        _ => Security::None,
    };
    node.path = draft.get_path().to_string();
    node.host = draft.get_host().to_string();
    node.service_name = draft.get_service_name().to_string();
    node.sni = draft.get_sni().to_string();
    node.fingerprint = draft.get_fingerprint().to_string();
    node.public_key = draft.get_public_key().to_string();
    node.short_id = draft.get_short_id().to_string();
    node.flow = draft.get_flow().to_string();
    node.allow_insecure = draft.get_allow_insecure();
    node.mux = draft.get_mux();
    node
}

// ------------------------------------------------------- после первого кадра

thread_local! {
    /// Таймеры фонового обслуживания живут столько же, сколько окно: Timer
    /// останавливается, как только его роняют.
    static TIMERS: RefCell<Vec<slint::Timer>> = const { RefCell::new(Vec::new()) };
}

fn keep(timer: slint::Timer) {
    TIMERS.with(|timers| timers.borrow_mut().push(timer));
}

/// Всё, что делается уже с готовым интерфейсом: догнать подписки, подключиться,
/// если так настроено, и следить за релизами.
pub fn after_start(ui: &AppWindow, handle: &AppHandle) {
    let settings = handle.state().settings.read().clone();

    crate::shell::install(ui, handle);
    if settings.start_minimized && settings.close_to_tray {
        // Запуск в трей: окно прячется тем же способом, что и по крестику.
        ui.window()
            .with_winit_window(|window| window.set_visible(false));
    }

    // Задержку до текущего сервера при поднятом туннеле меряет сторож
    // балансировщика (core/balancer.rs) — он же и решает, отвечает ли сервер.

    // Уведомления Windows принимает только от приложения с ярлыком в меню
    // «Пуск»; создаём его, пока галочка включена.
    if settings.notifications {
        app::runtime().spawn_blocking(|| {
            if let Err(err) = crate::sys::notify::ensure_registered() {
                eprintln!("уведомления не зарегистрированы: {err}");
            }
        });
    }

    // Страны серверов: база скачивается один раз, дальше всё из кэша.
    {
        crate::core::geoip::drop_legacy(handle.state());
        let handle = handle.clone();
        app::runtime().spawn(async move {
            api::refresh_countries(&handle).await;
        });
    }

    // Подписки, у которых вышел срок автообновления, тянутся в фоне — список
    // серверов приедет событием, когда будет готов.
    {
        let handle = handle.clone();
        app::runtime().spawn(async move {
            api::refresh_stale_subscriptions(&handle).await;
        });
    }

    if settings.auto_connect {
        let handle = handle.clone();
        // Небольшая пауза: пусть окно успеет отрисоваться, прежде чем ядро
        // займёт процессор поднятием туннеля.
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::SingleShot,
            std::time::Duration::from_millis(400),
            move || run(&handle, |h| async move { api::connect(h).await }),
        );
        keep(timer);
    }

    // Проверка обновлений: первый заход через несколько секунд, дальше по кругу.
    let check = {
        let handle = handle.clone();
        move || {
            let handle = handle.clone();
            app::runtime().spawn(async move {
                let reporter = handle.clone();
                let Ok(found) = api::check_update(handle).await else { return };
                reporter.with_ui(move |ui| {
                    let data = ui.global::<Data>();
                    match found {
                        Some(update) => {
                            data.set_update_version(update.version.as_str().into());
                            data.set_update_url(update.url.as_str().into());
                        }
                        None => {
                            data.set_update_version("".into());
                            data.set_update_url("".into());
                        }
                    }
                });
            });
        }
    };
    let first = slint::Timer::default();
    first.start(
        slint::TimerMode::SingleShot,
        std::time::Duration::from_secs(5),
        check.clone(),
    );
    keep(first);
    let repeat = slint::Timer::default();
    repeat.start(slint::TimerMode::Repeated, UPDATE_CHECK, check);
    keep(repeat);

    // Живые цифры карточки ресурсов: своя память процесса и полный working set.
    {
        let weak = ui.as_weak();
        let mut probe = sysinfo::System::new();
        let pid = sysinfo::Pid::from_u32(std::process::id());
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(2),
            move || {
                probe.refresh_processes_specifics(
                    sysinfo::ProcessesToUpdate::Some(&[pid]),
                    true,
                    sysinfo::ProcessRefreshKind::nothing().with_memory(),
                );
                let (Some(ui), Some(process)) = (weak.upgrade(), probe.process(pid)) else {
                    return;
                };
                let data = ui.global::<Data>();
                let full = process.memory() as f64 / (1024.0 * 1024.0);
                data.set_ws_text(crate::tr(|l| format!("{full:.1} {}", l.unit(2))).into());
                let private = crate::private_working_set_mb().unwrap_or(full);
                data.set_mem_text(crate::tr(|l| format!("{private:.1} {}", l.unit(2))).into());
            },
        );
        keep(timer);
    }
}

// ---------------------------------------------------------------------- qr

/// Пауза между уходом окна и снимком: столько системе нужно, чтобы дорисовать
/// то, что было под нами. Меньше — и на снимке останется наш собственный фон.
const SCREENSHOT_DELAY: std::time::Duration = std::time::Duration::from_millis(180);

/// Размер полоски режима «считать с экрана», в точках разметки.
const SCAN_BAR: (f32, f32) = (270.0, 80.0);
/// Отступ полоски от края рабочей области.
const SCAN_BAR_MARGIN: f32 = 16.0;
/// Сколько полоска держит «код не найден», прежде чем вернуть подсказку.
const SCAN_EMPTY_LIFE: std::time::Duration = std::time::Duration::from_secs(3);

/// Уводит окно в полоску: она встаёт у правого края поверх остальных окон, а
/// сам снимок ждёт кнопки — сперва надо открыть то, где код показан.
fn enter_scan_mode(ui: &AppWindow) {
    let window = ui.window();
    // Геометрию нигде не сохраняют между запусками, поэтому вернуть её после
    // выхода из режима может только тот, кто её и забрал.
    SCAN_RETURN.with(|slot| *slot.borrow_mut() = Some((window.size(), window.position())));

    let global = ui.global::<Ui>();
    global.set_scan_empty(false);
    global.set_scan_mode(true);

    // Нижний предел снимается и напрямую: разметка его тоже опускает, но
    // ограничения едут в оконную систему своим чередом, а изменить размер
    // нужно уже сейчас.
    set_min_size(ui, SCAN_BAR);
    window.set_size(slint::LogicalSize::new(SCAN_BAR.0, SCAN_BAR.1));
    place_scan_bar(ui);
    set_topmost(ui, true);
}

/// Возвращает окно на место. Зовётся и из полоски, и снаружи — например, когда
/// приложение уходит в трей прямо из режима.
pub fn leave_scan_mode(ui: &AppWindow) {
    let global = ui.global::<Ui>();
    if !global.get_scan_mode() {
        return;
    }
    set_topmost(ui, false);
    global.set_scan_mode(false);
    global.set_scan_empty(false);
    set_min_size(ui, WINDOW_MIN);
    if let Some((size, position)) = SCAN_RETURN.with(|slot| slot.borrow_mut().take()) {
        ui.window().set_size(size);
        ui.window().set_position(position);
    }
}

/// Полоска у правого края рабочей области, по середине высоты: правый край —
/// это то место, где меньше всего шансов накрыть собой код.
fn place_scan_bar(ui: &AppWindow) {
    let Some((left, top, right, bottom)) = screen::work_area() else {
        return;
    };
    let scale = ui.window().scale_factor().max(1.0);
    let width = (SCAN_BAR.0 * scale) as i32;
    let height = (SCAN_BAR.1 * scale) as i32;
    let margin = (SCAN_BAR_MARGIN * scale) as i32;
    ui.window().set_position(slint::PhysicalPosition::new(
        (right - width - margin).max(left),
        (top + (bottom - top - height) / 2).max(top),
    ));
}

/// Наименьший размер окна, в точках разметки: те же числа, что у AppWindow.
const WINDOW_MIN: (f32, f32) = (960.0, 640.0);

/// Нижний предел размера окна. Дублирует ограничение разметки: она объявляет
/// его же, но окно ужимается здесь и сейчас, а не когда до него дойдёт очередь.
fn set_min_size(ui: &AppWindow, size: (f32, f32)) {
    use i_slint_backend_winit::winit::dpi::LogicalSize;

    ui.window().with_winit_window(|window| {
        window.set_min_inner_size(Some(LogicalSize::new(size.0 as f64, size.1 as f64)));
    });
}

/// Поверх остальных окон — иначе браузер, в который пойдут за кодом, закроет
/// собой саму кнопку.
fn set_topmost(ui: &AppWindow, on: bool) {
    use i_slint_backend_winit::winit::window::WindowLevel;

    ui.window().with_winit_window(|window| {
        window.set_window_level(if on {
            WindowLevel::AlwaysOnTop
        } else {
            WindowLevel::Normal
        });
    });
}

/// Полоске негде показать тост, поэтому «не найдено» она говорит у себя же —
/// и гасит это сама, чтобы надпись не осталась висеть над следующей попыткой.
fn flash_nothing_found(ui: &AppWindow) {
    ui.global::<Ui>().set_scan_empty(true);
    let weak = ui.as_weak();
    slint::Timer::single_shot(SCAN_EMPTY_LIFE, move || {
        if let Some(ui) = weak.upgrade() {
            ui.global::<Ui>().set_scan_empty(false);
        }
    });
}

/// Как часто разбирать кадр предпросмотра. Камера отдаёт тридцать кадров в
/// секунду, разбор каждого стоил бы ядра процессора целиком — и без всякой
/// пользы: руку с телефоном над кодом так быстро не переставляют.
const DECODE_EVERY: std::time::Duration = std::time::Duration::from_millis(120);

/// Открывает камеру под номером `index` и заводит цикл съёмки. Прежняя сессия,
/// если была, гасится вместе со своей записью здесь.
fn start_camera(handle: &AppHandle, ui: &AppWindow, index: usize) {
    let device = CAMERAS.with(|slot| slot.borrow().get(index).map(|d| d.id.clone()));
    let global = ui.global::<Ui>();
    global.set_camera_index(index as i32);
    global.set_camera_error(slint::SharedString::new());
    global.set_camera_live(false);

    let reporter = handle.clone();
    let mut next_decode = std::time::Instant::now();
    let session = camera::Session::start(device, move |event| match event {
        camera::Event::Frame(frame) => {
            let now = std::time::Instant::now();
            let found = if now >= next_decode {
                next_decode = now + DECODE_EVERY;
                qr::decode_luma(
                    frame.width as usize,
                    frame.height as usize,
                    &frame.luma,
                )
            } else {
                Vec::new()
            };
            // Код найден — снимать больше нечего.
            let keep = found.is_empty();
            let (width, height, rgb) = (frame.width, frame.height, frame.rgb);
            reporter.with_ui(move |ui| {
                // Картинка собирается здесь, а не в потоке съёмки: `Image` живёт
                // в потоке цикла и через границу потока не проходит.
                let mut buffer = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(width, height);
                buffer.make_mut_bytes().copy_from_slice(&rgb);
                let global = ui.global::<Ui>();
                global.set_camera_frame(slint::Image::from_rgb8(buffer));
                global.set_camera_live(true);
                if !found.is_empty() {
                    close_camera(ui);
                    absorb_codes(ui, found);
                }
            });
            keep
        }
        camera::Event::Failed(text) => {
            reporter.with_ui(move |ui| {
                let global = ui.global::<Ui>();
                global.set_camera_live(false);
                global.set_camera_error(text.as_str().into());
            });
            false
        }
    });
    CAMERA.with(|slot| *slot.borrow_mut() = Some(session));
}

/// Гасит камеру снаружи — окно уходит в трей, а съёмка за спиной у человека
/// не ведётся.
pub fn stop_camera(ui: &AppWindow) {
    close_camera(ui);
}

/// Гасит камеру и возвращает к окну импорта: прочитанное лежит в его поле.
fn close_camera(ui: &AppWindow) {
    CAMERA.with(|slot| drop(slot.borrow_mut().take()));
    let global = ui.global::<Ui>();
    global.set_camera_live(false);
    global.set_camera_frame(slint::Image::default());
    if global.get_modal() == 7 {
        global.set_modal(1);
    }
}

/// Прочитанные коды дописываются в поле импорта, а не импортируются сразу:
/// видно, что вышло из картинки, и можно снять второй код прежде, чем нажать
/// «Импортировать».
fn absorb_codes(ui: &AppWindow, found: Vec<String>) {
    if found.is_empty() {
        let text = crate::tr(|l| l.qr_nothing.clone());
        view::toast(ui, "info", &text, "");
        return;
    }

    // Один и тот же код на экране дважды — обычное дело: страница и её же
    // предпросмотр. В поле он должен попасть один раз.
    append_import(ui, found.iter().map(String::as_str));
    ui.global::<Ui>().set_modal(1);

    let text = if found.len() == 1 {
        crate::tr(|l| l.qr_found_one.clone())
    } else {
        crate::tr(|l| l.qr_found_many.clone()).replace("{n}", &found.len().to_string())
    };
    view::toast(ui, "success", &text, "");
}

/// Дописывает строки в поле импорта, не повторяя того, что там уже есть.
///
/// Дописывает, а не заменяет: поле может быть непустым — туда уже вставили
/// ссылку руками или прочитали первый код, — и терять это молча нельзя.
fn append_import<'a>(ui: &AppWindow, incoming: impl Iterator<Item = &'a str>) {
    let global = ui.global::<Ui>();
    let mut lines: Vec<String> = global
        .get_import_text()
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    for line in incoming {
        let line = line.trim().to_string();
        if !line.is_empty() && !lines.contains(&line) {
            lines.push(line);
        }
    }
    global.set_import_text(lines.join("\n").into());
}
