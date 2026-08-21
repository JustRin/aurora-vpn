//! Aurora VPN на Slint — весь интерфейс одним нативным процессом, без
//! WebView2. Ядро (sing-box, конфиг, ссылки, настройки, системная интеграция)
//! живёт в соседних модулях: это тот же код, что раньше лежал в src-tauri/src.

#![windows_subsystem = "windows"]

slint::include_modules!();

mod api;
mod app;
mod bind;
mod core;
mod error;
mod icons;
mod link;
mod model;
mod net;
mod settings;
mod shell;
mod state;
mod store;
mod sys;
mod view;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use i_slint_backend_winit::winit::window::ResizeDirection;
// Тема системы приходит из winit; своё имя ей нужно, потому что Theme здесь
// уже занят глобалом палитры из разметки.
use i_slint_backend_winit::winit::window::Theme as SystemTheme;
use i_slint_backend_winit::WinitWindowAccessor;
use slint::Model;

/// Снимок словаря разметки (i18n.slint) для строк, которые Rust собирает
/// сам. Живёт в потоке интерфейса — всё, что его читает, крутится в том же
/// событийном цикле, а обновляет его Data.relabel() при смене языка.
#[derive(Default, Clone)]
struct Lang {
    /// Английский ли сейчас интерфейс: по нему выбирается название страны из
    /// базы, где переводы лежат рядом.
    en: bool,
    no_tls: String,
    latency_ms: String,
    na: String,
    instances: String,
    peak: String,
    per_second: String,
    byte_units: Vec<String>,
    state_connected: String,
    state_disconnected: String,
    server_deleted: String,
    link_copied: String,
    server_saved: String,
    server_added: String,
    report_no_new: String,
    report_added: String,
    already_in_list: String,
    log_copied: String,
    conns_closed: String,
    data_folder: String,
    imported: String,
    latency_updated: String,
    sub_refreshed: String,
    sub_deleted: String,
    apps_cleared: String,
    apps_added: String,
    update_demo: String,
    demo_expiry: String,
    demo_traffic: String,
    demo_foot_1: String,
    demo_sub_name: String,
    demo_foot_2: String,
    never: String,
    just_now: String,
    min_ago: String,
    hours_ago: String,
    days_ago: String,
    day_forms: String,
    no_expiry: String,
    expired: String,
    expires_today: String,
    updated_when: String,
    server_one: String,
    server_few: String,
    server_many: String,
    expired_warning: String,
    exhausted_warning: String,
    state_connecting: String,
    state_error: String,
    autostart_failed: String,
    notify_connected: String,
    notify_disconnected: String,
    notify_error: String,
    tray_show: String,
    tray_connect: String,
    tray_disconnect: String,
    tray_quit: String,
}

impl Lang {
    fn read(ui: &AppWindow) -> Self {
        let s = ui.global::<Str>();
        Self {
            en: s.get_en(),
            no_tls: s.get_fmt_no_tls().into(),
            latency_ms: s.get_srv_latency_ms().into(),
            na: s.get_dash_na().into(),
            instances: s.get_split_instances_count().into(),
            peak: s.get_graph_peak().into(),
            per_second: s.get_fmt_per_second().into(),
            byte_units: s.get_fmt_byte_units().split('|').map(String::from).collect(),
            state_connected: s.get_dash_state_connected().into(),
            state_disconnected: s.get_dash_state_disconnected().into(),
            server_deleted: s.get_srv_server_deleted().into(),
            link_copied: s.get_srv_link_copied().into(),
            server_saved: s.get_srv_server_saved().into(),
            server_added: s.get_srv_server_added().into(),
            report_no_new: s.get_srv_report_no_new().into(),
            report_added: s.get_srv_report_added().into(),
            already_in_list: s.get_split_already_in_list().into(),
            log_copied: s.get_logs_copied().into(),
            conns_closed: s.get_dash_conns_closed().into(),
            data_folder: s.get_set_data_folder().into(),
            imported: s.get_spike_imported().into(),
            latency_updated: s.get_spike_latency_updated().into(),
            sub_refreshed: s.get_spike_sub_refreshed().into(),
            sub_deleted: s.get_spike_sub_deleted().into(),
            apps_cleared: s.get_spike_apps_cleared().into(),
            apps_added: s.get_spike_apps_added().into(),
            update_demo: s.get_spike_update_demo().into(),
            demo_expiry: s.get_spike_demo_expiry().into(),
            demo_traffic: s.get_spike_demo_traffic().into(),
            demo_foot_1: s.get_spike_demo_foot_1().into(),
            demo_sub_name: s.get_spike_demo_sub_name().into(),
            demo_foot_2: s.get_spike_demo_foot_2().into(),
            never: s.get_fmt_never().into(),
            just_now: s.get_fmt_just_now().into(),
            min_ago: s.get_fmt_min_ago().into(),
            hours_ago: s.get_fmt_hours_ago().into(),
            days_ago: s.get_fmt_days_ago().into(),
            day_forms: s.get_fmt_day_forms().into(),
            no_expiry: s.get_fmt_no_expiry().into(),
            expired: s.get_fmt_expired().into(),
            expires_today: s.get_fmt_expires_today().into(),
            updated_when: s.get_srv_updated_when().into(),
            server_one: s.get_srv_server_one().into(),
            server_few: s.get_srv_server_few().into(),
            server_many: s.get_srv_server_many().into(),
            expired_warning: s.get_srv_expired_warning().into(),
            exhausted_warning: s.get_srv_exhausted_warning().into(),
            state_connecting: s.get_dash_state_connecting().into(),
            state_error: s.get_dash_state_error().into(),
            autostart_failed: s.get_set_autostart_failed().into(),
            notify_connected: s.get_notify_connected_title().into(),
            notify_disconnected: s.get_notify_disconnected_title().into(),
            notify_error: s.get_notify_error_title().into(),
            tray_show: s.get_tray_show().into(),
            tray_connect: s.get_tray_connect().into(),
            tray_disconnect: s.get_tray_disconnect().into(),
            tray_quit: s.get_tray_quit().into(),
        }
    }

    /// Единица из fmt.byteUnits: «Б|КБ|МБ|ГБ|ТБ» одной строкой, как в вебе.
    fn unit(&self, i: usize) -> &str {
        self.byte_units.get(i).map(String::as_str).unwrap_or("")
    }
}

thread_local! {
    static LANG: RefCell<Lang> = RefCell::new(Lang::default());
}

/// Строка из снимка словаря.
fn tr<R>(pick: impl FnOnce(&Lang) -> R) -> R {
    LANG.with(|lang| pick(&lang.borrow()))
}

/// Перечитать словарь после смены языка.
fn reload_lang(ui: &AppWindow) {
    LANG.with(|lang| *lang.borrow_mut() = Lang::read(ui));
}

/// Пересобрать амбиент-слой под текущий размер окна и палитру.
///
/// Заодно это единственный дешёвый способ пометить грязным всё окно: слой
/// растянут на него целиком, и подмена картинки заставляет перерисовать кадр
/// полностью. Тем и пользуется возврат из трея (shell::show).
fn repaint_ambient(ui: &AppWindow) {
    let size = ui.window().size();
    if size.width == 0 || size.height == 0 {
        return;
    }
    let theme = ui.global::<Theme>();
    let glows = [theme.get_glow_a(), theme.get_glow_b(), theme.get_glow_c()];
    ui.set_ambient(ambient_image(size.width, size.height, theme.get_bg(), glows));
}

/// Сторона аватарки в физических пикселях: разметка отводит под неё 30 точек,
/// а иконка должна прийти ровно в тех пикселях, которыми будет нарисована.
fn icon_px(scale: f32) -> u32 {
    (30.0 * scale).round().clamp(16.0, 256.0) as u32
}

/// Раздаёт строкам обоих списков иконки, которые уже добыты, и ставит в
/// очередь те, которых в кэше ещё нет. Зовётся после каждой перестройки
/// списков и из потока-добытчика, когда он приносит очередную пачку.
fn sync_icons(ui: &AppWindow) {
    let size = icon_px(ui.window().scale_factor());
    let data = ui.global::<Data>();

    // Сравнение со стороной, а не с нулём: после переезда окна на монитор с
    // другим масштабом строке нужна иконка в других пикселях.
    let apps = data.get_apps();
    for i in 0..apps.row_count() {
        let Some(row) = apps.row_data(i) else { continue };
        if row.icon.size().width == size {
            continue;
        }
        if let Some(icon) = icons::get(&row.name, &row.path, size) {
            apps.set_row_data(i, AppRule { icon, ..row });
        }
    }

    let procs = data.get_procs();
    for i in 0..procs.row_count() {
        let Some(row) = procs.row_data(i) else { continue };
        if row.icon.size().width == size {
            continue;
        }
        if let Some(icon) = icons::get(&row.name, &row.path, size) {
            procs.set_row_data(i, RunningApp { icon, ..row });
        }
    }
}

/// Иконка окна — та, что видно в панели задач и в Alt-Tab. Пиксели разобраны
/// на сборке (build.rs) и лежат в бинаре готовыми, поэтому декодера PNG в нём
/// нет.
///
/// Ставится в обход разметки. Свойство `icon` у Window в Slint 1.17 доезжает
/// до winit только если у картинки есть ключ кэша, а у собранной в памяти
/// (`Image::from_rgba8`) он `Invalid`, то есть `None` — ровно то значение, с
/// которым поле заводится. Проверка «иконка изменилась?» не срабатывает ни
/// разу, и `set_window_icon` не зовётся вообще (i-slint-backend-winit,
/// winitwindowadapter.rs, `apply_window_properties`).
///
/// Иконка в ресурсах .exe (build.rs) тут не помогает: класс окна winit заводит
/// с `hIcon: 0`, и на кнопке в панели задач оказывается системная заглушка.
fn window_icon() -> Option<i_slint_backend_winit::winit::window::Icon> {
    const SIDE: u32 = 128;
    const PIXELS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/app-icon.rgba"));

    i_slint_backend_winit::winit::window::Icon::from_rgba(PIXELS.to_vec(), SIDE, SIDE).ok()
}

fn main() -> Result<(), slint::PlatformError> {
    // Включённый «запуск сразу с правами администратора» означает задачу
    // планировщика, которая поднимает это же приложение с правами и без UAC.
    // Обычный щелчок по ярлыку передаёт запуск ей: иначе с включённой галочкой
    // пользователь каждый раз открывал бы неповышенный экземпляр, который
    // первым делом просит перезапуститься.
    if shell::hand_off_to_elevated_task() {
        return Ok(());
    }

    // Второй запуск не поднимает второе ядро: он просит работающий экземпляр
    // показать окно и уходит. Иначе два процесса подрались бы за виртуальный
    // адаптер и за одну и ту же папку настроек.
    if !shell::claim_single_instance() {
        return Ok(());
    }

    // Программный рендер: GL-контекст видеодрайвера один стоит ~120 МБ, а
    // статичному интерфейсу из панелей и тумблеров он не нужен.
    // (25 МБ working set против 145 МБ с femtovg/GL на этой машине.)
    if std::env::var_os("SLINT_BACKEND").is_none() {
        std::env::set_var("SLINT_BACKEND", "winit-software");
    }

    let ui = AppWindow::new()?;
    {
        let theme = ui.global::<Theme>();
        theme.set_ui_font(ui_font().into());
        theme.set_mono_font(mono_font().into());
    }

    // Иконки программ добываются на отдельном потоке; сюда он стучится, когда
    // очередная пачка готова, — строки списков забирают её из кэша.
    icons::init({
        let weak = ui.as_weak();
        move || {
            let _ = weak.upgrade_in_event_loop(|ui| sync_icons(&ui));
        }
    });

    // Язык системы — для «как в системе». Читается один раз: локаль в живой
    // сессии Windows не меняется. Снимок словаря снимается сразу после, до
    // того как соберутся модели: в них строки попадают уже готовыми.
    ui.global::<Conf>().set_system_en(!system_locale_is_ru());
    LANG.with(|lang| *lang.borrow_mut() = Lang::read(&ui));

    // Ambient-слой переснимается только на новый физический размер окна:
    // changed width/height в разметке дёргает колбэк на каждую сторону, а
    // размер окна меняется один раз на обе.
    ui.on_ambient_resize({
        let weak = ui.as_weak();
        // Палитра в ключе рядом с размером: смена темы меняет цвета слоя при
        // том же окне, и без неё повторный заход отсеялся бы как лишний.
        let last = Rc::new(std::cell::Cell::new((0u32, 0u32, -1i32)));
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let size = ui.window().size();
            let theme = ui.global::<Theme>();
            let key = (size.width, size.height, theme.get_variant());
            if size.width == 0 || size.height == 0 || last.get() == key {
                return;
            }
            last.set(key);
            repaint_ambient(&ui);
            // Заодно первый заход за иконками: до показа окна winit ещё не
            // знает масштаб монитора и отдаёт единицу, а здесь размер уже
            // настоящий — как и всё, что из него считается.
            sync_icons(&ui);
        }
    });

    // «Как в системе»: Windows меняет тему на ходу, в том числе по своему
    // расписанию светлой и тёмной. WindowEvent::ThemeChanged до разметки не
    // доходит, поэтому опрос — winit держит текущую тему у себя, и чтение
    // стоит одного сравнения. Первый заход до показа окна ещё не видит HWND и
    // отвечает «тёмная»; через две секунды таймер поправит.
    let system_theme_timer = slint::Timer::default();
    {
        let weak = ui.as_weak();
        let sync = move || {
            let Some(ui) = weak.upgrade() else { return };
            let dark = ui
                .window()
                .with_winit_window(|window| window.theme() != Some(SystemTheme::Light))
                .unwrap_or(true);
            let conf = ui.global::<Conf>();
            if conf.get_system_dark() != dark {
                conf.set_system_dark(dark);
            }
        };
        sync();
        system_theme_timer.start(slint::TimerMode::Repeated, Duration::from_secs(2), sync);
    }

    // Иконка и скругление углов — всё, что делается по живому окну. Win11
    // скругляет только окна с системной рамкой; безрамочному надо попросить
    // скругление у DWM самому — иначе углы остаются острыми. Winit
    // материализует HWND лишь после старта событийного цикла, и одна
    // отложенная попытка легко приходит слишком рано — таймер повторяет
    // вызов, пока DWM не ответит S_OK по настоящему окну, и тогда замолкает.
    let dressed = Rc::new(std::cell::Cell::new(false));
    let dress_window = move |window: &i_slint_backend_winit::winit::window::Window| {
        // Иконку хватает поставить один раз, скругление может потребовать
        // ещё нескольких заходов.
        if !dressed.replace(true) {
            window.set_window_icon(window_icon());
        }
        round_window_corners(window)
    };
    ui.window().with_winit_window(&dress_window);
    let round_timer = std::rc::Rc::new(slint::Timer::default());
    {
        let weak = ui.as_weak();
        // Weak, а не clone: замыкание живёт внутри самого таймера, и сильная
        // ссылка замкнула бы его на себя.
        let timer = std::rc::Rc::downgrade(&round_timer);
        round_timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(50),
            move || {
                let Some(ui) = weak.upgrade() else { return };
                if ui.window().with_winit_window(&dress_window) == Some(true) {
                    if let Some(timer) = timer.upgrade() {
                        timer.stop();
                    }
                }
            },
        );
    }

    // ---- своя шапка: системные кнопки и перетаскивание --------------------
    ui.on_minimize({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.window().set_minimized(true);
            }
        }
    });
    ui.on_toggle_maximize({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                let window = ui.window();
                window.set_maximized(!window.is_maximized());
            }
        }
    });
    ui.on_close_window({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                shell::on_close(&ui);
            }
        }
    });
    ui.on_start_move({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.window().with_winit_window(|window| {
                    let _ = window.drag_window();
                });
            }
        }
    });
    ui.on_start_resize({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.window().with_winit_window(|window| {
                    let _ = window.drag_resize_window(ResizeDirection::SouthEast);
                });
            }
        }
    });

    // ---- ядро и обработчики ----------------------------------------------
    // Всё, что дальше знает про sing-box, живёт в bind.rs: он поднимает
    // состояние, раскладывает снимок по глобалам и подключает колбэки.
    let handle = match bind::install(&ui) {
        Ok(handle) => handle,
        Err(err) => {
            // Без ядра приложение бесполезно, но окно всё равно показываем: в
            // нём видно, чего не хватает.
            let text = err.to_string();
            let weak = ui.as_weak();
            slint::Timer::single_shot(Duration::from_millis(200), move || {
                if let Some(ui) = weak.upgrade() {
                    view::toast(&ui, "error", &text, "");
                }
            });
            return ui.run();
        }
    };
    let data = ui.global::<Data>();


    // Ширина графика изменилась — пути пересобираются в том же кадре, иначе
    // до следующего отсчёта график рисуется в чужом масштабе.
    data.on_regen({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                view::render_traffic(&ui);
            }
        }
    });

    // Часы аптайма идут сами: ядро о них не сообщает, оно отдаёт лишь момент
    // подключения.
    let weak = ui.as_weak();
    let uptime_timer = slint::Timer::default();
    uptime_timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(1),
        move || {
            if let Some(ui) = weak.upgrade() {
                view::render_uptime(&ui);
            }
        },
    );

    // Дыхание хало кнопки: 10 к/с достаточно для пульса с периодом 4 с, а
    // перерисовки становятся в шесть раз реже, чем при animation-tick().
    let weak = ui.as_weak();
    let breath_timer = slint::Timer::default();
    let breath_started = Instant::now();
    breath_timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(100),
        move || {
            if let Some(ui) = weak.upgrade() {
                let data = ui.global::<Data>();
                if data.get_connected() {
                    let phase = breath_started.elapsed().as_secs_f32() / 4.0;
                    data.set_breath((phase * std::f32::consts::TAU).sin());
                }
            }
        },
    );

    ui.show()?;
    // Интерфейс собран — можно досылать всё, что делается после первого кадра.
    bind::after_start(&ui, &handle);

    // Не ui.run(): тот заканчивается, как только закрылось последнее окно, —
    // и сворачивание в трей закрывало приложение вместо того, чтобы спрятать
    // его. Значок в трее держит сторонний крейт, Slint про него не знает,
    // поэтому цикл живёт до явного quit_event_loop() — из меню трея или из
    // крестика, когда сворачивать в трей не просили.
    let result = slint::run_event_loop_until_quit();

    // Выход из цикла — это выход приложения: туннель надо опустить, а системный
    // прокси вернуть на место, пока процесс ещё жив.
    shell::shutdown(&handle);
    result
}

/// История скоростей для графика «Обзора». Отсчёты приходят из ядра раз в
/// секунду, а геометрия повторяет TrafficGraph.tsx: те же координаты, то же
/// скругление низа карточки.
#[derive(Default)]
pub struct Graph {
    down: std::collections::VecDeque<f64>,
    up: std::collections::VecDeque<f64>,
}

impl Graph {
    /// Как в TrafficGraph.tsx: буфер на минуту, сверху воздух под легенду.
    /// Координаты генерируются в пикселях элемента (высота фиксированная 72,
    /// ширину сообщает слой Slint через graph-w).
    const CAPACITY: usize = 60;
    const HEIGHT: f64 = 72.0;
    const PAD_TOP: f64 = 14.0;
    const PAD_BOTTOM: f64 = 1.0;
    /// Радиус нижних углов карточки. `clip` софтверного рендера умеет только
    /// прямоугольник (скруглённый — TODO в i-slint-renderer-software), а
    /// закрывать вылезшее заплаткой цвета фона нельзя: под полупрозрачной
    /// карточкой лежит амбиентное свечение, и плоская заливка выдаёт себя
    /// тёмным уголком. Поэтому скругление вносится в сами пути.
    const RADIUS: f64 = 16.0;

    /// Нижняя граница скруглённого низа карточки в точке `x`: у краёв она
    /// поднимается по дуге, в середине совпадает с низом графика.
    fn bottom_limit(x: f64, width: f64) -> f64 {
        let r = Self::RADIUS;
        let dx = if x < r {
            r - x
        } else if x > width - r {
            x - (width - r)
        } else {
            0.0
        };
        Self::HEIGHT - r + (r * r - dx * dx).max(0.0).sqrt()
    }

    /// Точка пересечения отрезка `a`→`b` с этой границей: половинным делением,
    /// чтобы линия обрывалась ровно на дуге, а не на ближайшем отсчёте.
    fn crossing(a: (f64, f64), b: (f64, f64), width: f64) -> (f64, f64) {
        let at = |t: f64| (a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t);
        let inside = |t: f64| {
            let (x, y) = at(t);
            y <= Self::bottom_limit(x, width)
        };
        let a_inside = inside(0.0);
        let (mut lo, mut hi) = (0.0f64, 1.0f64);
        for _ in 0..14 {
            let mid = 0.5 * (lo + hi);
            if inside(mid) == a_inside {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        at(0.5 * (lo + hi))
    }

    /// Заполнить историю нулями: до первого отсчёта график должен быть ровной
    /// линией по низу, а не одной ступенью.
    pub fn prefill(&mut self) {
        self.down = std::collections::VecDeque::from(vec![0.0; Self::CAPACITY]);
        self.up = self.down.clone();
    }

    /// Очередной отсчёт из поллера ядра. Пока туннель опущен, приходят нули —
    /// график оседает сам собой.
    pub fn push(&mut self, traffic: &crate::state::Traffic) {
        if self.down.len() == Self::CAPACITY {
            self.down.pop_front();
            self.up.pop_front();
        }
        self.down.push_back(traffic.down_speed as f64);
        self.up.push_back(traffic.up_speed as f64);
    }

    /// Отсчёты в координатах элемента, как toPath из TrafficGraph.tsx.
    fn points(
        values: &std::collections::VecDeque<f64>,
        peak: f64,
        width: f64,
    ) -> Vec<(f64, f64)> {
        let usable = Self::HEIGHT - Self::PAD_TOP - Self::PAD_BOTTOM;
        let step = width / (values.len().max(2) - 1) as f64;
        values
            .iter()
            .enumerate()
            .map(|(i, value)| {
                (
                    i as f64 * step,
                    Self::HEIGHT - Self::PAD_BOTTOM - value / peak * usable,
                )
            })
            .collect()
    }

    /// Линия, обрезанная скруглением: в углах она обрывается на дуге и
    /// продолжается новым подпутём, а не загибается вверх вслед за границей.
    fn line(points: &[(f64, f64)], width: f64) -> String {
        let inside = |p: (f64, f64)| p.1 <= Self::bottom_limit(p.0, width);
        let mut out = String::with_capacity(points.len() * 16);
        let mut pen = false;
        for (i, &p) in points.iter().enumerate() {
            let here = inside(p);
            if i > 0 {
                let prev = points[i - 1];
                if inside(prev) != here {
                    let (cx, cy) = Self::crossing(prev, p, width);
                    out.push_str(&format!("{}{cx:.1},{cy:.1} ", if here { "M" } else { "L" }));
                    pen = here;
                }
            }
            if here {
                out.push_str(&format!("{}{:.1},{:.1} ", if pen { "L" } else { "M" }, p.0, p.1));
                pen = true;
            }
        }
        out
    }

    /// Заливка под линией. Верхняя кромка прижата к той же границе (в углу
    /// высота заливки просто сходит на нет), низ замкнут дугами радиуса 16 —
    /// поэтому фигура сразу рождается со скруглёнными нижними углами.
    fn area(points: &[(f64, f64)], width: f64) -> String {
        let r = Self::RADIUS;
        let h = Self::HEIGHT;
        let mut out = String::with_capacity(points.len() * 16 + 96);
        for (i, &(x, y)) in points.iter().enumerate() {
            let y = y.min(Self::bottom_limit(x, width));
            out.push_str(&format!("{}{x:.1},{y:.1} ", if i == 0 { "M" } else { "L" }));
        }
        out.push_str(&format!(
            "L{width:.1},{top:.1} A {r} {r} 0 0 1 {right:.1},{h} L {r},{h} A {r} {r} 0 0 1 0,{top:.1} Z",
            top = h - r,
            right = width - r,
        ));
        out
    }

    /// Пути графика и подпись пика. Скорости и итоги пишет view.rs — они
    /// приходят тем же событием, но живут в других плитках.
    pub fn render(&self, data: &Data, width: f64) {
        let width = width.max(300.0);
        let peak = self
            .down
            .iter()
            .chain(self.up.iter())
            .fold(64.0 * 1024.0, |a: f64, &b| a.max(b));

        let down = Self::points(&self.down, peak, width);
        let up = Self::points(&self.up, peak, width);
        data.set_graph_down_area(Self::area(&down, width).into());
        data.set_graph_up_area(Self::area(&up, width).into());
        data.set_graph_down_line(Self::line(&down, width).into());
        data.set_graph_up_line(Self::line(&up, width).into());

        let per_sec = tr(|l| l.per_second.clone());
        data.set_peak(tr(|l| format!("{} {}{per_sec}", l.peak, fmt_bytes(peak))).into());
    }
}

/// «3.2 МБ» в духе format.ts: больше точности там, где она помещается.
fn fmt_bytes(value: f64) -> String {
    if value <= 0.0 {
        return tr(|l| format!("0 {}", l.unit(0)));
    }
    let i = (value.log2() / 10.0).floor().min(4.0).max(0.0) as usize;
    let scaled = value / 1024f64.powi(i as i32);
    tr(|l| {
        if i == 0 {
            format!("{scaled:.0} {}", l.unit(i))
        } else if scaled < 10.0 {
            format!("{scaled:.2} {}", l.unit(i))
        } else {
            format!("{scaled:.1} {}", l.unit(i))
        }
    })
}

/// Ambient-слой одной непрозрачной картинкой: фон окна и три пятна подсветки,
/// геометрия которых описана в app.slint.
///
/// Считается на каждый новый размер окна и от содержимого не зависит. Формулы
/// повторяют софтверный рендер Slint дословно — радиус по умолчанию равен
/// половине диагонали бокса (brush.rs, radius_or_default_scaled), цвет между
/// стопами интерполируется без предумножения, и только потом предумножается и
/// смешивается с фоном (draw_functions.rs) — чтобы картинка совпала с прежней
/// отрисовкой.
fn ambient_image(w: u32, h: u32, bg: slint::Color, glows: [slint::Color; 3]) -> slint::Image {
    // Геометрия пятен: центр в долях окна и бокс градиента в долях окна —
    // копия трёх Glow из app.slint. Цвета (Theme.bg, Theme.glow-a/b/c)
    // приходят из текущей палитры.
    const PLACES: [([f32; 2], [f32; 2]); 3] = [
        ([0.08, 0.035], [1.26, 1.38]),
        ([0.95, 0.11], [1.08, 1.20]),
        ([0.44, 0.86], [1.56, 1.38]),
    ];
    let bg: [u8; 3] = [bg.red(), bg.green(), bg.blue()];
    let spots: [([f32; 2], [f32; 2], [u8; 4]); 3] = std::array::from_fn(|i| {
        let c = glows[i];
        (PLACES[i].0, PLACES[i].1, [c.red(), c.green(), c.blue(), c.alpha()])
    });
    // Последний стоп градиента: дальше него пятно полностью прозрачно.
    const EDGE: f32 = 0.62;
    // Пятна размыты так, что соседние пиксели отличаются на 0–1/255, поэтому
    // картинку держим вдвое мельче окна и растягиваем (image-fit: fill).
    // Памяти это стоит вчетверо меньше — 0.6 МБ вместо 2.5 на окне 1120×760, —
    // а ступеньки растяжения не шире тех, что и так даёт квантование в 1/255.
    // Потолок в 4096 — страховка от нелепого размера окна: без него буфер
    // считается прямо от того, что пришло из системы.
    const SHRINK: u32 = 2;
    const MAX_SIDE: u32 = 4096;

    let w = (w / SHRINK).clamp(1, MAX_SIDE);
    let h = (h / SHRINK).clamp(1, MAX_SIDE);
    let (fw, fh) = (w as f32, h as f32);
    let spots: Vec<(f32, f32, f32, f32, [u8; 4])> = spots
        .iter()
        .map(|(center, box_size, color)| {
            let (bw, bh) = (box_size[0] * fw, box_size[1] * fh);
            let radius = 0.5 * (bw * bw + bh * bh).sqrt();
            // Радиус видимой части — чтобы не считать корень там, где пятна нет.
            (center[0] * fw, center[1] * fh, radius, (radius * EDGE).powi(2), *color)
        })
        .collect();

    let mut buffer = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(w, h);
    let pixels = buffer.make_mut_slice();
    for y in 0..h {
        for x in 0..w {
            let (mut r, mut g, mut b) = (bg[0], bg[1], bg[2]);
            for (cx, cy, radius, edge_sq, color) in &spots {
                let (dx, dy) = (x as f32 - cx, y as f32 - cy);
                let distance_sq = dx * dx + dy * dy;
                if distance_sq >= *edge_sq {
                    continue;
                }
                // Доля пути до последнего стопа: на нём пятно сходит на нет.
                let t = (distance_sq.sqrt() / radius) / EDGE;
                let k = 1.0 - t;
                let alpha = (k * color[3] as f32) as u16;
                let mix = |c: u8, dst: u8| {
                    let src = (k * c as f32) as u16 * alpha / 255;
                    (dst as u16 * (255 - alpha) / 255) as u8 + src as u8
                };
                r = mix(color[0], r);
                g = mix(color[1], g);
                b = mix(color[2], b);
            }
            pixels[(y * w + x) as usize] = slint::Rgb8Pixel { r, g, b };
        }
    }
    slint::Image::from_rgb8(buffer)
}

/// Русская ли локаль у пользователя. Правило то же, что у resolveLang в
/// i18n.ts: русский — только для локалей, начинающихся на ru.
#[cfg(windows)]
fn system_locale_is_ru() -> bool {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
    // LOCALE_NAME_MAX_LENGTH; функция возвращает длину вместе с нулём.
    let mut buffer = [0u16; 85];
    let len = unsafe { GetUserDefaultLocaleName(buffer.as_mut_ptr(), buffer.len() as i32) };
    if len <= 1 {
        return false;
    }
    String::from_utf16_lossy(&buffer[..len as usize - 1])
        .to_ascii_lowercase()
        .starts_with("ru")
}

#[cfg(not(windows))]
fn system_locale_is_ru() -> bool {
    false
}

/// Установлен ли шрифт — по файлу в системной папке: перебирать семейства
/// через DirectWrite ради двух проверок незачем, а имена файлов у обоих
/// постоянные.
#[cfg(windows)]
fn font_installed(file: &str) -> bool {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    std::path::Path::new(&root).join("Fonts").join(file).exists()
}

/// Первое доступное семейство из стека body (styles.css). Вариативный Segoe
/// появился только в Windows 11; без подмены fontique на Windows 10 ушёл бы в
/// свой generic sans-serif — в Arial, а не в статический Segoe UI.
#[cfg(windows)]
fn ui_font() -> &'static str {
    if font_installed("SegUIVar.ttf") {
        "Segoe UI Variable Display"
    } else {
        "Segoe UI"
    }
}

/// То же для стека .log-view: Cascadia Mono приезжает с Windows 11 (и с
/// Терминалом), Consolas есть всегда.
#[cfg(windows)]
fn mono_font() -> &'static str {
    if font_installed("CascadiaMono.ttf") {
        "Cascadia Mono"
    } else {
        "Consolas"
    }
}

#[cfg(not(windows))]
fn ui_font() -> &'static str {
    ""
}

#[cfg(not(windows))]
fn mono_font() -> &'static str {
    ""
}

/// `DWMWA_WINDOW_CORNER_PREFERENCE = DWMWCP_ROUND`: композитор Windows 11
/// обрезает окно по скруглённому прямоугольнику и рисует системную кромку —
/// то же, что получает Tauri-версия со своей безрамочной шапкой.
/// Возвращает true только после S_OK — сигнал повторяющему таймеру замолчать.
#[cfg(windows)]
fn round_window_corners(window: &i_slint_backend_winit::winit::window::Window) -> bool {
    use i_slint_backend_winit::winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND,
        DWM_WINDOW_CORNER_PREFERENCE,
    };

    let Ok(handle) = window.window_handle() else {
        return false;
    };
    let RawWindowHandle::Win32(win32) = handle.as_raw() else {
        return false;
    };
    let hwnd = win32.hwnd.get() as *mut std::ffi::c_void;
    let preference: DWM_WINDOW_CORNER_PREFERENCE = DWMWCP_ROUND;
    unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            &preference as *const DWM_WINDOW_CORNER_PREFERENCE as *const std::ffi::c_void,
            std::mem::size_of::<DWM_WINDOW_CORNER_PREFERENCE>() as u32,
        ) == 0
    }
}

#[cfg(not(windows))]
fn round_window_corners(_window: &i_slint_backend_winit::winit::window::Window) -> bool {
    true
}

/// Своя (приватная) память процесса — ровно та цифра, что колонка «Память»
/// в диспетчере задач: без разделяемых системных DLL.
#[cfg(windows)]
fn private_working_set_mb() -> Option<f64> {
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX2,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS_EX2 = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32;
        let ok = K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters as *mut _ as *mut PROCESS_MEMORY_COUNTERS,
            counters.cb,
        );
        if ok == 0 {
            return None;
        }
        Some(counters.PrivateWorkingSetSize as f64 / (1024.0 * 1024.0))
    }
}

#[cfg(not(windows))]
fn private_working_set_mb() -> Option<f64> {
    None
}
