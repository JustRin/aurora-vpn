//! Перекладывает состояние ядра в модели разметки.
//!
//! Роль та же, что у store.ts плюс format.ts в веб-версии: события приходят
//! кусками (статус отдельно, узлы отдельно, задержка отдельно), а строкам на
//! экране нужны сразу несколько из них. Поэтому здесь лежит зеркало состояния,
//! события правят его, а перерисовывается только то, что от них зависит.

use std::cell::RefCell;
use std::collections::HashMap;

use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::app::Event;
use crate::core::log::LogLine;
use crate::core::geoip::Country;
use crate::model::{Network, Protocol, Security, ServerNode};
use crate::settings::Subscription;
use crate::state::{ConnState, Status, Traffic};
use crate::{tr, AppWindow, Data};

/// Зеркало того, что показано на экране. Живёт в потоке цикла — трогать его
/// можно только оттуда, и туда же приходят все события (см. AppHandle::emit).
#[derive(Default)]
pub struct View {
    pub nodes: Vec<ServerNode>,
    pub latency: HashMap<String, Option<u32>>,
    /// Адрес узла → страна. Ключ по адресу, а не по узлу: у нескольких узлов
    /// одной панели адрес обычно общий, и страна у них одна.
    pub countries: HashMap<String, Country>,
    pub subs: Vec<Subscription>,
    pub status: Status,
    pub traffic: Traffic,
    pub active_id: String,
    /// История скоростей для графика: те же отсчёты, что рисует TrafficGraph.
    pub graph: crate::Graph,
}

thread_local! {
    static VIEW: RefCell<View> = RefCell::new(View::default());
}

/// Поработать с зеркалом. Вложенные вызовы недопустимы — RefCell поймает.
pub fn with<R>(f: impl FnOnce(&mut View) -> R) -> R {
    VIEW.with(|view| f(&mut view.borrow_mut()))
}

/// Разложить событие ядра по глобалам разметки.
pub fn apply(ui: &AppWindow, event: Event) {
    match event {
        Event::Status(status) => {
            let (was, now) = with(|view| {
                let was = view.status.state;
                view.status = status;
                (was, view.status.state)
            });
            render_status(ui);
            announce(ui, was, now);
        }
        Event::Traffic(traffic) => {
            with(|view| {
                view.graph.push(&traffic);
                view.traffic = traffic;
            });
            render_traffic(ui);
        }
        Event::Log(line) => push_log(ui, line),
        Event::Nodes(nodes) => {
            with(|view| view.nodes = nodes);
            render_nodes(ui);
        }
        Event::Subscriptions(subs) => {
            with(|view| view.subs = subs);
            render_subs(ui);
        }
        Event::Latency(latency) => {
            with(|view| view.latency.extend(latency));
            render_nodes(ui);
        }
        Event::Countries(countries) => {
            with(|view| view.countries = countries);
            render_nodes(ui);
        }
        Event::UpdateProgress(progress) => {
            let data = ui.global::<Data>();
            let share = progress
                .total
                .filter(|total| *total > 0)
                .map(|total| progress.downloaded as f32 / total as f32)
                .unwrap_or(0.0);
            data.set_update_progress(share);
        }
    }
}

// ------------------------------------------------------------------ статус

pub fn render_status(ui: &AppWindow) {
    let data = ui.global::<Data>();
    with(|view| {
        let status = &view.status;
        data.set_connected(matches!(status.state, ConnState::Connected));
        data.set_elevated(status.elevated);
        data.set_state_text(state_text(status.state).into());
        data.set_active_id(status.active_id.as_str().into());
        view.active_id = status.active_id.clone();
    });
    render_active(ui);
}

/// Сообщить системе о смене состояния туннеля — если пользователь просил.
///
/// Только о переходах: одно и то же состояние, подтверждённое ядром дважды,
/// уведомлением быть не должно. «Подключение» пропускается — это ещё не
/// новость, а обещание.
fn announce(ui: &AppWindow, was: ConnState, now: ConnState) {
    if was == now || !ui.global::<crate::Conf>().get_notifications() {
        return;
    }
    let (title, body) = match now {
        // В теле — подпись выбранного сервера: она уже собрана для шапки и
        // отвечает ровно на вопрос «куда подключились».
        ConnState::Connected => (
            tr(|l| l.notify_connected.clone()),
            ui.global::<Data>().get_active_label().to_string(),
        ),
        ConnState::Disconnected => (tr(|l| l.notify_disconnected.clone()), String::new()),
        ConnState::Error => (
            tr(|l| l.notify_error.clone()),
            with(|view| view.status.message.clone()),
        ),
        ConnState::Connecting => return,
    };
    crate::sys::notify::show(&title, &body);
}

fn state_text(state: ConnState) -> String {
    tr(|l| {
        match state {
            ConnState::Disconnected => &l.state_disconnected,
            ConnState::Connecting => &l.state_connecting,
            ConnState::Connected => &l.state_connected,
            ConnState::Error => &l.state_error,
        }
        .clone()
    })
}

/// Часы аптайма. Зовётся раз в секунду отдельным таймером: время идёт само,
/// без событий от ядра.
pub fn render_uptime(ui: &AppWindow) {
    let since = with(|view| view.status.since_ms);
    let text = match since {
        Some(ms) if ms > 0 => {
            let total = (chrono::Utc::now().timestamp_millis() - ms).max(0) / 1000;
            let (h, m, s) = (total / 3600, (total % 3600) / 60, total % 60);
            if h > 0 {
                format!("{h}:{m:02}:{s:02}")
            } else {
                format!("{m:02}:{s:02}")
            }
        }
        _ => "—".into(),
    };
    ui.global::<Data>().set_uptime(text.into());
}

// ------------------------------------------------------------------ трафик

pub fn render_traffic(ui: &AppWindow) {
    let data = ui.global::<Data>();
    let width = data.get_graph_w() as f64;
    with(|view| {
        let traffic = &view.traffic;
        let per_sec = tr(|l| l.per_second.clone());
        data.set_down_rate(format!("{}{per_sec}", crate::fmt_bytes(traffic.down_speed as f64)).into());
        data.set_up_rate(format!("{}{per_sec}", crate::fmt_bytes(traffic.up_speed as f64)).into());
        data.set_conns(traffic.connections.to_string().into());
        data.set_session_total(
            crate::fmt_bytes((traffic.download + traffic.upload) as f64).into(),
        );
        data.set_session_foot(
            format!(
                "↓ {} · ↑ {}",
                crate::fmt_bytes(traffic.download as f64),
                crate::fmt_bytes(traffic.upload as f64)
            )
            .into(),
        );
        view.graph.render(&data, width);
    });
}

// ------------------------------------------------------------------- узлы

pub fn render_nodes(ui: &AppWindow) {
    let data = ui.global::<Data>();
    let rows: Vec<crate::ServerNode> = with(|view| {
        view.nodes
            .iter()
            .map(|node| {
                node_row(
                    node,
                    view.latency.get(&node.id).copied().flatten(),
                    view.countries.get(&node.address),
                )
            })
            .collect()
    });
    data.set_nodes(ModelRc::new(VecModel::from(rows)));
    render_active(ui);
}

/// Шапка «Обзора» показывает выбранный узел: искать строку в модели средствами
/// разметки нечем, поэтому имя и задержка кладутся отдельными свойствами.
fn render_active(ui: &AppWindow) {
    let data = ui.global::<Data>();
    with(|view| {
        let active = view
            .nodes
            .iter()
            .find(|node| node.id == view.active_id)
            .or_else(|| view.nodes.first());
        match active {
            Some(node) => {
                let ms = view.latency.get(&node.id).copied().flatten();
                let country = view.countries.get(&node.address);
                data.set_active_name(node.name.as_str().into());
                data.set_active_label(active_label(node, country).into());
                data.set_active_latency(latency_text(ms).into());
                data.set_active_tier(latency_tier(ms).into());
            }
            None => {
                data.set_active_name("".into());
                data.set_active_label("".into());
                data.set_active_latency("".into());
                data.set_active_tier("none".into());
            }
        }
    });
}

/// Подпись выбранного сервера: «Нидерланды · VLESS · vless-Me». Здесь страна
/// называется полностью — места хватает, а в строках списка остаётся код.
/// Пока страна не определена, кусок отпадает вместе со своим разделителем.
fn active_label(node: &ServerNode, country: Option<&Country>) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(3);
    if let Some(country) = country {
        parts.push(country_name(country));
    }
    parts.push(protocol_label(node.protocol));
    parts.push(node.name.as_str());
    parts.join(" · ")
}

/// Название страны на языке интерфейса; без перевода — код.
fn country_name(country: &Country) -> &str {
    let name = if tr(|l| l.en) { &country.en } else { &country.ru };
    if name.is_empty() {
        &country.code
    } else {
        name
    }
}

pub fn node_row(
    node: &ServerNode,
    latency: Option<u32>,
    country: Option<&Country>,
) -> crate::ServerNode {
    crate::ServerNode {
        id: node.id.as_str().into(),
        name: node.name.as_str().into(),
        proto: protocol_label(node.protocol).into(),
        transport: transport_label(node.security, node.network).into(),
        address: format!("{}:{}", node.address, node.port).into(),
        country: country.map(|c| c.code.as_str()).unwrap_or_default().into(),
        latency: latency.map(|ms| latency_text(Some(ms))).unwrap_or_else(|| "—".into()).into(),
        tier: latency_tier(latency).into(),
    }
}

fn latency_text(ms: Option<u32>) -> String {
    match ms {
        Some(ms) => tr(|l| l.latency_ms.replace("{ms}", &ms.to_string())),
        None => "—".into(),
    }
}

/// Пороги те же, что у latencyTier из format.ts: они красят точку сигнала.
pub fn latency_tier(ms: Option<u32>) -> &'static str {
    match ms {
        None => "none",
        Some(ms) if ms < 200 => "good",
        Some(ms) if ms < 500 => "ok",
        Some(_) => "bad",
    }
}

fn protocol_label(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Vless => "VLESS",
        Protocol::Vmess => "VMess",
        Protocol::Trojan => "Trojan",
        Protocol::Shadowsocks => "Shadowsocks",
        Protocol::Hysteria2 => "Hysteria2",
        Protocol::Tuic => "TUIC",
    }
}

/// `REALITY · ws` — как transportLabel из format.ts.
fn transport_label(security: Security, network: Network) -> String {
    let sec = match security {
        Security::Reality => "REALITY".to_string(),
        Security::Tls => "TLS".to_string(),
        Security::None => tr(|l| l.no_tls.clone()),
    };
    match network {
        Network::Tcp => sec,
        other => format!("{sec} · {}", other.as_xray()),
    }
}

// -------------------------------------------------------------- подписки

pub fn render_subs(ui: &AppWindow) {
    let rows: Vec<crate::SubInfo> = with(|view| view.subs.iter().map(sub_row).collect());
    ui.global::<Data>().set_subs(ModelRc::new(VecModel::from(rows)));
}

fn sub_row(sub: &Subscription) -> crate::SubInfo {
    let days = days_left(sub.expire);
    let exhausted = sub.total > 0 && sub.upload + sub.download >= sub.total;
    let warning = if days.is_some_and(|d| d < 0) {
        tr(|l| l.expired_warning.clone())
    } else if exhausted {
        tr(|l| l.exhausted_warning.clone())
    } else {
        String::new()
    };

    crate::SubInfo {
        id: sub.id.as_str().into(),
        name: sub.name.as_str().into(),
        has_usage: sub.has_usage,
        expiry: expiry_label(days).into(),
        expiry_tier: expiry_tier(days).into(),
        traffic: quota_label(sub.upload + sub.download, sub.total).into(),
        used: quota_used(sub.upload + sub.download, sub.total),
        warning: warning.into(),
        foot: sub_foot(sub).into(),
    }
}

/// «12 серверов · обновлено 5 мин назад» — подпись карточки подписки.
fn sub_foot(sub: &Subscription) -> String {
    let count = sub.node_count;
    let servers = tr(|l| plural(count as i64, &l.server_one, &l.server_few, &l.server_many).to_string());
    let when = relative_time(&sub.last_updated);
    let updated = tr(|l| l.updated_when.replace("{when}", &when));
    format!("{count} {servers} · {updated}")
}

/// Целых дней до конца тарифа; None — панель о сроке не сообщает.
fn days_left(expire_seconds: i64) -> Option<i64> {
    if expire_seconds == 0 {
        return None;
    }
    let ms = expire_seconds * 1000 - chrono::Utc::now().timestamp_millis();
    Some(ms.div_euclid(86_400_000))
}

fn expiry_label(days: Option<i64>) -> String {
    match days {
        None => tr(|l| l.no_expiry.clone()),
        Some(d) if d < 0 => tr(|l| l.expired.clone()),
        Some(0) => tr(|l| l.expires_today.clone()),
        Some(d) => {
            let forms = tr(|l| l.day_forms.clone());
            let parts: Vec<&str> = forms.split('|').collect();
            let form = |i: usize| parts.get(i).copied().unwrap_or_default();
            format!("{d} {}", plural(d, form(0), form(1), form(2)))
        }
    }
}

fn expiry_tier(days: Option<i64>) -> &'static str {
    match days {
        None => "none",
        Some(d) if d <= 3 => "bad",
        Some(d) if d <= 10 => "ok",
        Some(_) => "good",
    }
}

fn quota_used(used: u64, total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    (used as f32 / total as f32).clamp(0.0, 1.0)
}

/// `40.0 / 100 ГБ` — обе цифры в единице лимита, чтобы пара читалась одним
/// измерением и помещалась в строку.
fn quota_label(used: u64, total: u64) -> String {
    if total == 0 {
        return crate::fmt_bytes(used as f64);
    }
    let units = tr(|l| l.byte_units.clone());
    let i = ((total as f64).log2() / 10.0).floor().clamp(0.0, units.len() as f64 - 1.0) as usize;
    let scale = 1024f64.powi(i as i32);
    let show = |value: u64| {
        let scaled = value as f64 / scale;
        if scaled < 10.0 && i > 0 {
            format!("{scaled:.1}")
        } else {
            format!("{:.0}", scaled.round())
        }
    };
    format!("{} / {} {}", show(used), show(total), units[i])
}

/// «5 мин назад» по метке времени ISO-8601, как relativeTime из format.ts.
fn relative_time(iso: &str) -> String {
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(iso) else {
        return tr(|l| l.never.clone());
    };
    let seconds = (chrono::Utc::now() - then.with_timezone(&chrono::Utc)).num_seconds();
    if seconds < 60 {
        tr(|l| l.just_now.clone())
    } else if seconds < 3600 {
        tr(|l| l.min_ago.replace("{n}", &(seconds / 60).to_string()))
    } else if seconds < 86400 {
        tr(|l| l.hours_ago.replace("{n}", &(seconds / 3600).to_string()))
    } else {
        tr(|l| l.days_ago.replace("{n}", &(seconds / 86400).to_string()))
    }
}

/// Русское согласование числительных: 1 сервер, 2 сервера, 5 серверов. В
/// английском форм две, и `few` работает за общее множественное.
fn plural<'a>(n: i64, one: &'a str, few: &'a str, many: &'a str) -> &'a str {
    let abs = n.abs() % 100;
    if (11..=19).contains(&abs) {
        return many;
    }
    match abs % 10 {
        1 => one,
        2..=4 => few,
        _ => many,
    }
}

// ------------------------------------------------------------------ журнал

/// Строки журнала копятся в модели, а не пересобираются целиком: их бывает
/// несколько сотен, и полная замена на каждую новую строку заметно дороже.
pub fn push_log(ui: &AppWindow, line: LogLine) {
    let data = ui.global::<Data>();
    if !passes_filter(ui, &line) {
        return;
    }
    let model = data.get_logs();
    let Some(rows) = model.as_any().downcast_ref::<VecModel<crate::LogLine>>() else {
        return;
    };
    // Тот же потолок, что у кольцевого буфера ядра: дальше журнал листают,
    // а не читают, и держать больше нечего.
    if rows.row_count() >= 2000 {
        rows.remove(0);
    }
    rows.push(log_row(&line));
}

pub fn render_logs(ui: &AppWindow, lines: &[LogLine]) {
    let rows: Vec<crate::LogLine> = lines
        .iter()
        .filter(|line| passes_filter(ui, line))
        .map(log_row)
        .collect();
    ui.global::<Data>().set_logs(ModelRc::new(VecModel::from(rows)));
}

fn log_row(line: &LogLine) -> crate::LogLine {
    crate::LogLine {
        level: line.level.as_str().into(),
        text: line.text.as_str().into(),
    }
}

/// Фильтр журнала: 0 всё, 1 info и выше, 2 warn и выше, 3 только ошибки.
fn passes_filter(ui: &AppWindow, line: &LogLine) -> bool {
    let level = line.level.as_str();
    match ui.global::<crate::Ui>().get_log_filter() {
        1 => !matches!(level, "trace" | "debug"),
        2 => matches!(level, "warn" | "error" | "fatal" | "panic"),
        3 => matches!(level, "error" | "fatal" | "panic"),
        _ => true,
    }
}

/// Сколько живёт всплывающее сообщение. С подробностями — дольше: там есть что
/// прочитать.
const TOAST_LIFE: std::time::Duration = std::time::Duration::from_millis(4500);
const TOAST_LIFE_LONG: std::time::Duration = std::time::Duration::from_millis(8000);
/// Столько сообщение сворачивается перед тем, как уйти из модели. Должно
/// совпадать с длительностью анимации в разметке (Toast в widgets.slint).
const TOAST_FADE: std::time::Duration = std::time::Duration::from_millis(240);

/// Строка для тоста — сообщения появляются и из ядра, и из действий. Гаснет
/// сама: убирать её пользователю незачем.
pub fn toast(ui: &AppWindow, kind: &str, text: &str, detail: &str) {
    let data = ui.global::<Data>();
    let model = data.get_toasts();
    let Some(rows) = model.as_any().downcast_ref::<VecModel<crate::ToastMsg>>() else {
        return;
    };
    let id = rows.iter().map(|t| t.id).max().unwrap_or(0) + 1;
    rows.push(crate::ToastMsg {
        id,
        kind: kind.into(),
        text: SharedString::from(text),
        detail: SharedString::from(detail),
        leaving: false,
    });

    let life = if detail.is_empty() { TOAST_LIFE } else { TOAST_LIFE_LONG };
    let weak = ui.as_weak();
    slint::Timer::single_shot(life, move || {
        if let Some(ui) = weak.upgrade() {
            dismiss_toast(&ui, id);
        }
    });
}

/// Погасить сообщение: сперва взводится флаг ухода — по нему разметка
/// сворачивает карточку, — и только потом строка уходит из модели. Убрать её
/// сразу значит оборвать анимацию на первом кадре.
pub fn dismiss_toast(ui: &AppWindow, id: i32) {
    let model = ui.global::<Data>().get_toasts();
    let Some(rows) = model.as_any().downcast_ref::<VecModel<crate::ToastMsg>>() else {
        return;
    };
    // По идентификатору, а не по позиции: за это время список мог измениться.
    let Some(at) = rows.iter().position(|toast| toast.id == id) else {
        return;
    };
    let Some(row) = rows.row_data(at) else { return };
    if row.leaving {
        // Уже уходит — второй щелчок ничего не меняет.
        return;
    }
    rows.set_row_data(at, crate::ToastMsg { leaving: true, ..row });

    let weak = ui.as_weak();
    slint::Timer::single_shot(TOAST_FADE, move || {
        let Some(ui) = weak.upgrade() else { return };
        let model = ui.global::<Data>().get_toasts();
        let Some(rows) = model.as_any().downcast_ref::<VecModel<crate::ToastMsg>>() else {
            return;
        };
        if let Some(at) = rows.iter().position(|toast| toast.id == id) {
            rows.remove(at);
        }
    });
}
