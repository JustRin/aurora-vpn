//! Мост между `stats::StatsRecorder` и Slint-страницей расширенной статистики.
//!
//! Держит кэш последнего `StatsReport` в потоке интерфейса, чтобы наведение
//! мышью по графику (Argus scrubbing) отрабатывало за микросекунды без обращений
//! к диску, а клик закреплял момент и сразу показывал приложения в эту секунду.

use std::cell::RefCell;
use std::collections::HashMap;

use chrono::{DateTime, Local, TimeZone};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::api;
use crate::app::AppHandle;
use crate::stats::{
    AppStats, ChartPoint, ServerStats, SessionRecord, StatsQuery, StatsRange, StatsReport,
    StorageInfo,
};
use crate::{fmt_bytes, tr, view, AppWindow, Stats, Ui};

const CHART_H: f64 = 168.0;
const PAD_TOP: f64 = 18.0;
const PAD_BOTTOM: f64 = 10.0;

#[derive(Default)]
struct StatsUiState {
    range: StatsRange,
    custom_from: Option<i64>,
    custom_to: Option<i64>,
    metric: i32,
    server_id: Option<String>,
    server_ids: Vec<String>,
    app_key: Option<String>,
    route_filter: i32,
    app_search: String,
    pinned_idx: Option<usize>,
    hovered_idx: Option<usize>,
    report: StatsReport,
}

thread_local! {
    static STATE: RefCell<StatsUiState> = RefCell::new(StatsUiState::default());
}

fn range_from_idx(idx: i32) -> StatsRange {
    match idx {
        1 => StatsRange::Hour1,
        2 => StatsRange::Hours24,
        3 => StatsRange::Days7,
        4 => StatsRange::Days30,
        5 => StatsRange::Custom,
        _ => StatsRange::Session,
    }
}

pub fn wire(ui: &AppWindow, handle: &AppHandle) {
    let stats = ui.global::<Stats>();

    stats.on_open_page({
        let weak = ui.as_weak();
        let handle = handle.clone();
        move |tab| {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<Ui>().set_page(0);
            let s = ui.global::<Stats>();
            s.set_tab(tab.clamp(0, 2));
            s.set_open(true);
            refresh(&ui, &handle);
        }
    });

    stats.on_close_page({
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<Stats>().set_open(false);
        }
    });

    stats.on_refresh({
        let weak = ui.as_weak();
        let handle = handle.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                if ui.global::<Stats>().get_open() {
                    refresh(&ui, &handle);
                }
            }
        }
    });

    stats.on_set_range({
        let weak = ui.as_weak();
        let handle = handle.clone();
        move |idx| {
            let Some(ui) = weak.upgrade() else { return };
            STATE.with(|st| {
                let mut st = st.borrow_mut();
                st.range = range_from_idx(idx);
                if st.range != StatsRange::Custom {
                    st.custom_from = None;
                    st.custom_to = None;
                }
                st.pinned_idx = None;
                st.hovered_idx = None;
            });
            refresh(&ui, &handle);
        }
    });

    stats.on_set_metric({
        let weak = ui.as_weak();
        move |metric| {
            let Some(ui) = weak.upgrade() else { return };
            STATE.with(|st| st.borrow_mut().metric = metric.clamp(0, 2));
            render_chart_and_cursor(&ui);
        }
    });

    stats.on_set_server_filter({
        let weak = ui.as_weak();
        let handle = handle.clone();
        move |idx| {
            let Some(ui) = weak.upgrade() else { return };
            STATE.with(|st| {
                let mut st = st.borrow_mut();
                let picked = st
                    .server_ids
                    .get(idx.max(0) as usize)
                    .filter(|id| !id.is_empty())
                    .cloned();
                st.server_id = picked;
                st.pinned_idx = None;
                st.hovered_idx = None;
            });
            refresh(&ui, &handle);
        }
    });

    stats.on_set_route_filter({
        let weak = ui.as_weak();
        move |route| {
            let Some(ui) = weak.upgrade() else { return };
            STATE.with(|st| st.borrow_mut().route_filter = route.clamp(0, 2));
            render_apps_list(&ui);
        }
    });

    stats.on_set_app_search({
        let weak = ui.as_weak();
        move |text| {
            let Some(ui) = weak.upgrade() else { return };
            STATE.with(|st| st.borrow_mut().app_search = text.to_lowercase());
            render_apps_list(&ui);
        }
    });

    stats.on_toggle_app({
        let weak = ui.as_weak();
        let handle = handle.clone();
        move |key| {
            let Some(ui) = weak.upgrade() else { return };
            let key_str = key.to_string();
            STATE.with(|st| {
                let mut st = st.borrow_mut();
                if key_str.is_empty() || st.app_key.as_deref() == Some(key_str.as_str()) {
                    st.app_key = None;
                } else {
                    st.app_key = Some(key_str);
                }
            });
            refresh(&ui, &handle);
        }
    });

    stats.on_select_server_row({
        let weak = ui.as_weak();
        let handle = handle.clone();
        move |sid| {
            let Some(ui) = weak.upgrade() else { return };
            let sid_str = sid.to_string();
            STATE.with(|st| {
                let mut st = st.borrow_mut();
                if st.server_id.as_deref() == Some(sid_str.as_str()) {
                    st.server_id = None;
                } else {
                    st.server_id = Some(sid_str);
                }
                st.pinned_idx = None;
                st.hovered_idx = None;
            });
            refresh(&ui, &handle);
        }
    });

    stats.on_select_session({
        let weak = ui.as_weak();
        let handle = handle.clone();
        move |row_idx| {
            let Some(ui) = weak.upgrade() else { return };
            let chosen = STATE.with(|st| {
                st.borrow()
                    .report
                    .sessions
                    .get(row_idx.max(0) as usize)
                    .cloned()
            });
            let Some(sess) = chosen else { return };
            STATE.with(|st| {
                let mut st = st.borrow_mut();
                if sess.active {
                    st.range = StatsRange::Session;
                    st.custom_from = None;
                    st.custom_to = None;
                } else {
                    st.range = StatsRange::Custom;
                    st.custom_from = Some(sess.started_ms);
                    st.custom_to = Some(sess.ended_ms.max(sess.started_ms + 1000));
                }
                st.pinned_idx = None;
                st.hovered_idx = None;
            });
            let s = ui.global::<Stats>();
            s.set_range(if sess.active { 0 } else { 5 });
            s.set_tab(0);
            refresh(&ui, &handle);
        }
    });

    stats.on_hover_chart({
        let weak = ui.as_weak();
        move |frac| {
            let Some(ui) = weak.upgrade() else { return };
            STATE.with(|st| {
                let mut st = st.borrow_mut();
                if frac < 0.0 || st.report.points.is_empty() {
                    st.hovered_idx = None;
                } else {
                    let max_i = st.report.points.len().saturating_sub(1);
                    let idx = ((frac.clamp(0.0, 1.0) * max_i as f32).round() as usize).min(max_i);
                    st.hovered_idx = Some(idx);
                }
            });
            render_cursor(&ui);
        }
    });

    stats.on_click_chart({
        let weak = ui.as_weak();
        let handle = handle.clone();
        move |frac| {
            let Some(ui) = weak.upgrade() else { return };
            let changed = STATE.with(|st| {
                let mut st = st.borrow_mut();
                if st.report.points.is_empty() {
                    return false;
                }
                let max_i = st.report.points.len().saturating_sub(1);
                let idx = ((frac.clamp(0.0, 1.0) * max_i as f32).round() as usize).min(max_i);
                if st.pinned_idx == Some(idx) {
                    st.pinned_idx = None;
                } else {
                    st.pinned_idx = Some(idx);
                }
                true
            });
            if changed {
                refresh(&ui, &handle);
            }
        }
    });

    stats.on_unpin({
        let weak = ui.as_weak();
        let handle = handle.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            STATE.with(|st| {
                let mut st = st.borrow_mut();
                st.pinned_idx = None;
                st.hovered_idx = None;
            });
            refresh(&ui, &handle);
        }
    });

    stats.on_clear_history({
        let weak = ui.as_weak();
        let handle = handle.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let info = api::clear_stats_history(&handle);
            apply_storage_text(&ui, &info);
            STATE.with(|st| {
                let mut st = st.borrow_mut();
                st.pinned_idx = None;
                st.hovered_idx = None;
                st.app_key = None;
                st.server_id = None;
            });
            if ui.global::<Stats>().get_open() {
                refresh(&ui, &handle);
            }
            let msg = tr(|l| l.stats_cleared_toast.clone());
            view::toast(&ui, "success", &msg, "");
        }
    });

    refresh_storage(ui, handle);
}

pub fn refresh_storage(ui: &AppWindow, handle: &AppHandle) {
    let info = api::stats_storage_info(handle);
    apply_storage_text(ui, &info);
}

fn apply_storage_text(ui: &AppWindow, info: &StorageInfo) {
    let bytes = fmt_bytes(info.bytes_on_disk as f64);
    let text = if info.days_stored > 0 {
        let days_short = tr(|l| l.set_stats_days_short.clone());
        format!("{bytes} · {} {days_short}", info.days_stored)
    } else {
        bytes
    };
    ui.global::<Stats>().set_storage_text(text.into());
}

/// Живое обновление раз в секунду, пока открыта вкладка текущей сессии.
pub fn tick(ui: &AppWindow, handle: &AppHandle) {
    if !ui.global::<Stats>().get_open() {
        return;
    }
    let should = STATE.with(|st| {
        let st = st.borrow();
        st.range == StatsRange::Session && st.pinned_idx.is_none()
    });
    if should {
        refresh(ui, handle);
    }
}

pub fn relabel(ui: &AppWindow, handle: &AppHandle) {
    refresh_storage(ui, handle);
    if ui.global::<Stats>().get_open() {
        refresh(ui, handle);
    }
}

pub fn refresh(ui: &AppWindow, handle: &AppHandle) {
    let query = STATE.with(|st| {
        let st = st.borrow();
        StatsQuery {
            range: st.range,
            custom_from_ms: st.custom_from,
            custom_to_ms: st.custom_to,
            server_id: st.server_id.clone(),
            app_key: st.app_key.clone(),
            pinned_index: st.pinned_idx,
            max_points: Some(96),
        }
    });

    let report = api::query_stats(handle, &query);
    apply_storage_text(ui, &report.storage);

    STATE.with(|st| {
        let mut st = st.borrow_mut();
        if let Some(p) = st.pinned_idx {
            if p >= report.points.len() {
                st.pinned_idx = None;
            }
        }
        st.report = report;
    });

    render_all(ui);
    crate::sync_icons(ui);
}

fn render_all(ui: &AppWindow) {
    let stats = ui.global::<Stats>();
    let per_sec = tr(|l| l.per_second.clone());
    let ms_unit = tr(|l| l.latency_ms.clone());

    STATE.with(|st| {
        let mut st = st.borrow_mut();
        let has = st.report.summary.has_data;
        stats.set_has_data(has);

        // Выпадающий фильтр серверов.
        let all_label = tr(|l| l.stats_all_servers.clone());
        let mut opts: Vec<SharedString> = vec![all_label.into()];
        let mut ids: Vec<String> = vec![String::new()];
        for s in &st.report.servers {
            opts.push(s.server_name.as_str().into());
            ids.push(s.server_id.clone());
        }
        let sel_idx = st
            .server_id
            .as_deref()
            .and_then(|sid| ids.iter().position(|id| id == sid))
            .unwrap_or(0);
        st.server_ids = ids;
        stats.set_server_filter_options(ModelRc::new(VecModel::from(opts)));
        stats.set_server_filter_idx(sel_idx as i32);

        // Имя выбранного приложения для чипа-фильтра.
        let sel_app_name = st
            .app_key
            .as_deref()
            .map(|k| {
                st.report
                    .apps
                    .iter()
                    .find(|a| a.key == k)
                    .map(|a| display_app_name(a))
                    .unwrap_or_else(|| crate::stats::app_name_from_path(k))
            })
            .unwrap_or_default();
        stats.set_selected_app_name(sel_app_name.into());

        if !has {
            stats.set_period_label("".into());
            return;
        }

        let sum = &st.report.summary;
        stats.set_period_label(format_period(sum.from_ms, sum.to_ms).into());

        // KPI 1: Трафик.
        stats.set_kpi_traffic(fmt_bytes(sum.total_bytes as f64).into());
        let vpn_direct = tr(|l| {
            l.stats_vpn_direct_fmt
                .replace("{vpn}", &fmt_bytes(sum.proxy_bytes as f64))
                .replace("{direct}", &fmt_bytes(sum.direct_bytes as f64))
        });
        stats.set_kpi_traffic_foot(vpn_direct.into());

        // KPI 2: Скорость.
        stats.set_kpi_speed(format!("{}{per_sec}", fmt_bytes(sum.avg_down_bps as f64)).into());
        let speed_foot = tr(|l| {
            l.stats_speed_foot_fmt
                .replace("{down}", &format!("{}{per_sec}", fmt_bytes(sum.peak_down_bps as f64)))
                .replace("{up}", &format!("{}{per_sec}", fmt_bytes(sum.peak_up_bps as f64)))
        });
        stats.set_kpi_speed_foot(speed_foot.into());

        // KPI 3: Задержка.
        match sum.avg_latency_ms {
            Some(avg) => {
                stats.set_kpi_latency(fmt_ms(&ms_unit, avg).into());
                let foot = if let Some(jit) = sum.jitter_ms {
                    let j = tr(|l| l.stats_jitter_fmt.replace("{ms}", &jit.to_string()));
                    if let (Some(mn), Some(mx)) = (sum.min_latency_ms, sum.max_latency_ms) {
                        format!("{j} · {mn}–{mx}")
                    } else {
                        j
                    }
                } else if let (Some(mn), Some(mx)) = (sum.min_latency_ms, sum.max_latency_ms) {
                    ms_unit.replace("{ms}", &format!("{mn}–{mx}"))
                } else {
                    String::new()
                };
                stats.set_kpi_latency_foot(foot.into());
            }
            None => {
                stats.set_kpi_latency("—".into());
                stats.set_kpi_latency_foot("".into());
            }
        }

        // KPI 4: Потери.
        stats.set_kpi_loss(format_loss(sum.loss_pct).into());
        stats.set_kpi_loss_tier(loss_tier(sum.loss_pct).into());
        let errs = sum.dial_fails.saturating_add(sum.relay_errors);
        let drops = tr(|l| {
            l.stats_drops_fmt
                .replace("{lost}", &sum.packets_lost.to_string())
                .replace("{err}", &errs.to_string())
        });
        stats.set_kpi_loss_foot(drops.into());

        // Баннер закреплённого момента.
        if let Some(p) = &st.report.pinned_point {
            let prefix = tr(|l| l.stats_moment_prefix.clone());
            stats.set_pinned(true);
            stats.set_pinned_banner(format!("{prefix}: {}", format_point_time(p)).into());
        } else {
            stats.set_pinned(false);
            stats.set_pinned_banner("".into());
        }

        // Таблица VPN-серверов.
        let srv_rows: Vec<crate::StatsServerRow> = st
            .report
            .servers
            .iter()
            .map(|s| server_row(s, st.server_id.as_deref(), &per_sec, &ms_unit))
            .collect();
        stats.set_servers(ModelRc::new(VecModel::from(srv_rows)));

        // Таблица сессий.
        let sess_rows: Vec<crate::StatsSessionRow> = st
            .report
            .sessions
            .iter()
            .map(|s| session_row(s, &ms_unit))
            .collect();
        stats.set_sessions(ModelRc::new(VecModel::from(sess_rows)));
    });

    render_chart_and_cursor(ui);
    render_apps_list(ui);
}

fn render_chart_and_cursor(ui: &AppWindow) {
    let stats = ui.global::<Stats>();
    let width = (stats.get_chart_w() as f64).max(320.0);
    let per_sec = tr(|l| l.per_second.clone());
    let ms_unit = tr(|l| l.latency_ms.clone());

    STATE.with(|st| {
        let st = st.borrow();
        let pts = &st.report.points;
        if pts.is_empty() {
            stats.set_primary_area("".into());
            stats.set_primary_line("".into());
            stats.set_secondary_area("".into());
            stats.set_secondary_line("".into());
            stats.set_app_line("".into());
            stats.set_server_bands(ModelRc::new(VecModel::<crate::StatsServerBand>::default()));
            return;
        }

        match st.metric {
            1 => {
                // Потери (%)
                let vals: Vec<f64> = pts.iter().map(|p| f64::from(p.loss_pct)).collect();
                let peak = vals.iter().copied().fold(5.0f64, f64::max).min(100.0);
                let coords = to_coords(&vals, peak, width);
                stats.set_primary_area(build_area(&coords, width).into());
                stats.set_primary_line(build_line(&coords).into());
                stats.set_secondary_area("".into());
                stats.set_secondary_line("".into());
                stats.set_app_line("".into());
                stats.set_y_max_label(format!("{peak:.0}%").into());
                stats.set_y_mid_label(format!("{:.1}%", peak * 0.5).into());
            }
            2 => {
                // Задержка (мс)
                let vals: Vec<Option<f64>> =
                    pts.iter().map(|p| p.latency_ms.map(f64::from)).collect();
                let peak = vals
                    .iter()
                    .flatten()
                    .copied()
                    .fold(100.0f64, f64::max);
                let dense: Vec<f64> = vals.iter().map(|v| v.unwrap_or(0.0)).collect();
                let coords = to_coords(&dense, peak, width);
                stats.set_primary_area(build_area(&coords, width).into());
                stats.set_primary_line(build_opt_line(&vals, peak, width).into());
                stats.set_secondary_area("".into());
                stats.set_secondary_line("".into());
                stats.set_app_line("".into());
                stats.set_y_max_label(fmt_ms(&ms_unit, peak.round() as u32).into());
                stats.set_y_mid_label(fmt_ms(&ms_unit, (peak * 0.5).round() as u32).into());
            }
            _ => {
                // Скорость (приём / отдача + выбранное приложение)
                let down: Vec<f64> = pts.iter().map(|p| p.down_bps as f64).collect();
                let up: Vec<f64> = pts.iter().map(|p| p.up_bps as f64).collect();
                let peak = down
                    .iter()
                    .chain(up.iter())
                    .copied()
                    .fold(64.0 * 1024.0, f64::max);
                let dc = to_coords(&down, peak, width);
                let uc = to_coords(&up, peak, width);
                stats.set_primary_area(build_area(&dc, width).into());
                stats.set_primary_line(build_line(&dc).into());
                stats.set_secondary_area(build_area(&uc, width).into());
                stats.set_secondary_line(build_line(&uc).into());

                if st.app_key.is_some() {
                    let app_v: Vec<f64> = pts
                        .iter()
                        .map(|p| (p.app_down_bps + p.app_up_bps) as f64)
                        .collect();
                    let ac = to_coords(&app_v, peak, width);
                    stats.set_app_line(build_line(&ac).into());
                } else {
                    stats.set_app_line("".into());
                }

                stats.set_y_max_label(format!("{}{per_sec}", fmt_bytes(peak)).into());
                stats.set_y_mid_label(format!("{}{per_sec}", fmt_bytes(peak * 0.5)).into());
            }
        }

        // Ось X.
        let span_days = (pts.last().unwrap().end_ms - pts.first().unwrap().ts_ms) > 86_400_000;
        let mid_idx = pts.len() / 2;
        stats.set_x_start_label(format_axis_time(pts.first().unwrap().ts_ms, span_days).into());
        stats.set_x_mid_label(format_axis_time(pts[mid_idx].ts_ms, span_days).into());
        stats.set_x_end_label(format_axis_time(pts.last().unwrap().end_ms, span_days).into());

        // Цветная полоса смены VPN-серверов по нижней кромке графика.
        let bands = build_server_bands(pts);
        stats.set_server_bands(ModelRc::new(VecModel::from(bands)));
    });

    render_cursor(ui);
}

fn render_cursor(ui: &AppWindow) {
    let stats = ui.global::<Stats>();
    let per_sec = tr(|l| l.per_second.clone());
    let ms_unit = tr(|l| l.latency_ms.clone());
    let conns_word = tr(|l| l.stats_conns_short.clone());
    let loss_word = tr(|l| l.stats_loss_word.clone());
    let sys_other = tr(|l| l.stats_system_other.clone());

    STATE.with(|st| {
        let st = st.borrow();
        let active_idx = st.hovered_idx.or(st.pinned_idx);
        let Some(idx) = active_idx.filter(|&i| i < st.report.points.len()) else {
            stats.set_cursor_visible(false);
            return;
        };
        let p = &st.report.points[idx];
        let denom = (st.report.points.len().saturating_sub(1)).max(1) as f32;
        stats.set_cursor_visible(true);
        stats.set_cursor_frac((idx as f32 / denom).clamp(0.0, 1.0));
        stats.set_cursor_time(format_point_time(p).into());
        let srv_label = if p.server_proto.is_empty() {
            p.server_name.clone()
        } else {
            format!("{} · {}", p.server_name, p.server_proto)
        };
        stats.set_cursor_server(srv_label.into());

        let primary = match st.metric {
            1 => format!("{loss_word} {}", format_loss(p.loss_pct)),
            2 => match p.latency_ms {
                Some(ms) => fmt_ms(&ms_unit, ms),
                None => "—".into(),
            },
            _ => format!(
                "↓ {}{per_sec} · ↑ {}{per_sec}",
                fmt_bytes(p.down_bps as f64),
                fmt_bytes(p.up_bps as f64)
            ),
        };
        stats.set_cursor_primary(primary.into());

        let lat_part = match p.latency_ms {
            Some(ms) => fmt_ms(&ms_unit, ms),
            None => "—".into(),
        };
        stats.set_cursor_secondary(
            format!(
                "{lat_part} · {loss_word} {} · {} {conns_word}",
                format_loss(p.loss_pct),
                p.connections
            )
            .into(),
        );

        let top: String = p
            .top_apps
            .iter()
            .take(3)
            .map(|a| {
                let name = if a.name.is_empty() { &sys_other } else { &a.name };
                format!("{name} {}", fmt_bytes(a.bytes as f64))
            })
            .collect::<Vec<_>>()
            .join(" · ");
        stats.set_cursor_top_apps(top.into());
    });
}

fn render_apps_list(ui: &AppWindow) {
    let stats = ui.global::<Stats>();
    let per_sec = tr(|l| l.per_second.clone());
    let conns_word = tr(|l| l.stats_conns_short.clone());
    let direct_word = tr(|l| l.stats_route_direct.clone());

    let rows: Vec<crate::StatsAppRow> = STATE.with(|st| {
        let st = st.borrow();
        let src: &[AppStats] = if st.pinned_idx.is_some() {
            &st.report.pinned_apps
        } else {
            &st.report.apps
        };
        let filtered: Vec<&AppStats> = src
            .iter()
            .filter(|a| {
                let route_ok = match st.route_filter {
                    1 => a.proxy_bytes > 0,
                    2 => a.direct_bytes > 0,
                    _ => true,
                };
                if !route_ok {
                    return false;
                }
                if st.app_search.is_empty() {
                    return true;
                }
                let name = display_app_name(a).to_lowercase();
                name.contains(&st.app_search) || a.path.to_lowercase().contains(&st.app_search)
            })
            .collect();

        let max_bytes = filtered
            .iter()
            .map(|a| a.total_bytes)
            .max()
            .unwrap_or(1)
            .max(1);

        filtered
            .into_iter()
            .take(120)
            .map(|a| {
                let name = display_app_name(a);
                let initial: String = name
                    .chars()
                    .next()
                    .map(|c| c.to_uppercase().to_string())
                    .unwrap_or_else(|| "?".into());
                let vpn_text = if a.total_bytes == 0 {
                    String::new()
                } else if a.vpn_pct >= 99.5 {
                    "VPN".into()
                } else if a.vpn_pct <= 0.5 {
                    direct_word.clone()
                } else {
                    format!("VPN {:.0}%", a.vpn_pct)
                };
                crate::StatsAppRow {
                    key: a.key.as_str().into(),
                    name: name.into(),
                    initial: initial.into(),
                    icon: slint::Image::default(),
                    path: a.path.as_str().into(),
                    total: fmt_bytes(a.total_bytes as f64).into(),
                    down: fmt_bytes(a.down_bytes as f64).into(),
                    up: fmt_bytes(a.up_bytes as f64).into(),
                    peak: format!("{}{per_sec}", fmt_bytes(a.peak_bps as f64)).into(),
                    vpn_share: (a.vpn_pct / 100.0).clamp(0.0, 1.0),
                    total_share: (a.total_bytes as f32 / max_bytes as f32).clamp(0.0, 1.0),
                    share_text: format!("{:.0}%", a.share_pct).into(),
                    vpn_text: vpn_text.into(),
                    conns: format!("{} {conns_word}", a.total_conns).into(),
                    errors: a.errors.min(i32::MAX as u64) as i32,
                    selected: st.app_key.as_deref() == Some(a.key.as_str()) && !a.key.is_empty(),
                }
            })
            .collect()
    });

    stats.set_apps(ModelRc::new(VecModel::from(rows)));
    crate::sync_icons(ui);
}

// --------------------------------------------------------------- row builders

fn display_app_name(a: &AppStats) -> String {
    if a.name.is_empty() {
        tr(|l| l.stats_system_other.clone())
    } else {
        a.name.clone()
    }
}

fn server_row(
    s: &ServerStats,
    selected_id: Option<&str>,
    per_sec: &str,
    ms_unit: &str,
) -> crate::StatsServerRow {
    let latency = match (s.avg_latency_ms, s.jitter_ms) {
        (Some(avg), Some(j)) => format!("{} (±{j})", fmt_ms(ms_unit, avg)),
        (Some(avg), None) => fmt_ms(ms_unit, avg),
        _ => "—".into(),
    };
    let errs = s.dial_fails.saturating_add(s.relay_errors);
    let drops = tr(|l| {
        l.stats_drops_fmt
            .replace("{lost}", &s.packets_lost.to_string())
            .replace("{err}", &errs.to_string())
    });
    let speed = format!(
        "↓ {}{per_sec} · ↑ {}{per_sec}",
        fmt_bytes(s.avg_down_bps as f64),
        fmt_bytes(s.avg_up_bps as f64)
    );
    crate::StatsServerRow {
        id: s.server_id.as_str().into(),
        name: if s.server_name.is_empty() {
            s.server_id.as_str().into()
        } else {
            s.server_name.as_str().into()
        },
        proto: s.server_proto.as_str().into(),
        health: s.health.as_str().into(),
        duration: format_duration(s.duration_s).into(),
        traffic: fmt_bytes(s.total_bytes as f64).into(),
        speed: speed.into(),
        latency: latency.into(),
        loss_text: format_loss(s.loss_pct).into(),
        loss_tier: loss_tier(s.loss_pct).into(),
        drops_text: drops.into(),
        selected: selected_id == Some(s.server_id.as_str()),
    }
}

fn session_row(s: &SessionRecord, ms_unit: &str) -> crate::StatsSessionRow {
    let server = if s.server_count > 1 && !s.primary_server_name.is_empty() {
        format!("{} (+{})", s.primary_server_name, s.server_count - 1)
    } else if !s.primary_server_name.is_empty() {
        s.primary_server_name.clone()
    } else {
        "—".into()
    };
    let lat = match s.avg_latency_ms {
        Some(ms) => fmt_ms(ms_unit, ms),
        None => "—".into(),
    };
    crate::StatsSessionRow {
        id: s.id.as_str().into(),
        date_text: format_session_date(s.started_ms).into(),
        duration: format_duration(s.duration_s).into(),
        server: server.into(),
        traffic: fmt_bytes((s.down_bytes + s.up_bytes) as f64).into(),
        latency: lat.into(),
        loss_text: format_loss(s.loss_pct).into(),
        loss_tier: loss_tier(s.loss_pct).into(),
        active: s.active,
    }
}

// --------------------------------------------------------------- SVG paths

fn to_coords(values: &[f64], peak: f64, width: f64) -> Vec<(f64, f64)> {
    let usable = CHART_H - PAD_TOP - PAD_BOTTOM;
    let peak = peak.max(1e-6);
    if values.len() == 1 {
        let y = CHART_H - PAD_BOTTOM - (values[0] / peak).clamp(0.0, 1.0) * usable;
        return vec![(0.0, y), (width, y)];
    }
    let step = width / (values.len() - 1) as f64;
    values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = i as f64 * step;
            let y = CHART_H - PAD_BOTTOM - (v / peak).clamp(0.0, 1.0) * usable;
            (x, y)
        })
        .collect()
}

fn build_line(points: &[(f64, f64)]) -> String {
    let mut out = String::with_capacity(points.len() * 14);
    for (i, &(x, y)) in points.iter().enumerate() {
        out.push_str(&format!("{}{x:.1},{y:.1} ", if i == 0 { "M" } else { "L" }));
    }
    out
}

fn build_opt_line(values: &[Option<f64>], peak: f64, width: f64) -> String {
    let usable = CHART_H - PAD_TOP - PAD_BOTTOM;
    let peak = peak.max(1e-6);
    if values.len() == 1 {
        if let Some(v) = values[0] {
            let y = CHART_H - PAD_BOTTOM - (v / peak).clamp(0.0, 1.0) * usable;
            return format!("M0.0,{y:.1} L{width:.1},{y:.1} ");
        }
        return String::new();
    }
    let step = width / (values.len() - 1) as f64;
    let mut out = String::with_capacity(values.len() * 14);
    let mut pen = false;
    for (i, v) in values.iter().enumerate() {
        if let Some(val) = v {
            let x = i as f64 * step;
            let y = CHART_H - PAD_BOTTOM - (val / peak).clamp(0.0, 1.0) * usable;
            out.push_str(&format!("{}{x:.1},{y:.1} ", if pen { "L" } else { "M" }));
            pen = true;
        } else {
            pen = false;
        }
    }
    out
}

fn build_area(points: &[(f64, f64)], width: f64) -> String {
    let base_y = CHART_H - PAD_BOTTOM;
    let mut out = String::with_capacity(points.len() * 14 + 48);
    for (i, &(x, y)) in points.iter().enumerate() {
        out.push_str(&format!("{}{x:.1},{y:.1} ", if i == 0 { "M" } else { "L" }));
    }
    out.push_str(&format!("L{width:.1},{base_y:.1} L0.0,{base_y:.1} Z"));
    out
}

fn build_server_bands(pts: &[ChartPoint]) -> Vec<crate::StatsServerBand> {
    if pts.is_empty() {
        return Vec::new();
    }
    let n = pts.len() as f32;
    let mut color_map: HashMap<&str, i32> = HashMap::new();
    let mut next_color = 0i32;
    let mut bands = Vec::new();
    let mut i = 0;
    while i < pts.len() {
        let sid = pts[i].server_id.as_str();
        let start = i;
        while i < pts.len() && pts[i].server_id == sid {
            i += 1;
        }
        if !sid.is_empty() {
            let color_idx = *color_map.entry(sid).or_insert_with(|| {
                let c = next_color % 5;
                next_color += 1;
                c
            });
            bands.push(crate::StatsServerBand {
                start_frac: start as f32 / n,
                width_frac: (i - start) as f32 / n,
                color_idx,
                label: pts[start].server_name.as_str().into(),
            });
        }
    }
    bands
}

// --------------------------------------------------------------- formatting

fn fmt_ms(template: &str, ms: u32) -> String {
    if template.contains("{ms}") {
        template.replace("{ms}", &ms.to_string())
    } else {
        format!("{ms} {template}")
    }
}

fn loss_tier(pct: f32) -> &'static str {
    if pct >= 5.0 {
        "bad"
    } else if pct >= 1.0 {
        "ok"
    } else {
        "good"
    }
}

fn format_loss(pct: f32) -> String {
    if pct <= 0.0 {
        "0%".into()
    } else if pct < 10.0 {
        format!("{pct:.1}%")
    } else {
        format!("{pct:.0}%")
    }
}

fn format_duration(total_s: u64) -> String {
    let h = total_s / 3600;
    let m = (total_s % 3600) / 60;
    let s = total_s % 60;
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

fn local_dt(ts_ms: i64) -> Option<DateTime<Local>> {
    Local.timestamp_millis_opt(ts_ms).single()
}

fn format_axis_time(ts_ms: i64, with_date: bool) -> String {
    let Some(dt) = local_dt(ts_ms) else {
        return String::new();
    };
    if with_date {
        dt.format("%d.%m %H:%M").to_string()
    } else {
        dt.format("%H:%M:%S").to_string()
    }
}

fn format_point_time(p: &ChartPoint) -> String {
    let (Some(a), Some(b)) = (local_dt(p.ts_ms), local_dt(p.end_ms)) else {
        return String::new();
    };
    if p.end_ms - p.ts_ms >= 60_000 {
        if a.date_naive() == b.date_naive() {
            format!("{} — {}", a.format("%d.%m %H:%M"), b.format("%H:%M"))
        } else {
            format!("{} — {}", a.format("%d.%m %H:%M"), b.format("%d.%m %H:%M"))
        }
    } else {
        format!("{} — {}", a.format("%H:%M:%S"), b.format("%H:%M:%S"))
    }
}

fn format_period(from_ms: i64, to_ms: i64) -> String {
    let (Some(a), Some(b)) = (local_dt(from_ms), local_dt(to_ms)) else {
        return String::new();
    };
    if a.date_naive() == b.date_naive() {
        format!("{} — {}", a.format("%d.%m.%Y, %H:%M"), b.format("%H:%M"))
    } else {
        format!("{} — {}", a.format("%d.%m %H:%M"), b.format("%d.%m %H:%M"))
    }
}

fn format_session_date(started_ms: i64) -> String {
    local_dt(started_ms)
        .map(|dt| dt.format("%d.%m.%Y · %H:%M").to_string())
        .unwrap_or_default()
}
