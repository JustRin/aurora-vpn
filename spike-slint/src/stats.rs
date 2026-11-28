//! Расширенная статистика сессий, приложений и качества VPN-серверов.
//!
//! Снимает телеметрию раз в секунду, держит подробный 1-секундный буфер в памяти
//! для текущей сессии и складывает 10-секундные срезы на диск в подённые файлы
//! `YYYY-MM-DD.jsonl` (прошлые дни сжимаются в `.jsonl.gz`). По умолчанию данные
//! хранятся 30 дней; при `retention_days == 0` запись на диск не ведётся.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// Максимальное число секундных отсчётов в памяти (10 минут детального просмотра).
const LIVE_1S_CAPACITY: usize = 600;
/// Длительность одного агрегированного среза на диске (секунды).
const BUCKET_SECS: u32 = 10;
/// Сколько самых активных приложений сохранять в одном 10-секундном срезе;
/// остальные складываются в общую строку «Прочее», чтобы файлы не раздувались.
const MAX_APPS_PER_BUCKET: usize = 24;
/// Предел числа точек на графике по умолчанию.
const DEFAULT_MAX_POINTS: usize = 96;

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// --------------------------------------------------------------- input types

#[derive(Debug, Clone, Default)]
pub struct TelemetryNet {
    pub tun_rx_packets: u64,
    pub tun_tx_packets: u64,
    pub tun_dropped: u64,
    pub udp_dropped: u64,
    pub tcp_bytes_out: u64,
    pub tcp_bytes_in: u64,
    pub tcp_bytes_retrans: u64,
    pub tcp_retrans_events: u64,
    pub tcp_rtt_us_sum: u64,
    pub tcp_rtt_samples: u64,
    pub quic_packets_sent: u64,
    pub quic_packets_lost: u64,
    pub dial_ok: u64,
    pub dial_fail: u64,
    pub relay_errors: u64,
}

#[derive(Debug, Clone, Default)]
pub struct TelemetryApp {
    pub path: String,
    pub down: u64,
    pub up: u64,
    pub proxy_down: u64,
    pub proxy_up: u64,
    pub active_conns: u32,
    pub total_conns: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Default)]
pub struct OpenConnSample {
    pub id: String,
    pub path: String,
    pub is_proxy: bool,
    pub down: u64,
    pub up: u64,
}

#[derive(Debug, Clone, Default)]
pub struct TelemetrySnapshot {
    pub download: u64,
    pub upload: u64,
    pub proxy_download: u64,
    pub proxy_upload: u64,
    pub direct_download: u64,
    pub direct_upload: u64,
    pub connections: usize,
    pub has_net_metrics: bool,
    pub net: TelemetryNet,
    /// `true` — накопленные счётчики с момента старта ядра (`aura-engine`).
    /// `false` — снимок активных соединений (`sing-box /connections`).
    pub apps_cumulative: bool,
    pub apps: Vec<TelemetryApp>,
    pub open_conns: Vec<OpenConnSample>,
}

#[derive(Debug, Clone, Default)]
pub struct ServerContext {
    pub id: String,
    pub name: String,
    pub proto: String,
}

// --------------------------------------------------------------- disk schema

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AppBucket {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    k: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    n: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    p: String,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    d: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    u: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pd: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pu: u64,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    c: u32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    tc: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    e: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SampleBucket {
    ts: i64,
    dur: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sp: String,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    d: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    u: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pd: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pu: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pkd: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pku: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    lat_sum: u64,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    lat_n: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    lat_min: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    lat_max: u32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    jit_sum: u64,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    jit_n: u32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    tcp_out: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    tcp_ret: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    tcp_ev: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    q_sent: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    q_lost: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    tun_pkts: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    tun_drop: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    udp_drop: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    dial_ok: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    dial_fail: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    relay_err: u64,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    prb_n: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    prb_fail: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    conns: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    apps: Vec<AppBucket>,
}

// --------------------------------------------------------------- public API

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum StatsRange {
    #[default]
    Session,
    Hour1,
    Hours24,
    Days7,
    Days30,
    Custom,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StatsQuery {
    pub range: StatsRange,
    pub custom_from_ms: Option<i64>,
    pub custom_to_ms: Option<i64>,
    pub server_id: Option<String>,
    pub app_key: Option<String>,
    pub pinned_index: Option<usize>,
    pub max_points: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageInfo {
    pub bytes_on_disk: u64,
    pub days_stored: u32,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PointAppSummary {
    pub key: String,
    pub name: String,
    pub path: String,
    pub bytes: u64,
    pub down_bytes: u64,
    pub up_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChartPoint {
    pub ts_ms: i64,
    pub end_ms: i64,
    pub dur_s: u32,
    pub down_bps: u64,
    pub up_bps: u64,
    pub proxy_down_bps: u64,
    pub proxy_up_bps: u64,
    pub app_down_bps: u64,
    pub app_up_bps: u64,
    pub down_bytes: u64,
    pub up_bytes: u64,
    pub latency_ms: Option<u32>,
    pub loss_pct: f32,
    pub packets_lost: u64,
    pub errors: u64,
    pub connections: u32,
    pub server_id: String,
    pub server_name: String,
    pub server_proto: String,
    pub top_apps: Vec<PointAppSummary>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStats {
    pub key: String,
    pub name: String,
    pub path: String,
    pub down_bytes: u64,
    pub up_bytes: u64,
    pub total_bytes: u64,
    pub proxy_bytes: u64,
    pub direct_bytes: u64,
    pub peak_bps: u64,
    pub share_pct: f32,
    pub vpn_pct: f32,
    pub active_conns: u32,
    pub total_conns: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStats {
    pub server_id: String,
    pub server_name: String,
    pub server_proto: String,
    pub duration_s: u64,
    pub down_bytes: u64,
    pub up_bytes: u64,
    pub total_bytes: u64,
    pub avg_down_bps: u64,
    pub peak_down_bps: u64,
    pub avg_up_bps: u64,
    pub peak_up_bps: u64,
    pub avg_latency_ms: Option<u32>,
    pub min_latency_ms: Option<u32>,
    pub max_latency_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub loss_pct: f32,
    pub packets_lost: u64,
    pub retrans_events: u64,
    pub dial_fails: u64,
    pub relay_errors: u64,
    pub probe_fails: u32,
    pub probe_total: u32,
    /// `"good"` | `"warn"` | `"bad"`
    pub health: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecord {
    pub id: String,
    pub started_ms: i64,
    pub ended_ms: i64,
    #[serde(default)]
    pub active: bool,
    pub duration_s: u64,
    pub primary_server_id: String,
    pub primary_server_name: String,
    pub server_count: usize,
    pub down_bytes: u64,
    pub up_bytes: u64,
    pub peak_down_bps: u64,
    pub avg_latency_ms: Option<u32>,
    pub loss_pct: f32,
    pub packets_lost: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsSummary {
    pub down_bytes: u64,
    pub up_bytes: u64,
    pub total_bytes: u64,
    pub proxy_bytes: u64,
    pub direct_bytes: u64,
    pub avg_down_bps: u64,
    pub peak_down_bps: u64,
    pub avg_up_bps: u64,
    pub peak_up_bps: u64,
    pub avg_latency_ms: Option<u32>,
    pub min_latency_ms: Option<u32>,
    pub max_latency_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub loss_pct: f32,
    pub packets_lost: u64,
    pub retrans_events: u64,
    pub tun_drops: u64,
    pub udp_drops: u64,
    pub dial_fails: u64,
    pub relay_errors: u64,
    pub probe_fails: u32,
    pub probe_total: u32,
    pub duration_s: u64,
    pub has_data: bool,
    pub from_ms: i64,
    pub to_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsReport {
    pub summary: StatsSummary,
    pub points: Vec<ChartPoint>,
    pub apps: Vec<AppStats>,
    pub pinned_point: Option<ChartPoint>,
    pub pinned_apps: Vec<AppStats>,
    pub servers: Vec<ServerStats>,
    pub sessions: Vec<SessionRecord>,
    pub storage: StorageInfo,
}

// --------------------------------------------------------------- recorder

#[derive(Default)]
struct PrevTelemetry {
    initialized: bool,
    download: u64,
    upload: u64,
    proxy_download: u64,
    proxy_upload: u64,
    net: TelemetryNet,
    /// Путь → предыдущие накопленные счётчики (для `aura-engine`).
    apps: HashMap<String, (u64, u64, u64, u64, u64, u64)>,
    /// id соединения → предыдущие `(down, up)` (для `sing-box`).
    open_conns: HashMap<String, (u64, u64)>,
}

#[derive(Default)]
struct ActiveSession {
    id: String,
    started_ms: i64,
    last_tick_ms: i64,
    servers_time: HashMap<String, (String, u64)>,
    agg: LossAgg,
    down_bytes: u64,
    up_bytes: u64,
    peak_down_bps: u64,
    lat_sum: u64,
    lat_n: u32,
}

struct PendingProbe {
    server_id: String,
    total: u32,
    failed: u32,
    lat_sum: u64,
    lat_n: u32,
    lat_min: u32,
    lat_max: u32,
    jit_sum: u64,
    jit_n: u32,
}

struct Inner {
    dir: PathBuf,
    retention_days: u32,
    last_day: Option<NaiveDate>,
    active: Option<ActiveSession>,
    prev: PrevTelemetry,
    /// Последний измеренный пинг по `server_id` (для расчёта джиттера и отображения
    /// на графике между проверками балансировщика).
    last_rtt: HashMap<String, u32>,
    pending_probe: Option<PendingProbe>,
    /// Подробная 1-секундная история текущей сессии (до 10 минут).
    live_1s: VecDeque<SampleBucket>,
    /// 10-секундные срезы всей текущей (или последней) сессии в памяти —
    /// работают даже при `retention_days == 0`.
    session_buckets: Vec<SampleBucket>,
    /// Текущий незакрытый 10-секундный срез.
    pending_bucket: Option<SampleBucket>,
    pending_apps: HashMap<String, AppBucket>,
}

pub struct StatsRecorder {
    inner: Mutex<Inner>,
}

impl StatsRecorder {
    pub fn new(dir: PathBuf, retention_days: u32) -> Self {
        let _ = fs::create_dir_all(&dir);
        let recorder = Self {
            inner: Mutex::new(Inner {
                dir,
                retention_days,
                last_day: Some(Utc::now().date_naive()),
                active: None,
                prev: PrevTelemetry::default(),
                last_rtt: HashMap::new(),
                pending_probe: None,
                live_1s: VecDeque::with_capacity(LIVE_1S_CAPACITY),
                session_buckets: Vec::new(),
                pending_bucket: None,
                pending_apps: HashMap::new(),
            }),
        };
        recorder.run_maintenance();
        recorder
    }

    pub fn set_retention_days(&self, days: u32) {
        {
            let mut g = self.inner.lock();
            g.retention_days = days;
        }
        self.run_maintenance();
    }

    pub fn retention_days(&self) -> u32 {
        self.inner.lock().retention_days
    }

    /// Начать новую сессию подключения.
    pub fn start_session(&self, server: ServerContext, started_ms: i64) {
        let mut g = self.inner.lock();
        g.finish_active_session_locked(started_ms);
        g.live_1s.clear();
        g.session_buckets.clear();
        g.prev = PrevTelemetry::default();
        g.pending_probe = None;

        let mut servers_time = HashMap::new();
        if !server.id.is_empty() {
            servers_time.insert(server.id.clone(), (server.name.clone(), 0));
        }
        g.active = Some(ActiveSession {
            id: format!("s-{started_ms}"),
            started_ms,
            last_tick_ms: started_ms,
            servers_time,
            ..Default::default()
        });
    }

    /// Завершить текущую сессию и сбросить накопленный срез на диск.
    pub fn end_session(&self) {
        let mut g = self.inner.lock();
        g.finish_active_session_locked(now_ms());
    }

    /// Сбросить буфер при выходе из приложения.
    pub fn flush(&self) {
        let mut g = self.inner.lock();
        g.finish_active_session_locked(now_ms());
    }

    /// Зафиксировать результат проверки активного сервера балансировщиком/сторожем.
    pub fn record_probe(&self, server_id: &str, latency_ms: Option<u32>) {
        if server_id.is_empty() {
            return;
        }
        let mut g = self.inner.lock();
        let jit = match (latency_ms, g.last_rtt.get(server_id).copied()) {
            (Some(cur), Some(prev)) => Some(cur.abs_diff(prev)),
            _ => None,
        };
        if let Some(ms) = latency_ms {
            g.last_rtt.insert(server_id.to_string(), ms);
        }
        let entry = g.pending_probe.get_or_insert_with(|| PendingProbe {
            server_id: server_id.to_string(),
            total: 0,
            failed: 0,
            lat_sum: 0,
            lat_n: 0,
            lat_min: u32::MAX,
            lat_max: 0,
            jit_sum: 0,
            jit_n: 0,
        });
        if entry.server_id != server_id {
            *entry = PendingProbe {
                server_id: server_id.to_string(),
                total: 0,
                failed: 0,
                lat_sum: 0,
                lat_n: 0,
                lat_min: u32::MAX,
                lat_max: 0,
                jit_sum: 0,
                jit_n: 0,
            };
        }
        entry.total = entry.total.saturating_add(1);
        match latency_ms {
            Some(ms) => {
                entry.lat_sum = entry.lat_sum.saturating_add(u64::from(ms));
                entry.lat_n = entry.lat_n.saturating_add(1);
                entry.lat_min = entry.lat_min.min(ms);
                entry.lat_max = entry.lat_max.max(ms);
                if let Some(j) = jit {
                    entry.jit_sum = entry.jit_sum.saturating_add(u64::from(j));
                    entry.jit_n = entry.jit_n.saturating_add(1);
                }
            }
            None => {
                entry.failed = entry.failed.saturating_add(1);
            }
        }
    }

    /// Записать очередную 1-секундную выборку телеметрии.
    pub fn record_tick(
        &self,
        ts_ms: i64,
        elapsed_secs: f64,
        server: ServerContext,
        snap: &TelemetrySnapshot,
        fallback_latency_ms: Option<u32>,
    ) {
        let mut g = self.inner.lock();
        g.record_tick_locked(ts_ms, elapsed_secs, server, snap, fallback_latency_ms);
    }

    /// Выполнить сжатие прошлых дней и очистку старше `retention_days`.
    pub fn run_maintenance(&self) {
        let (dir, retention) = {
            let g = self.inner.lock();
            (g.dir.clone(), g.retention_days)
        };
        let today = Utc::now().date_naive();
        compress_past_days(&dir, today);
        if retention > 0 {
            prune_old_files(&dir, today, retention);
            prune_sessions_file(&dir, retention);
        }
    }

    pub fn storage_info(&self) -> StorageInfo {
        let (dir, retention_days) = {
            let g = self.inner.lock();
            (g.dir.clone(), g.retention_days)
        };
        compute_storage_info(&dir, retention_days)
    }

    /// Удалить всю сохранённую историю с диска (и из памяти, если не подключены).
    pub fn clear_history(&self) -> StorageInfo {
        let mut g = self.inner.lock();
        if let Ok(entries) = fs::read_dir(&g.dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let _ = fs::remove_file(path);
                }
            }
        }
        g.live_1s.clear();
        g.session_buckets.clear();
        g.pending_bucket = None;
        g.pending_apps.clear();
        if let Some(active) = g.active.as_mut() {
            let now = now_ms();
            active.started_ms = now;
            active.last_tick_ms = now;
            active.down_bytes = 0;
            active.up_bytes = 0;
            active.peak_down_bps = 0;
            active.lat_sum = 0;
            active.lat_n = 0;
            active.agg = LossAgg::default();
            for (_, dur) in active.servers_time.values_mut() {
                *dur = 0;
            }
        }
        compute_storage_info(&g.dir, g.retention_days)
    }

    /// Построить отчёт статистики по запросу (период, фильтр сервера/приложения,
    /// закреплённая точка на графике).
    pub fn query(&self, q: &StatsQuery) -> StatsReport {
        let now = now_ms();
        let (
            dir,
            retention_days,
            live_1s,
            session_buckets,
            pending_bucket,
            active_session,
        ) = {
            let g = self.inner.lock();
            let pending = g.pending_bucket_snapshot();
            let active = g.active.as_ref().map(|a| a.to_record(true));
            (
                g.dir.clone(),
                g.retention_days,
                g.live_1s.clone(),
                g.session_buckets.clone(),
                pending,
                active,
            )
        };

        let storage = compute_storage_info(&dir, retention_days);
        let mut sessions = load_sessions(&dir);
        if let Some(act) = active_session.clone() {
            sessions.push(act);
        }
        sessions.sort_by(|a, b| b.started_ms.cmp(&a.started_ms));

        let (from_ms, to_ms, buckets) = match q.range {
            StatsRange::Session => {
                // Если в памяти есть активная или только что завершившаяся сессия — берём её.
                let has_mem = !live_1s.is_empty() || !session_buckets.is_empty() || pending_bucket.is_some();
                if has_mem {
                    let start = active_session
                        .as_ref()
                        .map(|s| s.started_ms)
                        .or_else(|| session_buckets.first().map(|b| b.ts))
                        .or_else(|| live_1s.front().map(|b| b.ts))
                        .or_else(|| pending_bucket.as_ref().map(|b| b.ts))
                        .unwrap_or(now);
                    let end = pending_bucket
                        .as_ref()
                        .map(|b| b.ts + i64::from(b.dur) * 1000)
                        .or_else(|| live_1s.back().map(|b| b.ts + i64::from(b.dur) * 1000))
                        .or_else(|| session_buckets.last().map(|b| b.ts + i64::from(b.dur) * 1000))
                        .unwrap_or(now);
                    // Для коротких сессий (≤ 10 мин) отдаём посекундные данные, для длинных — 10-сек + живой хвост.
                    let span_s = ((end - start).max(0) / 1000) as usize;
                    let list = if span_s <= LIVE_1S_CAPACITY && !live_1s.is_empty() {
                        live_1s.into_iter().collect::<Vec<_>>()
                    } else {
                        let mut v = session_buckets;
                        if let Some(p) = pending_bucket {
                            v.push(p);
                        }
                        v
                    };
                    (start, end, list)
                } else if let Some(last) = sessions.first() {
                    // Только что открыли приложение без подключения: покажем последнюю сессию с диска.
                    let list = load_buckets_range(&dir, last.started_ms, last.ended_ms + 10_000);
                    (last.started_ms, last.ended_ms, list)
                } else {
                    (now, now, Vec::new())
                }
            }
            StatsRange::Hour1 => {
                let from = now - 3_600_000;
                let list = merge_disk_and_mem(&dir, from, now, &session_buckets, pending_bucket.as_ref());
                (from, now, list)
            }
            StatsRange::Hours24 => {
                let from = now - 86_400_000;
                let list = merge_disk_and_mem(&dir, from, now, &session_buckets, pending_bucket.as_ref());
                (from, now, list)
            }
            StatsRange::Days7 => {
                let from = now - 7 * 86_400_000;
                let list = merge_disk_and_mem(&dir, from, now, &session_buckets, pending_bucket.as_ref());
                (from, now, list)
            }
            StatsRange::Days30 => {
                let from = now - 30 * 86_400_000;
                let list = merge_disk_and_mem(&dir, from, now, &session_buckets, pending_bucket.as_ref());
                (from, now, list)
            }
            StatsRange::Custom => {
                let from = q.custom_from_ms.unwrap_or(now - 3_600_000);
                let to = q.custom_to_ms.unwrap_or(now).max(from);
                let list = merge_disk_and_mem(&dir, from, to, &session_buckets, pending_bucket.as_ref());
                (from, to, list)
            }
        };

        // Сессии, пересекающиеся с выбранным окном.
        let sessions_in_range: Vec<SessionRecord> = match q.range {
            StatsRange::Session => sessions.into_iter().take(20).collect(),
            _ => sessions
                .into_iter()
                .filter(|s| s.ended_ms >= from_ms && s.started_ms <= to_ms)
                .take(50)
                .collect(),
        };

        build_report(buckets, q, from_ms, to_ms, sessions_in_range, storage)
    }
}

impl Inner {
    fn pending_bucket_snapshot(&self) -> Option<SampleBucket> {
        let mut b = self.pending_bucket.clone()?;
        b.apps = finalize_apps(&self.pending_apps);
        Some(b)
    }

    fn flush_pending_bucket_locked(&mut self) {
        let Some(mut bucket) = self.pending_bucket.take() else {
            self.pending_apps.clear();
            return;
        };
        bucket.apps = finalize_apps(&self.pending_apps);
        self.pending_apps.clear();

        self.session_buckets.push(bucket.clone());
        if self.retention_days > 0 {
            self.append_bucket_to_disk(&bucket);
        }
    }

    fn append_bucket_to_disk(&mut self, bucket: &SampleBucket) {
        let day = date_of_ms(bucket.ts);
        if self.last_day != Some(day) {
            self.last_day = Some(day);
            compress_past_days(&self.dir, day);
            if self.retention_days > 0 {
                prune_old_files(&self.dir, day, self.retention_days);
                prune_sessions_file(&self.dir, self.retention_days);
            }
        }
        let path = self.dir.join(format!("{}.jsonl", day.format("%Y-%m-%d")));
        if let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) {
            let mut w = BufWriter::new(file);
            if serde_json::to_writer(&mut w, bucket).is_ok() {
                let _ = w.write_all(b"\n");
                let _ = w.flush();
            }
        }
    }

    fn finish_active_session_locked(&mut self, ended_ms: i64) {
        self.flush_pending_bucket_locked();
        let Some(mut active) = self.active.take() else {
            return;
        };
        if active.last_tick_ms < ended_ms {
            active.last_tick_ms = ended_ms;
        }
        let rec = active.to_record(false);
        if self.retention_days > 0 && (rec.duration_s >= 2 || rec.down_bytes > 0 || rec.up_bytes > 0) {
            let path = self.dir.join("sessions.jsonl");
            if let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) {
                let mut w = BufWriter::new(file);
                if serde_json::to_writer(&mut w, &rec).is_ok() {
                    let _ = w.write_all(b"\n");
                    let _ = w.flush();
                }
            }
        }
    }

    fn record_tick_locked(
        &mut self,
        ts_ms: i64,
        elapsed_secs: f64,
        server: ServerContext,
        snap: &TelemetrySnapshot,
        fallback_latency_ms: Option<u32>,
    ) {
        let dur_f = elapsed_secs.clamp(0.2, 10.0);
        let dur_s = dur_f.round().max(1.0) as u32;

        // Первый тик после запуска ядра фиксирует базу, чтобы не давать всплеск.
        let (d_down, d_up, d_pdown, d_pup, d_net, app_deltas, sidecar_active_conns) = if !self.prev.initialized {
            self.prev.initialized = true;
            self.prev.download = snap.download;
            self.prev.upload = snap.upload;
            self.prev.proxy_download = snap.proxy_download;
            self.prev.proxy_upload = snap.proxy_upload;
            self.prev.net = snap.net.clone();
            if snap.apps_cumulative {
                for a in &snap.apps {
                    self.prev.apps.insert(
                        a.path.clone(),
                        (a.down, a.up, a.proxy_down, a.proxy_up, a.total_conns, a.errors),
                    );
                }
            } else {
                for c in &snap.open_conns {
                    self.prev.open_conns.insert(c.id.clone(), (c.down, c.up));
                }
            }
            (0, 0, 0, 0, TelemetryNet::default(), Vec::new(), 0usize)
        } else {
            let reset = snap.download < self.prev.download || snap.upload < self.prev.upload;
            let raw_d_down = if reset { snap.download } else { snap.download - self.prev.download };
            let raw_d_up = if reset { snap.upload } else { snap.upload - self.prev.upload };

            let mut sidecar_d = 0u64;
            let mut sidecar_u = 0u64;
            let mut sidecar_pd = 0u64;
            let mut sidecar_pu = 0u64;
            let mut sidecar_err = 0u64;
            let mut sidecar_active = 0usize;

            let (d_down, d_up, d_pdown, d_pup, app_deltas) = if snap.apps_cumulative {
                let raw_d_pdown = if reset {
                    snap.proxy_download
                } else {
                    snap.proxy_download.saturating_sub(self.prev.proxy_download)
                };
                let raw_d_pup = if reset {
                    snap.proxy_upload
                } else {
                    snap.proxy_upload.saturating_sub(self.prev.proxy_upload)
                };
                if reset {
                    self.prev.apps.clear();
                }
                let mut list = Vec::new();
                for a in &snap.apps {
                    let prev = self.prev.apps.get(&a.path).copied().unwrap_or_default();
                    let ad = a.down.saturating_sub(prev.0);
                    let au = a.up.saturating_sub(prev.1);
                    let apd = a.proxy_down.saturating_sub(prev.2);
                    let apu = a.proxy_up.saturating_sub(prev.3);
                    let atc = a.total_conns.saturating_sub(prev.4);
                    let ae = a.errors.saturating_sub(prev.5);
                    self.prev.apps.insert(
                        a.path.clone(),
                        (a.down, a.up, a.proxy_down, a.proxy_up, a.total_conns, a.errors),
                    );
                    if is_internal_sidecar(&a.path) {
                        sidecar_d = sidecar_d.saturating_add(ad);
                        sidecar_u = sidecar_u.saturating_add(au);
                        sidecar_pd = sidecar_pd.saturating_add(apd);
                        sidecar_pu = sidecar_pu.saturating_add(apu);
                        sidecar_err = sidecar_err.saturating_add(ae);
                        sidecar_active = sidecar_active.saturating_add(a.active_conns as usize);
                        continue;
                    }
                    if ad > 0 || au > 0 || a.active_conns > 0 || ae > 0 {
                        list.push(make_app_bucket(&a.path, ad, au, apd, apu, a.active_conns, atc, ae));
                    }
                }
                let d_down = raw_d_down.saturating_sub(sidecar_d);
                let d_up = raw_d_up.saturating_sub(sidecar_u);
                let d_pdown = raw_d_pdown.saturating_sub(sidecar_pd).min(d_down);
                let d_pup = raw_d_pup.saturating_sub(sidecar_pu).min(d_up);
                (d_down, d_up, d_pdown, d_pup, list)
            } else {
                // sing-box fallback: разности по id каждого живого соединения.
                let mut next_conns: HashMap<String, (u64, u64)> = HashMap::with_capacity(snap.open_conns.len());
                let mut by_app: HashMap<String, AppBucket> = HashMap::new();
                let mut sum_d = 0u64;
                let mut sum_u = 0u64;
                let mut sum_pd = 0u64;
                let mut sum_pu = 0u64;

                for c in &snap.open_conns {
                    let (prev_d, prev_u) = self.prev.open_conns.get(&c.id).copied().unwrap_or((0, 0));
                    let is_new = !self.prev.open_conns.contains_key(&c.id);
                    let cd = c.down.saturating_sub(prev_d);
                    let cu = c.up.saturating_sub(prev_u);
                    next_conns.insert(c.id.clone(), (c.down, c.up));

                    if is_internal_sidecar(&c.path) {
                        sidecar_d = sidecar_d.saturating_add(cd);
                        sidecar_u = sidecar_u.saturating_add(cu);
                        sidecar_active = sidecar_active.saturating_add(1);
                        continue;
                    }

                    sum_d = sum_d.saturating_add(cd);
                    sum_u = sum_u.saturating_add(cu);
                    let (cpd, cpu) = if c.is_proxy { (cd, cu) } else { (0, 0) };
                    sum_pd = sum_pd.saturating_add(cpd);
                    sum_pu = sum_pu.saturating_add(cpu);

                    let key = normalize_app_key(&c.path);
                    let entry = by_app.entry(key.clone()).or_insert_with(|| AppBucket {
                        k: key,
                        n: app_name_from_path(&c.path),
                        p: c.path.clone(),
                        ..Default::default()
                    });
                    entry.d = entry.d.saturating_add(cd);
                    entry.u = entry.u.saturating_add(cu);
                    entry.pd = entry.pd.saturating_add(cpd);
                    entry.pu = entry.pu.saturating_add(cpu);
                    entry.c = entry.c.saturating_add(1);
                    if is_new {
                        entry.tc = entry.tc.saturating_add(1);
                    }
                }
                self.prev.open_conns = next_conns;

                let d_down = raw_d_down.saturating_sub(sidecar_d);
                let d_up = raw_d_up.saturating_sub(sidecar_u);

                // Неучтённый хвост от мгновенных соединений, успевших закрыться за тик.
                let rem_d = d_down.saturating_sub(sum_d);
                let rem_u = d_up.saturating_sub(sum_u);
                if rem_d > 0 || rem_u > 0 {
                    let entry = by_app.entry(String::new()).or_default();
                    entry.d = entry.d.saturating_add(rem_d);
                    entry.u = entry.u.saturating_add(rem_u);
                    entry.pd = entry.pd.saturating_add(rem_d);
                    entry.pu = entry.pu.saturating_add(rem_u);
                    sum_pd = sum_pd.saturating_add(rem_d);
                    sum_pu = sum_pu.saturating_add(rem_u);
                }
                (d_down, d_up, sum_pd.min(d_down), sum_pu.min(d_up), by_app.into_values().collect())
            };

            let d_net = if snap.has_net_metrics {
                let mut net = if reset {
                    snap.net.clone()
                } else {
                    TelemetryNet {
                        tun_rx_packets: snap.net.tun_rx_packets.saturating_sub(self.prev.net.tun_rx_packets),
                        tun_tx_packets: snap.net.tun_tx_packets.saturating_sub(self.prev.net.tun_tx_packets),
                        tun_dropped: snap.net.tun_dropped.saturating_sub(self.prev.net.tun_dropped),
                        udp_dropped: snap.net.udp_dropped.saturating_sub(self.prev.net.udp_dropped),
                        tcp_bytes_out: snap.net.tcp_bytes_out.saturating_sub(self.prev.net.tcp_bytes_out),
                        tcp_bytes_in: snap.net.tcp_bytes_in.saturating_sub(self.prev.net.tcp_bytes_in),
                        tcp_bytes_retrans: snap.net.tcp_bytes_retrans.saturating_sub(self.prev.net.tcp_bytes_retrans),
                        tcp_retrans_events: snap.net.tcp_retrans_events.saturating_sub(self.prev.net.tcp_retrans_events),
                        tcp_rtt_us_sum: snap.net.tcp_rtt_us_sum.saturating_sub(self.prev.net.tcp_rtt_us_sum),
                        tcp_rtt_samples: snap.net.tcp_rtt_samples.saturating_sub(self.prev.net.tcp_rtt_samples),
                        quic_packets_sent: snap.net.quic_packets_sent.saturating_sub(self.prev.net.quic_packets_sent),
                        quic_packets_lost: snap.net.quic_packets_lost.saturating_sub(self.prev.net.quic_packets_lost),
                        dial_ok: snap.net.dial_ok.saturating_sub(self.prev.net.dial_ok),
                        dial_fail: snap.net.dial_fail.saturating_sub(self.prev.net.dial_fail),
                        relay_errors: snap.net.relay_errors.saturating_sub(self.prev.net.relay_errors),
                    }
                };
                if sidecar_err > 0 {
                    let sub_df = sidecar_err.min(net.dial_fail);
                    net.dial_fail -= sub_df;
                    net.relay_errors = net.relay_errors.saturating_sub(sidecar_err - sub_df);
                }
                net
            } else {
                TelemetryNet::default()
            };

            self.prev.download = snap.download;
            self.prev.upload = snap.upload;
            self.prev.proxy_download = snap.proxy_download;
            self.prev.proxy_upload = snap.proxy_upload;
            self.prev.net = snap.net.clone();
            (d_down, d_up, d_pdown, d_pup, d_net, app_deltas, sidecar_active)
        };

        let down_bps = (d_down as f64 / dur_f) as u64;
        let up_bps = (d_up as f64 / dur_f) as u64;

        // Забираем накопившиеся результаты проверок активного сервера.
        let probe = self
            .pending_probe
            .take()
            .filter(|p| p.server_id == server.id || server.id.is_empty());

        let (lat_sum, lat_n, lat_min, lat_max, jit_sum, jit_n, prb_n, prb_fail) =
            if let Some(p) = probe {
                (
                    p.lat_sum,
                    p.lat_n,
                    if p.lat_n > 0 { p.lat_min } else { 0 },
                    p.lat_max,
                    p.jit_sum,
                    p.jit_n,
                    p.total,
                    p.failed,
                )
            } else if let Some(ms) = self.last_rtt.get(&server.id).copied().or(fallback_latency_ms) {
                // Между проверками балансировщика держим последнее измеренное значение,
                // не искажая джиттер.
                (u64::from(ms), 1, ms, ms, 0, 0, 0, 0)
            } else {
                (0, 0, 0, 0, 0, 0, 0, 0)
            };

        let sample = SampleBucket {
            ts: ts_ms,
            dur: dur_s,
            sid: server.id.clone(),
            sn: server.name.clone(),
            sp: server.proto.clone(),
            d: d_down,
            u: d_up,
            pd: d_pdown,
            pu: d_pup,
            pkd: down_bps,
            pku: up_bps,
            lat_sum,
            lat_n,
            lat_min,
            lat_max,
            jit_sum,
            jit_n,
            tcp_out: d_net.tcp_bytes_out,
            tcp_ret: d_net.tcp_bytes_retrans,
            tcp_ev: d_net.tcp_retrans_events,
            q_sent: d_net.quic_packets_sent,
            q_lost: d_net.quic_packets_lost,
            tun_pkts: d_net.tun_rx_packets.saturating_add(d_net.tun_tx_packets),
            tun_drop: d_net.tun_dropped,
            udp_drop: d_net.udp_dropped,
            dial_ok: d_net.dial_ok,
            dial_fail: d_net.dial_fail,
            relay_err: d_net.relay_errors,
            prb_n,
            prb_fail,
            conns: snap.connections.saturating_sub(sidecar_active_conns) as u32,
            apps: app_deltas,
        };

        // Обновляем живую сессию.
        if let Some(active) = self.active.as_mut() {
            active.last_tick_ms = ts_ms + i64::from(dur_s) * 1000;
            active.down_bytes = active.down_bytes.saturating_add(sample.d);
            active.up_bytes = active.up_bytes.saturating_add(sample.u);
            active.peak_down_bps = active.peak_down_bps.max(sample.pkd);
            active.lat_sum = active.lat_sum.saturating_add(sample.lat_sum);
            active.lat_n = active.lat_n.saturating_add(sample.lat_n);
            active.agg.add_bucket(&sample);
            if !sample.sid.is_empty() {
                let entry = active
                    .servers_time
                    .entry(sample.sid.clone())
                    .or_insert_with(|| (sample.sn.clone(), 0));
                if !sample.sn.is_empty() {
                    entry.0 = sample.sn.clone();
                }
                entry.1 = entry.1.saturating_add(u64::from(sample.dur));
            }
        }

        // 1-секундный кольцевой буфер.
        if self.live_1s.len() >= LIVE_1S_CAPACITY {
            self.live_1s.pop_front();
        }
        self.live_1s.push_back(sample.clone());

        // 10-секундный срез для истории и диска.
        let need_flush = match &self.pending_bucket {
            Some(b) => {
                b.sid != sample.sid
                    || b.dur >= BUCKET_SECS
                    || (sample.ts - b.ts) >= i64::from(BUCKET_SECS) * 1000
            }
            None => false,
        };
        if need_flush {
            self.flush_pending_bucket_locked();
        }

        match &mut self.pending_bucket {
            Some(b) => {
                merge_into_bucket(b, &sample);
                merge_apps_into_map(&mut self.pending_apps, &sample.apps);
            }
            None => {
                let mut b = sample.clone();
                let apps = std::mem::take(&mut b.apps);
                merge_apps_into_map(&mut self.pending_apps, &apps);
                self.pending_bucket = Some(b);
            }
        }
    }
}

impl ActiveSession {
    fn to_record(&self, active: bool) -> SessionRecord {
        let duration_s = ((self.last_tick_ms - self.started_ms).max(0) / 1000) as u64;
        let (primary_id, primary_name) = self
            .servers_time
            .iter()
            .max_by_key(|(_, (_, secs))| *secs)
            .map(|(id, (name, _))| (id.clone(), name.clone()))
            .unwrap_or_default();
        let (loss_pct, packets_lost) = self.agg.loss_metrics();
        SessionRecord {
            id: self.id.clone(),
            started_ms: self.started_ms,
            ended_ms: self.last_tick_ms,
            active,
            duration_s,
            primary_server_id: primary_id,
            primary_server_name: primary_name,
            server_count: self.servers_time.len().max(1),
            down_bytes: self.down_bytes,
            up_bytes: self.up_bytes,
            peak_down_bps: self.peak_down_bps,
            avg_latency_ms: (self.lat_n > 0).then(|| (self.lat_sum / u64::from(self.lat_n)) as u32),
            loss_pct,
            packets_lost,
            errors: self.agg.dial_fail.saturating_add(self.agg.relay_err),
        }
    }
}

// --------------------------------------------------------------- helpers

pub fn normalize_app_key(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    #[cfg(windows)]
    {
        trimmed.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        trimmed.to_string()
    }
}

pub fn app_name_from_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    trimmed
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(trimmed)
        .to_string()
}

/// Внутренние сайдкары движка (Xray/sing-box/aura-engine), чей обходной трафик
/// в TUN не является трафиком пользовательских приложений и не должен двоить
/// счётчики или подмешивать фоновые сбои проб в общую статистику.
pub fn is_internal_sidecar(path: &str) -> bool {
    let name = app_name_from_path(path).to_ascii_lowercase();
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    stem == "xray"
        || stem.starts_with("xray-")
        || stem == "sing-box"
        || stem.starts_with("sing-box-")
        || stem == "aura-engine"
        || stem.starts_with("aura-engine-")
}

fn make_app_bucket(
    path: &str,
    d: u64,
    u: u64,
    pd: u64,
    pu: u64,
    c: u32,
    tc: u64,
    e: u64,
) -> AppBucket {
    AppBucket {
        k: normalize_app_key(path),
        n: app_name_from_path(path),
        p: path.trim().to_string(),
        d,
        u,
        pd,
        pu,
        c,
        tc,
        e,
    }
}

fn merge_into_bucket(dst: &mut SampleBucket, src: &SampleBucket) {
    dst.dur = dst.dur.saturating_add(src.dur);
    if dst.sn.is_empty() && !src.sn.is_empty() {
        dst.sn = src.sn.clone();
    }
    if dst.sp.is_empty() && !src.sp.is_empty() {
        dst.sp = src.sp.clone();
    }
    dst.d = dst.d.saturating_add(src.d);
    dst.u = dst.u.saturating_add(src.u);
    dst.pd = dst.pd.saturating_add(src.pd);
    dst.pu = dst.pu.saturating_add(src.pu);
    dst.pkd = dst.pkd.max(src.pkd);
    dst.pku = dst.pku.max(src.pku);
    if src.lat_n > 0 {
        dst.lat_sum = dst.lat_sum.saturating_add(src.lat_sum);
        dst.lat_n = dst.lat_n.saturating_add(src.lat_n);
        if dst.lat_min == 0 || (src.lat_min > 0 && src.lat_min < dst.lat_min) {
            dst.lat_min = src.lat_min;
        }
        dst.lat_max = dst.lat_max.max(src.lat_max);
    }
    if src.jit_n > 0 {
        dst.jit_sum = dst.jit_sum.saturating_add(src.jit_sum);
        dst.jit_n = dst.jit_n.saturating_add(src.jit_n);
    }
    dst.tcp_out = dst.tcp_out.saturating_add(src.tcp_out);
    dst.tcp_ret = dst.tcp_ret.saturating_add(src.tcp_ret);
    dst.tcp_ev = dst.tcp_ev.saturating_add(src.tcp_ev);
    dst.q_sent = dst.q_sent.saturating_add(src.q_sent);
    dst.q_lost = dst.q_lost.saturating_add(src.q_lost);
    dst.tun_pkts = dst.tun_pkts.saturating_add(src.tun_pkts);
    dst.tun_drop = dst.tun_drop.saturating_add(src.tun_drop);
    dst.udp_drop = dst.udp_drop.saturating_add(src.udp_drop);
    dst.dial_ok = dst.dial_ok.saturating_add(src.dial_ok);
    dst.dial_fail = dst.dial_fail.saturating_add(src.dial_fail);
    dst.relay_err = dst.relay_err.saturating_add(src.relay_err);
    dst.prb_n = dst.prb_n.saturating_add(src.prb_n);
    dst.prb_fail = dst.prb_fail.saturating_add(src.prb_fail);
    dst.conns = dst.conns.max(src.conns);
}

fn merge_apps_into_map(map: &mut HashMap<String, AppBucket>, apps: &[AppBucket]) {
    for a in apps {
        let entry = map.entry(a.k.clone()).or_insert_with(|| AppBucket {
            k: a.k.clone(),
            n: a.n.clone(),
            p: a.p.clone(),
            ..Default::default()
        });
        if entry.p.is_empty() && !a.p.is_empty() {
            entry.p = a.p.clone();
        }
        if entry.n.is_empty() && !a.n.is_empty() {
            entry.n = a.n.clone();
        }
        entry.d = entry.d.saturating_add(a.d);
        entry.u = entry.u.saturating_add(a.u);
        entry.pd = entry.pd.saturating_add(a.pd);
        entry.pu = entry.pu.saturating_add(a.pu);
        entry.c = entry.c.max(a.c);
        entry.tc = entry.tc.saturating_add(a.tc);
        entry.e = entry.e.saturating_add(a.e);
    }
}

fn finalize_apps(map: &HashMap<String, AppBucket>) -> Vec<AppBucket> {
    let mut list: Vec<AppBucket> = map
        .values()
        .filter(|a| a.d > 0 || a.u > 0 || a.e > 0 || a.c > 0)
        .cloned()
        .collect();
    list.sort_by(|a, b| (b.d + b.u).cmp(&(a.d + a.u)).then_with(|| b.e.cmp(&a.e)));
    if list.len() > MAX_APPS_PER_BUCKET {
        let tail = list.split_off(MAX_APPS_PER_BUCKET);
        let mut other = AppBucket::default();
        for t in tail {
            other.d = other.d.saturating_add(t.d);
            other.u = other.u.saturating_add(t.u);
            other.pd = other.pd.saturating_add(t.pd);
            other.pu = other.pu.saturating_add(t.pu);
            other.c = other.c.max(t.c);
            other.tc = other.tc.saturating_add(t.tc);
            other.e = other.e.saturating_add(t.e);
        }
        if let Some(existing) = list.iter_mut().find(|a| a.k.is_empty()) {
            existing.d = existing.d.saturating_add(other.d);
            existing.u = existing.u.saturating_add(other.u);
            existing.pd = existing.pd.saturating_add(other.pd);
            existing.pu = existing.pu.saturating_add(other.pu);
            existing.c = existing.c.max(other.c);
            existing.tc = existing.tc.saturating_add(other.tc);
            existing.e = existing.e.saturating_add(other.e);
        } else {
            list.push(other);
        }
    }
    list
}

// --------------------------------------------------------------- loss math

#[derive(Default, Clone)]
struct LossAgg {
    tcp_out: u64,
    tcp_ret: u64,
    tcp_ev: u64,
    q_sent: u64,
    q_lost: u64,
    tun_pkts: u64,
    tun_drop: u64,
    udp_drop: u64,
    dial_ok: u64,
    dial_fail: u64,
    relay_err: u64,
    prb_n: u32,
    prb_fail: u32,
}

impl LossAgg {
    fn add_bucket(&mut self, b: &SampleBucket) {
        self.tcp_out = self.tcp_out.saturating_add(b.tcp_out);
        self.tcp_ret = self.tcp_ret.saturating_add(b.tcp_ret);
        self.tcp_ev = self.tcp_ev.saturating_add(b.tcp_ev);
        self.q_sent = self.q_sent.saturating_add(b.q_sent);
        self.q_lost = self.q_lost.saturating_add(b.q_lost);
        self.tun_pkts = self.tun_pkts.saturating_add(b.tun_pkts);
        self.tun_drop = self.tun_drop.saturating_add(b.tun_drop);
        self.udp_drop = self.udp_drop.saturating_add(b.udp_drop);
        self.dial_ok = self.dial_ok.saturating_add(b.dial_ok);
        self.dial_fail = self.dial_fail.saturating_add(b.dial_fail);
        self.relay_err = self.relay_err.saturating_add(b.relay_err);
        self.prb_n = self.prb_n.saturating_add(b.prb_n);
        self.prb_fail = self.prb_fail.saturating_add(b.prb_fail);
    }

    /// Реальный процент потерь и число потерянных/повторно отправленных пакетов.
    fn loss_metrics(&self) -> (f32, u64) {
        let tcp_lost_pkts = self
            .tcp_ev
            .max(if self.tcp_ret > 0 { self.tcp_ret.div_ceil(1400) } else { 0 });
        let tcp_sent_pkts = if self.tcp_out > 0 {
            self.tcp_out.div_ceil(1400).max(1)
        } else {
            0
        };

        let trans_ratio = if self.q_sent > 0 && tcp_sent_pkts == 0 {
            (self.q_lost as f64 / self.q_sent as f64).clamp(0.0, 1.0)
        } else if self.tcp_out > 0 && self.q_sent == 0 {
            let by_bytes = (self.tcp_ret as f64 / self.tcp_out as f64).clamp(0.0, 1.0);
            let by_ev = (tcp_lost_pkts as f64 / tcp_sent_pkts as f64).clamp(0.0, 1.0);
            by_bytes.max(by_ev).min(1.0)
        } else if self.q_sent > 0 || tcp_sent_pkts > 0 {
            let sent = self.q_sent.saturating_add(tcp_sent_pkts).max(1);
            let lost = self.q_lost.saturating_add(tcp_lost_pkts);
            (lost as f64 / sent as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let local_drops = self.tun_drop.saturating_add(self.udp_drop);
        let tun_ratio = if self.tun_pkts > 0 && local_drops > 0 {
            (local_drops as f64 / self.tun_pkts as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let probe_ratio = if self.prb_n > 0 && self.prb_fail > 0 {
            (f64::from(self.prb_fail) / f64::from(self.prb_n)).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let combined = (1.0 - (1.0 - trans_ratio) * (1.0 - tun_ratio)).max(probe_ratio);
        let loss_pct = ((combined * 1000.0).round() / 10.0).clamp(0.0, 100.0) as f32;
        let packets_lost = tcp_lost_pkts
            .saturating_add(self.q_lost)
            .saturating_add(local_drops)
            .saturating_add(u64::from(self.prb_fail));
        (loss_pct, packets_lost)
    }
}

fn server_health(loss_pct: f32, prb_fail: u32, prb_n: u32, dial_fail: u64, dial_ok: u64) -> String {
    let probe_bad = prb_n >= 2 && (prb_fail as f32 / prb_n as f32) >= 0.15;
    let dial_total = dial_ok.saturating_add(dial_fail);
    let dial_bad = dial_total >= 10 && (dial_fail as f32 / dial_total as f32) >= 0.12;
    if loss_pct >= 5.0 || probe_bad || dial_bad {
        "bad".into()
    } else if loss_pct >= 1.0 || prb_fail > 0 || (dial_total >= 10 && (dial_fail as f32 / dial_total as f32) >= 0.03) {
        "warn".into()
    } else {
        "good".into()
    }
}

// --------------------------------------------------------------- report builder

fn build_report(
    all_buckets: Vec<SampleBucket>,
    q: &StatsQuery,
    from_ms: i64,
    to_ms: i64,
    sessions: Vec<SessionRecord>,
    storage: StorageInfo,
) -> StatsReport {
    // 1. Сводка по VPN-серверам строится по всем серверам в периоде (до фильтра server_id),
    //    чтобы пользователь мог сравнивать серверы и переключаться между ними в таблице.
    let servers = aggregate_servers(&all_buckets);

    // 2. Применяем фильтр по серверу, если выбран.
    let server_filter = q.server_id.as_deref().filter(|s| !s.is_empty());
    let filtered: Vec<SampleBucket> = match server_filter {
        Some(sid) => all_buckets.into_iter().filter(|b| b.sid == sid).collect(),
        None => all_buckets,
    };

    if filtered.is_empty() {
        return StatsReport {
            summary: StatsSummary {
                from_ms,
                to_ms,
                has_data: false,
                ..Default::default()
            },
            servers,
            sessions,
            storage,
            ..Default::default()
        };
    }

    let app_filter = q
        .app_key
        .as_deref()
        .map(normalize_app_key)
        .filter(|s| !s.is_empty());

    // 3. Сводные KPI и полный список приложений за период.
    let summary = aggregate_summary(&filtered, from_ms, to_ms);
    let apps = aggregate_apps(&filtered);

    // 4. Даунсэмплинг до ~96 точек графика + разбивка приложений на каждую точку.
    let max_points = q.max_points.unwrap_or(DEFAULT_MAX_POINTS).clamp(16, 240);
    let (points, point_app_lists) = build_chart_points(&filtered, max_points, app_filter.as_deref());

    // 5. Если пользователь кликнул точку на графике (Argus-режим) — отдаём её приложения.
    let (pinned_point, pinned_apps) = match q.pinned_index {
        Some(idx) if idx < points.len() => (Some(points[idx].clone()), point_app_lists[idx].clone()),
        _ => (None, Vec::new()),
    };

    StatsReport {
        summary,
        points,
        apps,
        pinned_point,
        pinned_apps,
        servers,
        sessions,
        storage,
    }
}

fn aggregate_summary(buckets: &[SampleBucket], from_ms: i64, to_ms: i64) -> StatsSummary {
    let mut down = 0u64;
    let mut up = 0u64;
    let mut pdown = 0u64;
    let mut pup = 0u64;
    let mut peak_d = 0u64;
    let mut peak_u = 0u64;
    let mut dur_s = 0u64;
    let mut lat_sum = 0u64;
    let mut lat_n = 0u32;
    let mut lat_min = u32::MAX;
    let mut lat_max = 0u32;
    let mut jit_sum = 0u64;
    let mut jit_n = 0u32;
    let mut loss = LossAgg::default();

    for b in buckets {
        down = down.saturating_add(b.d);
        up = up.saturating_add(b.u);
        pdown = pdown.saturating_add(b.pd);
        pup = pup.saturating_add(b.pu);
        peak_d = peak_d.max(b.pkd);
        peak_u = peak_u.max(b.pku);
        dur_s = dur_s.saturating_add(u64::from(b.dur.max(1)));
        if b.lat_n > 0 {
            lat_sum = lat_sum.saturating_add(b.lat_sum);
            lat_n = lat_n.saturating_add(b.lat_n);
            if b.lat_min > 0 {
                lat_min = lat_min.min(b.lat_min);
            }
            lat_max = lat_max.max(b.lat_max);
        }
        if b.jit_n > 0 {
            jit_sum = jit_sum.saturating_add(b.jit_sum);
            jit_n = jit_n.saturating_add(b.jit_n);
        }
        loss.add_bucket(b);
    }

    let total = down.saturating_add(up);
    let proxy = pdown.saturating_add(pup).min(total);
    let direct = total.saturating_sub(proxy);
    let (loss_pct, packets_lost) = loss.loss_metrics();

    StatsSummary {
        down_bytes: down,
        up_bytes: up,
        total_bytes: total,
        proxy_bytes: proxy,
        direct_bytes: direct,
        avg_down_bps: if dur_s > 0 { down / dur_s } else { 0 },
        peak_down_bps: peak_d,
        avg_up_bps: if dur_s > 0 { up / dur_s } else { 0 },
        peak_up_bps: peak_u,
        avg_latency_ms: (lat_n > 0).then(|| (lat_sum / u64::from(lat_n)) as u32),
        min_latency_ms: (lat_n > 0 && lat_min < u32::MAX).then_some(lat_min),
        max_latency_ms: (lat_n > 0 && lat_max > 0).then_some(lat_max),
        jitter_ms: (jit_n > 0).then(|| (jit_sum / u64::from(jit_n)) as u32),
        loss_pct,
        packets_lost,
        retrans_events: loss.tcp_ev,
        tun_drops: loss.tun_drop,
        udp_drops: loss.udp_drop,
        dial_fails: loss.dial_fail,
        relay_errors: loss.relay_err,
        probe_fails: loss.prb_fail,
        probe_total: loss.prb_n,
        duration_s: dur_s,
        has_data: true,
        from_ms,
        to_ms,
    }
}

fn aggregate_apps(buckets: &[SampleBucket]) -> Vec<AppStats> {
    struct Accum {
        key: String,
        name: String,
        path: String,
        down: u64,
        up: u64,
        proxy: u64,
        peak_bps: u64,
        active_conns: u32,
        total_conns: u64,
        errors: u64,
    }

    let mut map: HashMap<String, Accum> = HashMap::new();
    let mut grand_total = 0u64;

    for b in buckets {
        let dur = u64::from(b.dur.max(1));
        for a in &b.apps {
            let entry = map.entry(a.k.clone()).or_insert_with(|| Accum {
                key: a.k.clone(),
                name: a.n.clone(),
                path: a.p.clone(),
                down: 0,
                up: 0,
                proxy: 0,
                peak_bps: 0,
                active_conns: 0,
                total_conns: 0,
                errors: 0,
            });
            if entry.path.is_empty() && !a.p.is_empty() {
                entry.path = a.p.clone();
            }
            if entry.name.is_empty() && !a.n.is_empty() {
                entry.name = a.n.clone();
            }
            entry.down = entry.down.saturating_add(a.d);
            entry.up = entry.up.saturating_add(a.u);
            entry.proxy = entry.proxy.saturating_add(a.pd.saturating_add(a.pu));
            entry.peak_bps = entry.peak_bps.max((a.d.saturating_add(a.u)) / dur);
            entry.active_conns = entry.active_conns.max(a.c);
            entry.total_conns = entry.total_conns.saturating_add(a.tc);
            entry.errors = entry.errors.saturating_add(a.e);
            grand_total = grand_total.saturating_add(a.d.saturating_add(a.u));
        }
    }

    let mut out: Vec<AppStats> = map
        .into_values()
        .filter(|a| a.down > 0 || a.up > 0 || a.errors > 0 || a.active_conns > 0)
        .map(|a| {
            let total = a.down.saturating_add(a.up);
            let proxy = a.proxy.min(total);
            let direct = total.saturating_sub(proxy);
            let share_pct = if grand_total > 0 {
                ((total as f64 / grand_total as f64) * 1000.0).round() as f32 / 10.0
            } else {
                0.0
            };
            let vpn_pct = if total > 0 {
                ((proxy as f64 / total as f64) * 1000.0).round() as f32 / 10.0
            } else {
                0.0
            };
            AppStats {
                key: a.key,
                name: a.name,
                path: a.path,
                down_bytes: a.down,
                up_bytes: a.up,
                total_bytes: total,
                proxy_bytes: proxy,
                direct_bytes: direct,
                peak_bps: a.peak_bps,
                share_pct,
                vpn_pct,
                active_conns: a.active_conns,
                total_conns: a.total_conns.max(u64::from(a.active_conns)),
                errors: a.errors,
            }
        })
        .collect();

    out.sort_by(|a, b| {
        b.total_bytes
            .cmp(&a.total_bytes)
            .then_with(|| b.errors.cmp(&a.errors))
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

fn aggregate_servers(buckets: &[SampleBucket]) -> Vec<ServerStats> {
    struct Accum {
        id: String,
        name: String,
        proto: String,
        dur_s: u64,
        down: u64,
        up: u64,
        peak_d: u64,
        peak_u: u64,
        lat_sum: u64,
        lat_n: u32,
        lat_min: u32,
        lat_max: u32,
        jit_sum: u64,
        jit_n: u32,
        loss: LossAgg,
    }

    let mut map: HashMap<String, Accum> = HashMap::new();
    for b in buckets {
        if b.sid.is_empty() && b.sn.is_empty() {
            continue;
        }
        let key = if b.sid.is_empty() { b.sn.clone() } else { b.sid.clone() };
        let entry = map.entry(key.clone()).or_insert_with(|| Accum {
            id: key,
            name: b.sn.clone(),
            proto: b.sp.clone(),
            dur_s: 0,
            down: 0,
            up: 0,
            peak_d: 0,
            peak_u: 0,
            lat_sum: 0,
            lat_n: 0,
            lat_min: u32::MAX,
            lat_max: 0,
            jit_sum: 0,
            jit_n: 0,
            loss: LossAgg::default(),
        });
        if entry.name.is_empty() && !b.sn.is_empty() {
            entry.name = b.sn.clone();
        }
        if entry.proto.is_empty() && !b.sp.is_empty() {
            entry.proto = b.sp.clone();
        }
        entry.dur_s = entry.dur_s.saturating_add(u64::from(b.dur.max(1)));
        entry.down = entry.down.saturating_add(b.d);
        entry.up = entry.up.saturating_add(b.u);
        entry.peak_d = entry.peak_d.max(b.pkd);
        entry.peak_u = entry.peak_u.max(b.pku);
        if b.lat_n > 0 {
            entry.lat_sum = entry.lat_sum.saturating_add(b.lat_sum);
            entry.lat_n = entry.lat_n.saturating_add(b.lat_n);
            if b.lat_min > 0 {
                entry.lat_min = entry.lat_min.min(b.lat_min);
            }
            entry.lat_max = entry.lat_max.max(b.lat_max);
        }
        if b.jit_n > 0 {
            entry.jit_sum = entry.jit_sum.saturating_add(b.jit_sum);
            entry.jit_n = entry.jit_n.saturating_add(b.jit_n);
        }
        entry.loss.add_bucket(b);
    }

    let mut list: Vec<ServerStats> = map
        .into_values()
        .map(|a| {
            let (loss_pct, packets_lost) = a.loss.loss_metrics();
            let health = server_health(
                loss_pct,
                a.loss.prb_fail,
                a.loss.prb_n,
                a.loss.dial_fail,
                a.loss.dial_ok,
            );
            let total = a.down.saturating_add(a.up);
            ServerStats {
                server_id: a.id,
                server_name: a.name,
                server_proto: a.proto,
                duration_s: a.dur_s,
                down_bytes: a.down,
                up_bytes: a.up,
                total_bytes: total,
                avg_down_bps: if a.dur_s > 0 { a.down / a.dur_s } else { 0 },
                peak_down_bps: a.peak_d,
                avg_up_bps: if a.dur_s > 0 { a.up / a.dur_s } else { 0 },
                peak_up_bps: a.peak_u,
                avg_latency_ms: (a.lat_n > 0).then(|| (a.lat_sum / u64::from(a.lat_n)) as u32),
                min_latency_ms: (a.lat_n > 0 && a.lat_min < u32::MAX).then_some(a.lat_min),
                max_latency_ms: (a.lat_n > 0 && a.lat_max > 0).then_some(a.lat_max),
                jitter_ms: (a.jit_n > 0).then(|| (a.jit_sum / u64::from(a.jit_n)) as u32),
                loss_pct,
                packets_lost,
                retrans_events: a.loss.tcp_ev,
                dial_fails: a.loss.dial_fail,
                relay_errors: a.loss.relay_err,
                probe_fails: a.loss.prb_fail,
                probe_total: a.loss.prb_n,
                health,
            }
        })
        .collect();

    list.sort_by(|a, b| {
        b.total_bytes
            .cmp(&a.total_bytes)
            .then_with(|| b.duration_s.cmp(&a.duration_s))
    });
    list
}

fn build_chart_points(
    buckets: &[SampleBucket],
    max_points: usize,
    app_filter: Option<&str>,
) -> (Vec<ChartPoint>, Vec<Vec<AppStats>>) {
    let n = buckets.len();
    if n == 0 {
        return (Vec::new(), Vec::new());
    }
    let chunk = n.div_ceil(max_points).max(1);
    let mut points = Vec::with_capacity(n.div_ceil(chunk));
    let mut app_lists = Vec::with_capacity(n.div_ceil(chunk));

    for group in buckets.chunks(chunk) {
        let ts_ms = group.first().map(|b| b.ts).unwrap_or(0);
        let end_ms = group
            .last()
            .map(|b| b.ts + i64::from(b.dur.max(1)) * 1000)
            .unwrap_or(ts_ms);
        let mut dur_s = 0u32;
        let mut down = 0u64;
        let mut up = 0u64;
        let mut pdown = 0u64;
        let mut pup = 0u64;
        let mut app_down = 0u64;
        let mut app_up = 0u64;
        let mut lat_sum = 0u64;
        let mut lat_n = 0u32;
        let mut conns = 0u32;
        let mut loss = LossAgg::default();
        let mut srv_time: HashMap<&str, (&str, &str, u32)> = HashMap::new();

        for b in group {
            let d = b.dur.max(1);
            dur_s = dur_s.saturating_add(d);
            down = down.saturating_add(b.d);
            up = up.saturating_add(b.u);
            pdown = pdown.saturating_add(b.pd);
            pup = pup.saturating_add(b.pu);
            if b.lat_n > 0 {
                lat_sum = lat_sum.saturating_add(b.lat_sum);
                lat_n = lat_n.saturating_add(b.lat_n);
            }
            conns = conns.max(b.conns);
            loss.add_bucket(b);
            if !b.sid.is_empty() {
                let e = srv_time
                    .entry(b.sid.as_str())
                    .or_insert((b.sn.as_str(), b.sp.as_str(), 0));
                e.2 = e.2.saturating_add(d);
            }
            if let Some(target_key) = app_filter {
                for a in &b.apps {
                    if a.k == target_key {
                        app_down = app_down.saturating_add(a.d);
                        app_up = app_up.saturating_add(a.u);
                    }
                }
            }
        }

        let (server_id, server_name, server_proto) = srv_time
            .into_iter()
            .max_by_key(|(_, (_, _, t))| *t)
            .map(|(id, (name, proto, _))| (id.to_string(), name.to_string(), proto.to_string()))
            .unwrap_or_default();

        let (loss_pct, packets_lost) = loss.loss_metrics();
        let dur_u64 = u64::from(dur_s.max(1));
        let group_apps = aggregate_apps(group);
        let top_apps = group_apps
            .iter()
            .take(5)
            .map(|a| PointAppSummary {
                key: a.key.clone(),
                name: a.name.clone(),
                path: a.path.clone(),
                bytes: a.total_bytes,
                down_bytes: a.down_bytes,
                up_bytes: a.up_bytes,
            })
            .collect();

        points.push(ChartPoint {
            ts_ms,
            end_ms,
            dur_s,
            down_bps: down / dur_u64,
            up_bps: up / dur_u64,
            proxy_down_bps: pdown / dur_u64,
            proxy_up_bps: pup / dur_u64,
            app_down_bps: app_down / dur_u64,
            app_up_bps: app_up / dur_u64,
            down_bytes: down,
            up_bytes: up,
            latency_ms: (lat_n > 0).then(|| (lat_sum / u64::from(lat_n)) as u32),
            loss_pct,
            packets_lost,
            errors: loss.dial_fail.saturating_add(loss.relay_err),
            connections: conns,
            server_id,
            server_name,
            server_proto,
            top_apps,
        });
        app_lists.push(group_apps);
    }

    (points, app_lists)
}

// --------------------------------------------------------------- disk I/O

fn date_of_ms(ts_ms: i64) -> NaiveDate {
    Utc.timestamp_millis_opt(ts_ms)
        .single()
        .map(|dt: DateTime<Utc>| dt.date_naive())
        .unwrap_or_else(|| Utc::now().date_naive())
}

fn parse_day_filename(name: &str) -> Option<(NaiveDate, bool)> {
    if let Some(stem) = name.strip_suffix(".jsonl.gz") {
        NaiveDate::parse_from_str(stem, "%Y-%m-%d").ok().map(|d| (d, true))
    } else if let Some(stem) = name.strip_suffix(".jsonl") {
        NaiveDate::parse_from_str(stem, "%Y-%m-%d").ok().map(|d| (d, false))
    } else {
        None
    }
}

fn compress_past_days(dir: &Path, today: NaiveDate) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else { continue };
        let Some((day, is_gz)) = parse_day_filename(name_str) else { continue };
        if is_gz || day >= today {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dir.join(format!("{}.jsonl.gz", day.format("%Y-%m-%d")));
        let tmp_path = dir.join(format!("{}.jsonl.gz.tmp", day.format("%Y-%m-%d")));
        if dst_path.exists() {
            let _ = fs::remove_file(&src_path);
            continue;
        }
        let ok = (|| -> std::io::Result<()> {
            let mut input = File::open(&src_path)?;
            let out = File::create(&tmp_path)?;
            let mut encoder = GzEncoder::new(out, Compression::fast());
            std::io::copy(&mut input, &mut encoder)?;
            encoder.finish()?;
            fs::rename(&tmp_path, &dst_path)?;
            Ok(())
        })();
        if ok.is_ok() {
            let _ = fs::remove_file(&src_path);
        } else {
            let _ = fs::remove_file(&tmp_path);
        }
    }
}

fn prune_old_files(dir: &Path, today: NaiveDate, retention_days: u32) {
    let cutoff = today - Duration::days(i64::from(retention_days));
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else { continue };
        let Some((day, _)) = parse_day_filename(name_str) else { continue };
        if day < cutoff {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn prune_sessions_file(dir: &Path, retention_days: u32) {
    let path = dir.join("sessions.jsonl");
    if !path.is_file() {
        return;
    }
    let cutoff_ms = now_ms() - i64::from(retention_days) * 86_400_000;
    let all = load_sessions(dir);
    let kept: Vec<&SessionRecord> = all.iter().filter(|s| s.ended_ms >= cutoff_ms).collect();
    if kept.len() == all.len() {
        return;
    }
    let tmp = dir.join("sessions.jsonl.tmp");
    if let Ok(file) = File::create(&tmp) {
        let mut w = BufWriter::new(file);
        for rec in kept {
            if serde_json::to_writer(&mut w, rec).is_ok() {
                let _ = w.write_all(b"\n");
            }
        }
        if w.flush().is_ok() {
            let _ = fs::rename(&tmp, &path);
        } else {
            let _ = fs::remove_file(&tmp);
        }
    }
}

fn compute_storage_info(dir: &Path, retention_days: u32) -> StorageInfo {
    let mut bytes = 0u64;
    let mut days = HashSet::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                bytes = bytes.saturating_add(meta.len());
            }
            if let Some(name) = entry.file_name().to_str() {
                if let Some((day, _)) = parse_day_filename(name) {
                    days.insert(day);
                }
            }
        }
    }
    StorageInfo {
        bytes_on_disk: bytes,
        days_stored: days.len() as u32,
        retention_days,
    }
}

fn read_jsonl_reader<R: BufRead>(reader: R, from_ms: i64, to_ms: i64, out: &mut Vec<SampleBucket>) {
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.is_empty() {
            continue;
        }
        // Незавершённая последняя строка после аварийного выключения просто пропускается.
        let Ok(b) = serde_json::from_str::<SampleBucket>(&line) else { continue };
        let end = b.ts + i64::from(b.dur.max(1)) * 1000;
        if end >= from_ms && b.ts <= to_ms {
            out.push(b);
        }
    }
}

fn load_buckets_range(dir: &Path, from_ms: i64, to_ms: i64) -> Vec<SampleBucket> {
    let start_day = date_of_ms(from_ms) - Duration::days(1);
    let end_day = date_of_ms(to_ms) + Duration::days(1);
    let mut out = Vec::new();
    let mut day = start_day;
    while day <= end_day {
        let stem = day.format("%Y-%m-%d").to_string();
        let gz_path = dir.join(format!("{stem}.jsonl.gz"));
        let raw_path = dir.join(format!("{stem}.jsonl"));
        if gz_path.is_file() {
            if let Ok(file) = File::open(&gz_path) {
                let reader = BufReader::new(GzDecoder::new(file));
                read_jsonl_reader(reader, from_ms, to_ms, &mut out);
            }
        }
        if raw_path.is_file() {
            if let Ok(file) = File::open(&raw_path) {
                let reader = BufReader::new(file);
                read_jsonl_reader(reader, from_ms, to_ms, &mut out);
            }
        }
        day = match day.succ_opt() {
            Some(next) => next,
            None => break,
        };
    }
    out.sort_by_key(|b| b.ts);
    out
}

/// Объединить историю с диска с текущей оперативной сессией (убирая дубликаты по `ts`,
/// если часть текущей сессии уже записалась на диск).
fn merge_disk_and_mem(
    dir: &Path,
    from_ms: i64,
    to_ms: i64,
    session_buckets: &[SampleBucket],
    pending: Option<&SampleBucket>,
) -> Vec<SampleBucket> {
    let mut out = load_buckets_range(dir, from_ms, to_ms);
    let seen: HashSet<i64> = out.iter().map(|b| b.ts).collect();
    for b in session_buckets {
        let end = b.ts + i64::from(b.dur.max(1)) * 1000;
        if end >= from_ms && b.ts <= to_ms && !seen.contains(&b.ts) {
            out.push(b.clone());
        }
    }
    if let Some(p) = pending {
        let end = p.ts + i64::from(p.dur.max(1)) * 1000;
        if end >= from_ms && p.ts <= to_ms && !seen.contains(&p.ts) {
            out.push(p.clone());
        }
    }
    out.sort_by_key(|b| b.ts);
    out
}

fn load_sessions(dir: &Path) -> Vec<SessionRecord> {
    let path = dir.join("sessions.jsonl");
    let Ok(file) = File::open(&path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else { break };
        if let Ok(rec) = serde_json::from_str::<SessionRecord>(&line) {
            out.push(rec);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aurora-stats-test-{tag}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn srv(id: &str, name: &str) -> ServerContext {
        ServerContext {
            id: id.into(),
            name: name.into(),
            proto: "VLESS".into(),
        }
    }

    #[test]
    fn records_per_app_deltas_loss_and_pinned_moment() {
        let dir = temp_dir("pinned");
        let rec = StatsRecorder::new(dir.clone(), 30);
        let t0 = now_ms() - 30_000;
        rec.start_session(srv("s1", "Poland"), t0);

        // Тик 0 — база.
        rec.record_tick(t0, 1.0, srv("s1", "Poland"), &TelemetrySnapshot {
            apps_cumulative: true,
            has_net_metrics: true,
            ..Default::default()
        }, Some(50));

        // Тик 1 — Chrome скачал 2 МБ через VPN, 5% ретрансмитов.
        rec.record_probe("s1", Some(48));
        rec.record_tick(t0 + 1000, 1.0, srv("s1", "Poland"), &TelemetrySnapshot {
            download: 2_000_000,
            upload: 200_000,
            proxy_download: 2_000_000,
            proxy_upload: 200_000,
            connections: 12,
            has_net_metrics: true,
            apps_cumulative: true,
            net: TelemetryNet {
                tcp_bytes_out: 200_000,
                tcp_bytes_retrans: 10_000,
                tcp_retrans_events: 7,
                dial_ok: 12,
                dial_fail: 1,
                ..Default::default()
            },
            apps: vec![TelemetryApp {
                path: r"C:\Program Files\Google\Chrome\chrome.exe".into(),
                down: 2_000_000,
                up: 200_000,
                proxy_down: 2_000_000,
                proxy_up: 200_000,
                active_conns: 12,
                total_conns: 15,
                errors: 1,
            }],
            ..Default::default()
        }, Some(48));

        // Тик 2 — Steam скачал 5 МБ напрямую, без потерь.
        rec.record_probe("s1", Some(54));
        rec.record_tick(t0 + 2000, 1.0, srv("s1", "Poland"), &TelemetrySnapshot {
            download: 7_000_000,
            upload: 300_000,
            proxy_download: 2_000_000,
            proxy_upload: 200_000,
            direct_download: 5_000_000,
            direct_upload: 100_000,
            connections: 8,
            has_net_metrics: true,
            apps_cumulative: true,
            net: TelemetryNet {
                tcp_bytes_out: 300_000,
                tcp_bytes_retrans: 10_000,
                tcp_retrans_events: 7,
                dial_ok: 20,
                dial_fail: 1,
                ..Default::default()
            },
            apps: vec![
                TelemetryApp {
                    path: r"C:\Program Files\Google\Chrome\chrome.exe".into(),
                    down: 2_000_000,
                    up: 200_000,
                    proxy_down: 2_000_000,
                    proxy_up: 200_000,
                    active_conns: 2,
                    total_conns: 15,
                    errors: 1,
                },
                TelemetryApp {
                    path: r"C:\Program Files (x86)\Steam\steam.exe".into(),
                    down: 5_000_000,
                    up: 100_000,
                    proxy_down: 0,
                    proxy_up: 0,
                    active_conns: 6,
                    total_conns: 8,
                    errors: 0,
                },
            ],
            open_conns: Vec::new(),
        }, Some(54));

        // Запрос всей сессии + закреплённая точка #2 (момент Steam).
        let report = rec.query(&StatsQuery {
            range: StatsRange::Session,
            pinned_index: Some(2),
            ..Default::default()
        });
        assert!(report.summary.has_data);
        assert_eq!(report.summary.down_bytes, 7_000_000);
        assert_eq!(report.summary.proxy_bytes, 2_200_000);
        assert_eq!(report.summary.direct_bytes, 5_100_000);
        assert_eq!(report.summary.jitter_ms, Some(6));
        assert!(report.summary.loss_pct > 2.0);
        assert_eq!(report.apps.len(), 2);
        assert_eq!(report.apps[0].name, "steam.exe");
        assert_eq!(report.apps[1].name, "chrome.exe");

        // В закреплённой точке #2 активен именно Steam на 5.1 МБ.
        assert!(report.pinned_point.is_some());
        assert_eq!(report.pinned_apps[0].name, "steam.exe");
        assert_eq!(report.pinned_apps[0].down_bytes, 5_000_000);

        // В таблице серверов есть Poland с реальными потерями и ошибкой.
        assert_eq!(report.servers.len(), 1);
        assert_eq!(report.servers[0].server_name, "Poland");
        assert_eq!(report.servers[0].dial_fails, 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compresses_past_days_prunes_by_retention_and_survives_corrupt_tail() {
        let dir = temp_dir("retention");
        let today = Utc::now().date_naive();
        let old_day = today - Duration::days(45);
        let recent_day = today - Duration::days(3);

        let b_old = SampleBucket {
            ts: old_day.and_hms_opt(12, 0, 0).unwrap().and_utc().timestamp_millis(),
            dur: 10,
            sid: "s1".into(),
            sn: "Old".into(),
            d: 1000,
            ..Default::default()
        };
        let b_recent = SampleBucket {
            ts: recent_day.and_hms_opt(12, 0, 0).unwrap().and_utc().timestamp_millis(),
            dur: 10,
            sid: "s2".into(),
            sn: "Recent".into(),
            d: 4000,
            ..Default::default()
        };

        let old_file = dir.join(format!("{}.jsonl", old_day.format("%Y-%m-%d")));
        let recent_file = dir.join(format!("{}.jsonl", recent_day.format("%Y-%m-%d")));
        fs::write(&old_file, format!("{}\n", serde_json::to_string(&b_old).unwrap())).unwrap();
        // Добавляем битую последнюю строку — чтение обязано её пережить.
        fs::write(
            &recent_file,
            format!("{}\n{{\"ts\":123,\"broken", serde_json::to_string(&b_recent).unwrap()),
        )
        .unwrap();

        let rec = StatsRecorder::new(dir.clone(), 30);
        // 45-дневный файл удалён, 3-дневный сжат в .jsonl.gz.
        assert!(!old_file.exists());
        assert!(!dir.join(format!("{}.jsonl.gz", old_day.format("%Y-%m-%d"))).exists());
        assert!(!recent_file.exists());
        assert!(dir.join(format!("{}.jsonl.gz", recent_day.format("%Y-%m-%d"))).exists());

        let report = rec.query(&StatsQuery {
            range: StatsRange::Days30,
            ..Default::default()
        });
        assert_eq!(report.summary.down_bytes, 4000);
        assert_eq!(report.servers[0].server_name, "Recent");

        let info = rec.clear_history();
        assert_eq!(info.bytes_on_disk, 0);
        assert_eq!(info.days_stored, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_zero_keeps_session_in_memory_without_disk_writes() {
        let dir = temp_dir("memonly");
        let rec = StatsRecorder::new(dir.clone(), 0);
        let t0 = now_ms() - 15_000;
        rec.start_session(srv("s1", "DE"), t0);
        rec.record_tick(t0, 1.0, srv("s1", "DE"), &TelemetrySnapshot::default(), None);
        rec.record_tick(t0 + 1000, 1.0, srv("s1", "DE"), &TelemetrySnapshot {
            download: 500_000,
            upload: 50_000,
            apps_cumulative: true,
            ..Default::default()
        }, None);
        rec.end_session();

        let info = rec.storage_info();
        assert_eq!(info.bytes_on_disk, 0);
        let report = rec.query(&StatsQuery {
            range: StatsRange::Session,
            ..Default::default()
        });
        assert_eq!(report.summary.down_bytes, 500_000);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn internal_sidecars_are_excluded_from_stats_and_errors() {
        assert!(is_internal_sidecar(r"C:\Program Files\Aurora\xray.exe"));
        assert!(is_internal_sidecar("/usr/bin/xray-x86_64-unknown-linux-gnu"));
        assert!(is_internal_sidecar(r"C:\app\sing-box.exe"));
        assert!(!is_internal_sidecar(r"C:\Users\me\Discord.exe"));

        let dir = temp_dir("sidecar");
        let rec = StatsRecorder::new(dir.clone(), 0);
        let t0 = now_ms() - 10_000;
        rec.start_session(srv("s1", "PL"), t0);
        rec.record_tick(t0, 1.0, srv("s1", "PL"), &TelemetrySnapshot::default(), None);
        rec.record_tick(
            t0 + 1000,
            1.0,
            srv("s1", "PL"),
            &TelemetrySnapshot {
                download: 1_500_000,
                upload: 500_000,
                proxy_download: 400_000,
                proxy_upload: 100_000,
                connections: 12,
                has_net_metrics: true,
                net: TelemetryNet {
                    dial_fail: 54,
                    relay_errors: 2,
                    ..Default::default()
                },
                apps_cumulative: true,
                apps: vec![
                    TelemetryApp {
                        path: r"C:\app\xray.exe".into(),
                        down: 1_100_000,
                        up: 400_000,
                        proxy_down: 0,
                        proxy_up: 0,
                        active_conns: 10,
                        total_conns: 109,
                        errors: 52,
                    },
                    TelemetryApp {
                        path: r"C:\app\Discord.exe".into(),
                        down: 400_000,
                        up: 100_000,
                        proxy_down: 400_000,
                        proxy_up: 100_000,
                        active_conns: 2,
                        total_conns: 5,
                        errors: 0,
                    },
                ],
                ..Default::default()
            },
            Some(95),
        );
        let report = rec.query(&StatsQuery {
            range: StatsRange::Session,
            ..Default::default()
        });
        assert_eq!(report.apps.len(), 1);
        assert_eq!(report.apps[0].name, "Discord.exe");
        assert_eq!(report.summary.down_bytes, 400_000);
        assert_eq!(report.summary.up_bytes, 100_000);
        assert_eq!(report.summary.dial_fails, 2);
        assert_eq!(report.summary.relay_errors, 2);

        let _ = fs::remove_dir_all(&dir);
    }
}
