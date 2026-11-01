//! Журнал в формате sing-box: `+0000 2026-11-01 12:00:00 INFO sub: текст`.
//! Приложение разбирает строку `core::log::classify`, поэтому колонка уровня
//! обязана идти сразу за временем и большими буквами.
//!
//! Жизнь отдельных соединений пишется на DEBUG: sing-box на INFO пишет строку на
//! каждое соединение, и это заметная часть его работы под нагрузкой.

use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Журнал в виде функции `(уровень, текст)`: так его читает приложение, когда движок
/// живёт в его процессе.
pub type LogSink = Arc<dyn Fn(&str, &str) + Send + Sync>;

static SINK: RwLock<Option<LogSink>> = RwLock::new(None);

pub fn set_sink(sink: Option<LogSink>) {
    if let Ok(mut slot) = SINK.write() {
        *slot = sink;
    }
}

pub fn set_level(name: &str) {
    let level = match name.to_ascii_lowercase().as_str() {
        "trace" => Level::Trace,
        "debug" => Level::Debug,
        "warn" | "warning" => Level::Warn,
        "error" | "fatal" | "panic" => Level::Error,
        _ => Level::Info,
    };
    LEVEL.store(level as u8, Ordering::Relaxed);
}

#[inline]
pub fn enabled(level: Level) -> bool {
    level as u8 >= LEVEL.load(Ordering::Relaxed)
}

/// Гражданская дата из дней с эпохи (Howard Hinnant, `civil_from_days`).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

pub fn write(level: Level, sub: &str, args: std::fmt::Arguments<'_>) {
    let sink = SINK.read().ok().and_then(|slot| slot.clone());
    if let Some(sink) = sink {
        let name = match level {
            Level::Trace => "trace",
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        };
        sink(name, &format!("{sub}: {args}"));
        return;
    }
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, mo, d) = civil(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    let name = match level {
        Level::Trace => "TRACE",
        Level::Debug => "DEBUG",
        Level::Info => "INFO",
        Level::Warn => "WARN",
        Level::Error => "ERROR",
    };
    let line = format!(
        "+0000 {y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02} {name} {sub}: {args}\n",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    );
    // Закрытый пайп (приложение ушло) — не повод падать.
    let _ = std::io::stdout().write_all(line.as_bytes());
}

#[macro_export]
macro_rules! log_at {
    ($level:expr, $sub:expr, $($arg:tt)*) => {
        if $crate::log::enabled($level) {
            $crate::log::write($level, $sub, format_args!($($arg)*));
        }
    };
}
#[macro_export]
macro_rules! trace { ($sub:expr, $($arg:tt)*) => { $crate::log_at!($crate::log::Level::Trace, $sub, $($arg)*) }; }
#[macro_export]
macro_rules! debug { ($sub:expr, $($arg:tt)*) => { $crate::log_at!($crate::log::Level::Debug, $sub, $($arg)*) }; }
#[macro_export]
macro_rules! info { ($sub:expr, $($arg:tt)*) => { $crate::log_at!($crate::log::Level::Info, $sub, $($arg)*) }; }
#[macro_export]
macro_rules! warn { ($sub:expr, $($arg:tt)*) => { $crate::log_at!($crate::log::Level::Warn, $sub, $($arg)*) }; }
#[macro_export]
macro_rules! error { ($sub:expr, $($arg:tt)*) => { $crate::log_at!($crate::log::Level::Error, $sub, $($arg)*) }; }

#[cfg(test)]
mod tests {
    use super::civil;

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_758), (2026, 11, 1));
        assert_eq!(civil(11_016), (2000, 2, 29));
    }
}
