//! Log-line model shared by every engine driver: the desktop process
//! supervisor parses captured stdout/stderr, the Android driver parses the
//! file libbox writes. Both feed the same ring buffer and UI pipeline.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// Enough history to diagnose a failed handshake without growing unbounded.
pub const LOG_CAPACITY: usize = 3000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogLine {
    pub seq: u64,
    pub level: String,
    pub text: String,
}

#[derive(Default)]
pub struct LogBuffer {
    lines: VecDeque<LogLine>,
    next_seq: u64,
}

impl LogBuffer {
    pub fn push(&mut self, level: String, text: String) -> LogLine {
        let line = LogLine {
            seq: self.next_seq,
            level,
            text,
        };
        self.next_seq += 1;
        if self.lines.len() >= LOG_CAPACITY {
            self.lines.pop_front();
        }
        self.lines.push_back(line.clone());
        line
    }

    pub fn snapshot(&self) -> Vec<LogLine> {
        self.lines.iter().cloned().collect()
    }

    pub fn clear(&mut self) {
        self.lines.clear();
    }
}

/// sing-box writes `<timestamp> <LEVEL> <subsystem>: <message>`; pull the level
/// out so the UI can colour and filter, and keep the rest verbatim.
pub fn classify(raw: &str) -> (String, String) {
    const LEVELS: [&str; 7] = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "PANIC"];
    // Strip ANSI colour codes the core emits when it thinks it owns a terminal.
    let cleaned = strip_ansi(raw);

    // Паника Go-рантайма приходит без колонки уровня: «panic: …», за ней
    // стектрейс. Без этой пометки заголовок тонет в info, диагноз не попадает
    // ни в статус («ядро неожиданно завершилось»), ни в фильтр «Ошибки».
    if cleaned.starts_with("panic:") {
        return ("panic".to_string(), cleaned);
    }
    if cleaned.starts_with("fatal error:") {
        return ("fatal".to_string(), cleaned);
    }
    for level in LEVELS {
        if let Some(pos) = cleaned.find(level) {
            let before = &cleaned[..pos];
            // Only treat it as the level column if nothing but the timestamp precedes it.
            if before.chars().all(|c| {
                c.is_ascii_digit() || matches!(c, '-' | ':' | ' ' | '+' | '.' | '/')
            }) {
                let rest = cleaned[pos + level.len()..].trim().to_string();
                return (level.to_lowercase(), rest);
            }
        }
    }
    ("info".to_string(), cleaned)
}

/// Строки-однодневки о жизни отдельных соединений.
///
/// sing-box пишет их с уровнем ERROR, но это хроника обычного веб-серфинга:
/// вкладка закрылась, браузер оборвал начатый запрос — и копирование
/// соединения завершилось «connection upload closed: …: forcibly closed».
/// О здоровье туннеля они не говорят ничего, и в причину сбоя подключения
/// такую строку ставить нельзя — пользователь увидит страшный сетевой мусор
/// вместо настоящего объяснения.
pub fn is_connection_churn(text: &str) -> bool {
    ["connection upload closed", "connection download closed"]
        .iter()
        .any(|marker| text.contains(marker))
}

pub fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip up to and including the final byte of the CSI sequence.
            if chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_level_column() {
        let (level, text) = classify("+0300 2026-08-13 12:00:00 INFO router: started");
        assert_eq!(level, "info");
        assert_eq!(text, "router: started");
    }

    #[test]
    fn strips_terminal_colour_codes() {
        let (level, text) = classify("\u{1b}[31mFATAL\u{1b}[0m[0000] decode config");
        assert_eq!(level, "fatal");
        assert!(text.contains("decode config"), "{text}");
    }

    #[test]
    fn a_level_word_inside_the_message_is_not_mistaken_for_the_column() {
        // "ERROR" appears only after the subsystem name, so the real level wins.
        let (level, _) = classify("2026-08-13 12:00:00 INFO dns: ERROR string in payload");
        assert_eq!(level, "info");
    }

    #[test]
    fn unparsable_lines_still_reach_the_user() {
        let (level, text) = classify("bare output with no level");
        assert_eq!(level, "info");
        assert_eq!(text, "bare output with no level");
    }

    #[test]
    fn go_runtime_panics_are_promoted_from_info() {
        // Ровно так падает sing-box: типизированный nil в vmess+ws при urltest.
        let (level, text) =
            classify("panic: runtime error: invalid memory address or nil pointer dereference");
        assert_eq!(level, "panic");
        assert!(text.starts_with("panic:"));

        let (level, _) = classify("fatal error: concurrent map writes");
        assert_eq!(level, "fatal");

        // Стектрейс остаётся обычным info — важен только заголовок.
        let (level, _) = classify("goroutine 304 [running]:");
        assert_eq!(level, "info");

        // «panic:» в середине обычной строки уровнем не считается.
        let (level, _) = classify("+0300 2026-08-29 12:00:00 INFO dns: panic: in payload");
        assert_eq!(level, "info");
    }

    #[test]
    fn connection_churn_is_recognised_but_real_failures_are_not() {
        assert!(is_connection_churn(
            "[326477152 1.87s] connection: connection upload closed: raw-read tcp4 \
             172.19.0.1:59194->172.19.0.2:10262: An existing connection was forcibly \
             closed by the remote host."
        ));
        assert!(is_connection_churn(
            "[1 0ms] connection: connection download closed: read: connection reset"
        ));
        // Ошибка набора соединения — настоящий диагноз, его прятать нельзя.
        assert!(!is_connection_churn(
            "[2 3.5s] connection: open connection to example.com:443 using \
             outbound/hysteria2[0-hy]: timeout: no recent network activity"
        ));
        assert!(!is_connection_churn("start service: initialize cache-file: timeout"));
    }

    #[test]
    fn buffer_keeps_the_newest_lines_and_numbers_them() {
        let mut buf = LogBuffer::default();
        for i in 0..(LOG_CAPACITY + 10) {
            buf.push("info".into(), format!("line {i}"));
        }
        let snap = buf.snapshot();
        assert_eq!(snap.len(), LOG_CAPACITY);
        assert_eq!(snap.last().unwrap().text, format!("line {}", LOG_CAPACITY + 9));
        assert!(snap[0].seq < snap[1].seq);
    }
}
