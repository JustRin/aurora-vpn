//! FREE: один пул публичных серверов, собранный из открытых списков.
//!
//! Серверы чужие и бесплатные — их выкладывает репозиторий
//! igareck/vpn-configs-for-russia, и живут они часами: одни умирают, другие
//! появляются. Поэтому пул — это подписка особого рода: вместо одного адреса у
//! неё восемь списков, и обновляется она не по общему расписанию подписок, а
//! ровно в начале каждого часа.
//!
//! Отказаться можно в любой момент — пул удаляется как обычная подписка и
//! уносит свои серверы с собой.

use std::collections::HashSet;
use std::time::Duration;

use chrono::{DateTime, Local, TimeZone, Timelike};

use crate::error::{AppError, Result};
use crate::link::{self, ParseReport};
use crate::model::ServerNode;

/// Имя пула в списке — одинаковое на всех языках, как и у WARP.
pub const NAME: &str = "FREE";

/// Откуда берутся серверы. На эту же страницу ведёт окно согласия.
pub const SOURCE: &str = "https://github.com/igareck/vpn-configs-for-russia";

/// Все списки репозитория, в которых лежат ссылки на прокси. Мосты TOR там же
/// есть, но это не серверы.
const LISTS: [&str; 8] = [
    "BLACK_VLESS_RUS.txt",
    "BLACK_VLESS_RUS_mobile.txt",
    "BLACK_SS%2BAll_RUS.txt",
    "BLACK_SS_WEAK_DPI_RUS.txt",
    "Vless-Reality-White-Lists-Rus-Mobile.txt",
    "WHITE-CIDR-RU-all.txt",
    "WHITE-CIDR-RU-checked.txt",
    "WHITE-SNI-RU-all.txt",
];

/// Те же файлы на разных хостах. GitHub первый — обновляется раньше всех;
/// остальные — для сетей, где его притормаживают.
const MIRRORS: [&str; 3] = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main",
    "https://gitlab.com/igareck/vpn-configs-for-russia/-/raw/main",
    "https://raw.githack.com/igareck/vpn-configs-for-russia/main",
];

/// Как часто часовой круг смотрит на часы. Полминуты — и «ровно в 13:00»
/// остаётся правдой, и спящий ноутбук, проснувшись, догоняет пропущенный час.
pub const TICK: Duration = Duration::from_secs(30);

/// Пауза перед новой попыткой, если обновление в этот час не удалось: сеть
/// могла ещё не подняться, но и долбить хосты каждые полминуты незачем.
pub const RETRY: Duration = Duration::from_secs(5 * 60);

/// Что собралось со всех списков.
pub struct Pool {
    pub nodes: Vec<ServerNode>,
    /// Сколько повторов отсеяно: списки сильно пересекаются.
    pub duplicates: usize,
    /// `(список, причина)` для каждого списка, который не скачался.
    pub errors: Vec<(String, String)>,
}

/// Скачать все списки разом и свести их в один пул без повторов.
///
/// Списки независимы: недоступный пропускается, лишь бы хоть один пришёл.
/// Ошибка — только когда не пришло ничего.
pub async fn fetch() -> Result<Pool> {
    let client = crate::net::http_builder()
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(20))
        // Как и у обычных подписок: списки доступны и без туннеля, а
        // полунастроенный системный прокси подвесил бы обновление.
        .no_proxy()
        .user_agent("Aurora-VPN/0.1 (sing-box)")
        .build()?;

    // Порядок задач — порядок списков: при повторе остаётся экземпляр из того
    // списка, что стоит выше, и так от обновления к обновлению.
    let tasks: Vec<_> = LISTS
        .iter()
        .map(|&name| (name, tokio::spawn(fetch_list(client.clone(), name))))
        .collect();

    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    for (name, task) in tasks {
        let label = name.replace("%2B", "+");
        match task.await {
            Ok(Ok(report)) => nodes.extend(report.nodes),
            Ok(Err(e)) => errors.push((label, e.to_string())),
            Err(e) => errors.push((label, e.to_string())),
        }
    }

    if nodes.is_empty() {
        let why = errors
            .first()
            .map(|(_, why)| why.clone())
            .unwrap_or_else(|| "списки пусты".into());
        return Err(AppError::msg(format!(
            "не удалось скачать ни одного списка бесплатных серверов: {why}"
        )));
    }

    let fetched = nodes.len();
    let nodes = dedup(nodes);
    Ok(Pool {
        duplicates: fetched - nodes.len(),
        nodes,
        errors,
    })
}

/// Один список: зеркала по очереди, пока какое-нибудь не отдаст серверы.
///
/// Строки, которые не разобрались, не считаются ошибкой: это забота
/// публичного списка, и сделать с ними пользователь ничего не может. А вот
/// ответ без единого сервера — считается: так выглядит страница-заглушка
/// провайдера, вернувшая «200 OK».
async fn fetch_list(client: reqwest::Client, name: &'static str) -> Result<ParseReport> {
    let mut first_error = None;
    for base in MIRRORS {
        let attempt = async {
            let body = client
                .get(format!("{base}/{name}"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            let report = link::parse_subscription(&body);
            if report.nodes.is_empty() {
                return Err(AppError::msg("в ответе нет ни одного сервера"));
            }
            Ok(report)
        };
        match attempt.await {
            Ok(report) => return Ok(report),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error.expect("зеркал больше нуля"))
}

/// Оставить по одному экземпляру каждого сервера — тот, что встретился первым.
///
/// Списки пересекаются сильно: мобильный — срез полного, а один и тот же сервер
/// ходит по ним с разным отпечатком TLS, ALPN или порядком параметров. Из ~630
/// строк серверов набирается ~140. Тот же ли это сервер, решает тот же ключ,
/// которым список серверов узнаёт их при импорте и обновлении подписок, — с
/// адресом в нижнем регистре: имена хостов от регистра не зависят, а списки
/// пишут их кто как.
pub fn dedup(mut nodes: Vec<ServerNode>) -> Vec<ServerNode> {
    for node in &mut nodes {
        node.address.make_ascii_lowercase();
    }
    let mut seen = HashSet::new();
    nodes.retain(|node| seen.insert(node.fingerprint_key()));
    nodes
}

/// Пора ли освежить пул: последнее обновление было раньше, чем начался
/// текущий час по часам компьютера. Так обновление приходится ровно на 12:00,
/// 13:00 и дальше, а после выключенного компьютера или сна — сразу же.
pub fn due<Tz: TimeZone>(last_updated: &str, now: DateTime<Tz>) -> bool {
    let Ok(last) = DateTime::parse_from_rfc3339(last_updated) else {
        // Ни разу не обновлялся или время не читается — обновить.
        return true;
    };
    let hour_start = now
        .with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0));
    match hour_start {
        Some(start) => last < start,
        // Начала часа нет на часах (перевод времени) — дождаться следующего.
        None => false,
    }
}

/// [`due`] по местным часам.
pub fn due_now(last_updated: &str) -> bool {
    due(last_updated, Local::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;
    use chrono::{FixedOffset, Utc};

    fn node(name: &str, address: &str, uuid: &str, fingerprint: &str) -> ServerNode {
        ServerNode {
            name: name.into(),
            protocol: Protocol::Vless,
            address: address.into(),
            port: 443,
            uuid: uuid.into(),
            fingerprint: fingerprint.into(),
            ..Default::default()
        }
    }

    #[test]
    fn the_same_server_from_two_lists_is_kept_once() {
        let pooled = dedup(vec![
            node("из полного", "1.2.3.4", "u1", "chrome"),
            node("другой", "5.6.7.8", "u1", "chrome"),
            // Тот же сервер с другим отпечатком и в другом регистре.
            node("из мобильного", "1.2.3.4", "u1", "ios"),
            node("хост", "Edge.Example.com", "u2", ""),
            node("хост ещё раз", "edge.example.com", "u2", ""),
        ]);
        let names: Vec<_> = pooled.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["из полного", "другой", "хост"]);
    }

    #[test]
    fn a_different_credential_is_a_different_server() {
        let pooled = dedup(vec![
            node("a", "1.2.3.4", "u1", ""),
            node("b", "1.2.3.4", "u2", ""),
        ]);
        assert_eq!(pooled.len(), 2);
    }

    #[test]
    fn the_pool_is_due_once_the_hour_turns() {
        let msk = FixedOffset::east_opt(3 * 3600).unwrap();
        let at = |h, m| msk.with_ymd_and_hms(2026, 10, 29, h, m, 0).unwrap();
        // Обновлён в 12:00:05 по Москве — то есть в 09:00:05 UTC.
        let updated = "2026-10-29T09:00:05+00:00";
        assert!(!due(updated, at(12, 0)));
        assert!(!due(updated, at(12, 59)));
        assert!(due(updated, at(13, 0)));
        assert!(due(updated, at(15, 30)));
    }

    #[test]
    fn a_pool_never_fetched_is_due() {
        assert!(due("", Utc::now()));
        assert!(due("вчера", Utc::now()));
    }
}
