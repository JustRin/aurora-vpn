//! Страна сервера по его адресу.
//!
//! Панели редко пишут страну в имя узла — там оказывается что-нибудь вроде
//! `vless-Me`, — а подпись «Нидерланды · VLESS · vless-Me» читается сразу.
//!
//! База — DB-IP IP-to-Country Lite: она свободна, обновляется помесячно и
//! знает не только код страны, но и её название на нужном языке, поэтому своей
//! таблицы названий держать не приходится. Скачивается один раз и лежит в
//! папке данных; наружу при этом не уходит ничего, кроме самой загрузки.
//!
//! Сперва здесь стоял `geoip.db` от SagerNet — он идёт с sing-box и умеет
//! читаться его же командой `geoip lookup`. Отказались: та база наследует
//! MaxMind GeoLite2 и для арендованных подсетей показывает страну владельца,
//! а не машины. Живой пример — сервер в Нидерландах на американской подсети:
//! SagerNet отвечал `us`, DB-IP отвечает `nl`, и прав второй.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::state::AppState;

/// Файл базы в папке данных.
const DB_FILE: &str = "dbip-country.mmdb";
/// Документ хранилища: адрес → страна.
const CACHE: &str = "countries";

/// Страна с названием на обоих языках интерфейса: перевод берётся из самой
/// базы, чтобы не заводить таблицу на две с половиной сотни стран.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Country {
    /// Двухбуквенный код в верхнем регистре: «NL».
    pub code: String,
    pub ru: String,
    pub en: String,
}

pub fn db_path(state: &AppState) -> PathBuf {
    state.paths.config_dir.join(DB_FILE)
}

/// Скачать базу, если её ещё нет.
///
/// Файл именован месяцем выпуска; в первых числах свежего может ещё не быть,
/// поэтому при неудаче берётся прошлый. Повторных загрузок нет: страна у
/// адреса меняется примерно никогда, а мегабайты на старте ни к чему.
pub async fn ensure_db(state: &AppState) -> Result<PathBuf> {
    let path = db_path(state);
    if path.is_file() {
        return Ok(path);
    }

    let now = chrono::Utc::now();
    let months = [now, now - chrono::Duration::days(28)];
    let mut last: Option<String> = None;
    for month in months {
        let url = format!(
            "https://download.db-ip.com/free/dbip-country-lite-{}.mmdb.gz",
            month.format("%Y-%m")
        );
        match fetch(&url, &path).await {
            Ok(()) => return Ok(path),
            Err(err) => last = Some(err.to_string()),
        }
    }
    Err(AppError::msg(format!(
        "не удалось скачать базу стран: {}",
        last.unwrap_or_default()
    )))
}

async fn fetch(url: &str, path: &std::path::Path) -> Result<()> {
    use std::io::Read;

    let packed = crate::net::http_client()
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    // Распаковка — работа для отдельного потока: восемь мегабайт gzip заметно
    // дольше, чем стоит держать чужую задачу рантайма.
    let target = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut plain = Vec::new();
        flate2::read::GzDecoder::new(&packed[..]).read_to_end(&mut plain)?;
        // Через временный файл: оборванная загрузка не должна оставить огрызок,
        // который в следующий раз примут за готовую базу.
        let temp = target.with_extension("part");
        std::fs::write(&temp, &plain)?;
        std::fs::rename(&temp, &target)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::msg(format!("распаковка базы стран не удалась: {e}")))?
}

/// Адрес узла в IP: литерал берётся как есть, имя резолвится системой.
async fn resolve(address: &str) -> Option<IpAddr> {
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Some(ip);
    }
    tokio::net::lookup_host((address, 0))
        .await
        .ok()?
        .next()
        .map(|addr| addr.ip())
}

/// Дополнить кэш странами адресов, которых в нём ещё нет.
///
/// Возвращает полную карту «адрес → страна», в том числе уже известное:
/// интерфейс перерисовывает список целиком, и отдавать ему половину смысла нет.
pub async fn resolve_nodes(state: &AppState) -> HashMap<String, Country> {
    let mut cache: HashMap<String, Country> = state.store.load(CACHE);

    let unknown: Vec<String> = {
        let nodes = state.nodes.read();
        let mut seen: Vec<String> = Vec::new();
        for node in nodes.iter() {
            if !node.address.is_empty()
                && !cache.contains_key(&node.address)
                && !seen.contains(&node.address)
            {
                seen.push(node.address.clone());
            }
        }
        seen
    };
    if unknown.is_empty() {
        return cache;
    }

    let Ok(db) = ensure_db(state).await else {
        return cache;
    };
    // Имена резолвятся сетью, база читается с диска — обе операции не для
    // потока интерфейса, но и не настолько долгие, чтобы городить очередь.
    let mut resolved: Vec<(String, IpAddr)> = Vec::with_capacity(unknown.len());
    for address in unknown {
        if let Some(ip) = resolve(&address).await {
            resolved.push((address, ip));
        }
    }
    if resolved.is_empty() {
        return cache;
    }

    let found = tokio::task::spawn_blocking(move || lookup_all(&db, &resolved))
        .await
        .unwrap_or_default();
    if found.is_empty() {
        return cache;
    }
    cache.extend(found);
    let _ = state.store.save(CACHE, &cache);
    cache
}

/// Разобрать базу один раз на всю пачку адресов.
fn lookup_all(db: &std::path::Path, addresses: &[(String, IpAddr)]) -> HashMap<String, Country> {
    let Ok(reader) = maxminddb::Reader::open_readfile(db) else {
        return HashMap::new();
    };
    addresses
        .iter()
        .filter_map(|(address, ip)| {
            let record: maxminddb::geoip2::Country = reader.lookup(*ip).ok()??;
            let country = record.country?;
            let name = |lang: &str| {
                country
                    .names
                    .as_ref()
                    .and_then(|names| names.get(lang))
                    .map(|value| value.to_string())
                    .unwrap_or_default()
            };
            let code = country.iso_code?.to_uppercase();
            Some((
                address.clone(),
                Country {
                    ru: name("ru"),
                    en: name("en"),
                    code,
                },
            ))
        })
        .collect()
}

/// Убрать то, что осталось от прежней базы SagerNet. Файлы наши, лежат в нашей
/// же папке данных и после смены источника не значат ничего — а четыре
/// мегабайта занимают.
pub fn drop_legacy(state: &AppState) {
    let dir = &state.paths.config_dir;
    for stale in ["geoip.db", "geoip.json"] {
        let _ = std::fs::remove_file(dir.join(stale));
    }
}
