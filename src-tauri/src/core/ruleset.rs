//! Geo rule-set files, fetched and cached by us rather than by the core.
//!
//! sing-box treats a `type: remote` rule-set as a hard start-up dependency: if
//! the download fails, the whole service refuses to start. On a network where
//! GitHub is unreachable — precisely the network this app exists to escape —
//! enabling "block ads" or "bypass RU" would therefore make the tunnel
//! unstartable. So the files are downloaded here, cached on disk, and handed to
//! the core as local paths; a set we cannot obtain is dropped from the config
//! with a warning instead of taking the tunnel down with it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const GEOSITE: &str = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set";
const GEOIP: &str = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set";

/// Refresh cadence. Geo data moves slowly; a week-old copy is fine and beats
/// blocking every connect on a network round-trip.
const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub tag: String,
    pub url: String,
}

pub fn spec(tag: &str) -> Option<Spec> {
    let url = match tag {
        "geosite-ads" => format!("{GEOSITE}/geosite-category-ads-all.srs"),
        "geosite-ru" => format!("{GEOSITE}/geosite-category-ru.srs"),
        "geosite-cn" => format!("{GEOSITE}/geosite-cn.srs"),
        "geoip-ru" => format!("{GEOIP}/geoip-ru.srs"),
        "geoip-cn" => format!("{GEOIP}/geoip-cn.srs"),
        _ => return None,
    };
    Some(Spec {
        tag: tag.to_string(),
        url,
    })
}

pub fn path_for(dir: &Path, tag: &str) -> PathBuf {
    dir.join(format!("{tag}.srs"))
}

fn is_fresh(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.len() == 0 {
        return false;
    }
    meta.modified()
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|age| age < MAX_AGE)
        .unwrap_or(false)
}

pub struct Outcome {
    /// Tags the core may reference; everything else must be omitted.
    pub available: HashSet<String>,
    /// Human-readable reasons for the sets that could not be obtained.
    pub failures: Vec<String>,
}

/// Make sure every requested set exists on disk, downloading what is missing.
///
/// A stale copy is preferred over no copy: out-of-date geo data still routes
/// correctly for the overwhelming majority of addresses, whereas a missing set
/// silently disables the user's rule.
pub async fn ensure(specs: &[Spec], dir: &Path) -> Outcome {
    let mut available = HashSet::new();
    let mut failures = Vec::new();

    if specs.is_empty() {
        return Outcome { available, failures };
    }
    if let Err(e) = std::fs::create_dir_all(dir) {
        failures.push(format!("не удалось создать папку для гео-наборов: {e}"));
        return Outcome { available, failures };
    }

    let client = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        // The tunnel is not up yet, and a half-configured system proxy would
        // deadlock this fetch.
        .no_proxy()
        .user_agent("Aurora-VPN/0.1")
        .build()
        .ok();

    for spec in specs {
        let path = path_for(dir, &spec.tag);
        if is_fresh(&path) {
            available.insert(spec.tag.clone());
            continue;
        }

        let downloaded = match &client {
            Some(client) => download(client, &spec.url, &path).await,
            None => Err("HTTP-клиент недоступен".to_string()),
        };

        match downloaded {
            Ok(()) => {
                available.insert(spec.tag.clone());
            }
            Err(reason) if path.is_file() => {
                // Stale but usable.
                available.insert(spec.tag.clone());
                failures.push(format!(
                    "{}: обновить не удалось ({reason}), используется сохранённая копия",
                    spec.tag
                ));
            }
            Err(reason) => failures.push(format!("{}: {reason}", spec.tag)),
        }
    }

    Outcome { available, failures }
}

async fn download(client: &reqwest::Client, url: &str, path: &Path) -> Result<(), String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    if bytes.is_empty() {
        return Err("сервер вернул пустой файл".into());
    }

    // Write via a temporary file: a partially written .srs would be accepted as
    // "present" on the next run and then rejected by the core.
    let tmp = path.with_extension("srs.part");
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tags_resolve_to_upstream_urls() {
        assert!(spec("geosite-ru").unwrap().url.ends_with("geosite-category-ru.srs"));
        assert!(spec("geoip-cn").unwrap().url.ends_with("geoip-cn.srs"));
        assert!(spec("nonsense").is_none());
    }

    #[tokio::test]
    async fn an_unreachable_source_degrades_instead_of_failing_hard() {
        let dir = std::env::temp_dir().join("aurora-ruleset-offline");
        let _ = std::fs::remove_dir_all(&dir);

        let specs = vec![Spec {
            tag: "geosite-ads".into(),
            // Reserved TEST-NET address: guaranteed not to answer.
            url: "http://192.0.2.1/never.srs".into(),
        }];
        let outcome = ensure(&specs, &dir).await;

        assert!(outcome.available.is_empty(), "nothing should be usable");
        assert_eq!(outcome.failures.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_cached_copy_is_reused_without_touching_the_network() {
        let dir = std::env::temp_dir().join("aurora-ruleset-cached");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(path_for(&dir, "geosite-ru"), b"cached").unwrap();

        let specs = vec![Spec {
            tag: "geosite-ru".into(),
            url: "http://192.0.2.1/never.srs".into(),
        }];
        let outcome = ensure(&specs, &dir).await;

        // Fresh on disk, so the dead URL is never contacted.
        assert!(outcome.available.contains("geosite-ru"));
        assert!(outcome.failures.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
