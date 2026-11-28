//! Thin client over the Clash-compatible control API that sing-box exposes.
//!
//! Everything the UI does while connected — switching node, measuring latency,
//! reading counters, flipping Rule/Global/Direct — goes through here instead of
//! restarting the core.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::error::{AppError, Result};

#[derive(Clone)]
pub struct ClashApi {
    base: String,
    secret: String,
    http: reqwest::Client,
    fast_telemetry: Arc<AtomicBool>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Totals {
    pub download: u64,
    pub upload: u64,
    pub connections: usize,
}

#[derive(Deserialize)]
struct FastTelemetryNet {
    #[serde(default, rename = "tunRxPackets")]
    tun_rx_packets: u64,
    #[serde(default, rename = "tunTxPackets")]
    tun_tx_packets: u64,
    #[serde(default, rename = "tunDropped")]
    tun_dropped: u64,
    #[serde(default, rename = "udpDropped")]
    udp_dropped: u64,
    #[serde(default, rename = "tcpBytesOut")]
    tcp_bytes_out: u64,
    #[serde(default, rename = "tcpBytesIn")]
    tcp_bytes_in: u64,
    #[serde(default, rename = "tcpBytesRetrans")]
    tcp_bytes_retrans: u64,
    #[serde(default, rename = "tcpRetransEvents")]
    tcp_retrans_events: u64,
    #[serde(default, rename = "tcpRttUsSum")]
    tcp_rtt_us_sum: u64,
    #[serde(default, rename = "tcpRttSamples")]
    tcp_rtt_samples: u64,
    #[serde(default, rename = "quicPacketsSent")]
    quic_packets_sent: u64,
    #[serde(default, rename = "quicPacketsLost")]
    quic_packets_lost: u64,
    #[serde(default, rename = "dialOk")]
    dial_ok: u64,
    #[serde(default, rename = "dialFail")]
    dial_fail: u64,
    #[serde(default, rename = "relayErrors")]
    relay_errors: u64,
}

#[derive(Deserialize)]
struct FastTelemetryApp {
    #[serde(default)]
    path: String,
    #[serde(default)]
    down: u64,
    #[serde(default)]
    up: u64,
    #[serde(default, rename = "proxyDown")]
    proxy_down: u64,
    #[serde(default, rename = "proxyUp")]
    proxy_up: u64,
    #[serde(default, rename = "activeConns")]
    active_conns: u32,
    #[serde(default, rename = "totalConns")]
    total_conns: u64,
    #[serde(default)]
    errors: u64,
}

#[derive(Deserialize)]
struct FastTelemetryResponse {
    #[serde(default, rename = "downloadTotal")]
    download_total: u64,
    #[serde(default, rename = "uploadTotal")]
    upload_total: u64,
    #[serde(default, rename = "proxyDownloadTotal")]
    proxy_download_total: u64,
    #[serde(default, rename = "proxyUploadTotal")]
    proxy_upload_total: u64,
    #[serde(default, rename = "directDownloadTotal")]
    direct_download_total: u64,
    #[serde(default, rename = "directUploadTotal")]
    direct_upload_total: u64,
    #[serde(default, rename = "connectionsCount")]
    connections_count: usize,
    #[serde(default)]
    network: Option<FastTelemetryNet>,
    #[serde(default)]
    apps: Vec<FastTelemetryApp>,
}

#[derive(Deserialize)]
struct ConnectionsResponse {
    #[serde(default, rename = "downloadTotal")]
    download_total: u64,
    #[serde(default, rename = "uploadTotal")]
    upload_total: u64,
    #[serde(default)]
    connections: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
struct DelayResponse {
    #[serde(default)]
    delay: u32,
    #[serde(default)]
    message: String,
}

impl ClashApi {
    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn new(port: u16, secret: &str) -> Self {
        Self {
            base: format!("http://127.0.0.1:{port}"),
            secret: secret.to_string(),
            fast_telemetry: Arc::new(AtomicBool::new(true)),
            http: crate::net::http_builder()
                .timeout(Duration::from_secs(15))
                // The controller is on loopback; a system proxy must not intercept it.
                .no_proxy()
                .build()
                .unwrap_or_default(),
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.secret)
    }

    pub async fn version(&self) -> Result<String> {
        let value: serde_json::Value = self
            .request(reqwest::Method::GET, "/version")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(value["version"].as_str().unwrap_or_default().to_string())
    }

    /// Poll until the control plane answers, i.e. the core finished booting.
    ///
    /// Подключение ждёт панель иначе — `await_control_plane` смотрит ещё и на
    /// живость самого ядра; этот простой вариант остался интеграционным тестам.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        let mut last: Option<String> = None;
        while std::time::Instant::now() < deadline {
            match self.version().await {
                Ok(_) => return Ok(()),
                Err(e) => last = Some(e.to_string()),
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        Err(AppError::msg(format!(
            "ядро не ответило за {} с{}",
            timeout.as_secs(),
            last.map(|e| format!(": {e}")).unwrap_or_default()
        )))
    }

    /// Cumulative byte counters since the core started. The caller turns these
    /// into a rate by differencing consecutive samples.
    pub async fn totals(&self) -> Result<Totals> {
        let body: ConnectionsResponse = self
            .request(reqwest::Method::GET, "/connections")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(Totals {
            download: body.download_total,
            upload: body.upload_total,
            connections: body.connections.map(|c| c.len()).unwrap_or(0),
        })
    }

    pub async fn telemetry(&self) -> Result<crate::stats::TelemetrySnapshot> {
        use crate::stats::{OpenConnSample, TelemetryApp, TelemetryNet, TelemetrySnapshot};

        if self.fast_telemetry.load(Ordering::Relaxed) {
            match self.request(reqwest::Method::GET, "/traffic/telemetry").send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(body) = resp.json::<FastTelemetryResponse>().await {
                        let has_net = body.network.is_some();
                        let net = body
                            .network
                            .map(|n| TelemetryNet {
                                tun_rx_packets: n.tun_rx_packets,
                                tun_tx_packets: n.tun_tx_packets,
                                tun_dropped: n.tun_dropped,
                                udp_dropped: n.udp_dropped,
                                tcp_bytes_out: n.tcp_bytes_out,
                                tcp_bytes_in: n.tcp_bytes_in,
                                tcp_bytes_retrans: n.tcp_bytes_retrans,
                                tcp_retrans_events: n.tcp_retrans_events,
                                tcp_rtt_us_sum: n.tcp_rtt_us_sum,
                                tcp_rtt_samples: n.tcp_rtt_samples,
                                quic_packets_sent: n.quic_packets_sent,
                                quic_packets_lost: n.quic_packets_lost,
                                dial_ok: n.dial_ok,
                                dial_fail: n.dial_fail,
                                relay_errors: n.relay_errors,
                            })
                            .unwrap_or_default();
                        let apps = body
                            .apps
                            .into_iter()
                            .map(|a| TelemetryApp {
                                path: a.path,
                                down: a.down,
                                up: a.up,
                                proxy_down: a.proxy_down,
                                proxy_up: a.proxy_up,
                                active_conns: a.active_conns,
                                total_conns: a.total_conns,
                                errors: a.errors,
                            })
                            .collect();
                        return Ok(TelemetrySnapshot {
                            download: body.download_total,
                            upload: body.upload_total,
                            proxy_download: body.proxy_download_total,
                            proxy_upload: body.proxy_upload_total,
                            direct_download: body.direct_download_total,
                            direct_upload: body.direct_upload_total,
                            connections: body.connections_count,
                            has_net_metrics: has_net,
                            net,
                            apps_cumulative: true,
                            apps,
                            open_conns: Vec::new(),
                        });
                    }
                }
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::NOT_FOUND
                        || resp.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED =>
                {
                    self.fast_telemetry.store(false, Ordering::Relaxed);
                }
                Ok(_) | Err(_) => {}
            }
        }

        let body: ConnectionsResponse = self
            .request(reqwest::Method::GET, "/connections")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let raw_conns = body.connections.unwrap_or_default();
        let count = raw_conns.len();
        let open_conns = raw_conns
            .into_iter()
            .map(|c| {
                let id = c["id"].as_str().unwrap_or_default().to_string();
                let path = c["metadata"]["processPath"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let first_chain = c["chains"]
                    .as_array()
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str());
                let is_proxy = !matches!(first_chain, None | Some("direct") | Some("block"));
                let down = c["download"].as_u64().unwrap_or(0);
                let up = c["upload"].as_u64().unwrap_or(0);
                OpenConnSample {
                    id,
                    path,
                    is_proxy,
                    down,
                    up,
                }
            })
            .collect();
        Ok(TelemetrySnapshot {
            download: body.download_total,
            upload: body.upload_total,
            connections: count,
            apps_cumulative: false,
            open_conns,
            ..Default::default()
        })
    }

    /// Measure a single outbound. `Ok(None)` means the node answered but failed
    /// the probe, which the UI shows as "недоступен" rather than an error toast.
    pub async fn delay(&self, tag: &str, url: &str, timeout_ms: u32) -> Result<Option<u32>> {
        let encoded = urlencode(tag);
        let response = self
            .request(
                reqwest::Method::GET,
                &format!("/proxies/{encoded}/delay?timeout={timeout_ms}&url={}", urlencode(url)),
            )
            // Give the HTTP call more room than the probe itself, so a slow node
            // reports as slow instead of as a transport error.
            .timeout(Duration::from_millis(u64::from(timeout_ms) + 5_000))
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(None);
        }
        let body: DelayResponse = response.json().await?;
        if !body.message.is_empty() || body.delay == 0 {
            return Ok(None);
        }
        Ok(Some(body.delay))
    }

    /// Point a selector group at one of its members.
    pub async fn select(&self, group: &str, member: &str) -> Result<()> {
        let response = self
            .request(reqwest::Method::PUT, &format!("/proxies/{}", urlencode(group)))
            .json(&json!({ "name": member }))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(AppError::msg(format!(
                "ядро отклонило смену сервера ({})",
                response.status()
            )));
        }
        Ok(())
    }

    /// `Rule` | `Global` | `Direct` — matched by the `clash_mode` route rules.
    pub async fn set_mode(&self, mode: &str) -> Result<()> {
        let response = self
            .request(reqwest::Method::PATCH, "/configs")
            .json(&json!({ "mode": mode }))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(AppError::msg(format!(
                "не удалось переключить режим ({})",
                response.status()
            )));
        }
        Ok(())
    }

    pub async fn close_connections(&self) -> Result<()> {
        self.request(reqwest::Method::DELETE, "/connections")
            .send()
            .await?;
        Ok(())
    }

    /// Закрыть соединения, идущие через `tag` — любое звено цепочки (`chains`
    /// в ответе панели: от исходящего до узла). Точечнее, чем `DELETE
    /// /connections`: прямые соединения — локальная сеть, обход — остаются, и
    /// сеть ядро не сбрасывает.
    pub async fn close_via(&self, tag: &str) -> Result<usize> {
        let body: ConnectionsResponse = self
            .request(reqwest::Method::GET, "/connections")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let ids = ids_via(&body.connections.unwrap_or_default(), tag);
        for id in &ids {
            let _ = self
                .request(reqwest::Method::DELETE, &format!("/connections/{}", urlencode(id)))
                .send()
                .await;
        }
        Ok(ids.len())
    }
}

/// Идентификаторы соединений, в чьей цепочке исходящих есть `tag`.
fn ids_via(connections: &[serde_json::Value], tag: &str) -> Vec<String> {
    connections
        .iter()
        .filter(|conn| {
            conn["chains"]
                .as_array()
                .is_some_and(|chain| chain.iter().any(|hop| hop == tag))
        })
        .filter_map(|conn| conn["id"].as_str().map(str::to_string))
        .collect()
}

/// Percent-encode a path/query segment. Proxy tags carry spaces and non-ASCII
/// names, both of which would otherwise corrupt the request line.
fn urlencode(value: &str) -> String {
    const UNRESERVED: &[u8] = b"-_.~";
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || UNRESERVED.contains(byte) {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_tags_that_would_break_the_request_line() {
        assert_eq!(urlencode("0-Tokyo JP"), "0-Tokyo%20JP");
        assert_eq!(urlencode("Москва"), "%D0%9C%D0%BE%D1%81%D0%BA%D0%B2%D0%B0");
        assert_eq!(urlencode("a/b?c=d"), "a%2Fb%3Fc%3Dd");
        assert_eq!(urlencode("plain-tag_1.0~x"), "plain-tag_1.0~x");
    }

    #[test]
    fn only_connections_routed_through_the_tag_are_picked() {
        // Цепочка — от узла к группе: у прокси-соединения это [узел, proxy],
        // у прямого — [direct]. Закрывать надо первые и не трогать вторые.
        let connections = vec![
            json!({ "id": "one", "chains": ["0-Tokyo", "proxy"] }),
            json!({ "id": "two", "chains": ["direct"] }),
            json!({ "id": "three", "chains": ["1-Berlin", "proxy"] }),
            json!({ "id": "four" }),
        ];
        assert_eq!(ids_via(&connections, "proxy"), vec!["one", "three"]);
        assert_eq!(ids_via(&connections, "0-Tokyo"), vec!["one"]);
        assert!(ids_via(&connections, "auto").is_empty());
    }
}
