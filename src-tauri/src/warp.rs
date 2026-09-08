//! Cloudflare WARP: registering a free account and turning it into a node.
//!
//! WARP is a WireGuard tunnel Cloudflare hands out to anyone who asks — no
//! sign-up, no credentials, just a device registration bound to a public key we
//! generate here. The app uses it two ways: as a server of its own, and as the
//! extra layer wrapped around whatever server the user picked.
//!
//! The registration is a two-step affair, and the second step is easy to miss:
//! a fresh device comes back with `warp_enabled: false`, and until it is
//! flipped the tunnel handshakes, reports itself healthy and carries nothing.

use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{AppError, Result};
use crate::model::{Protocol, ServerNode};

/// The client API, at the version wgcf pins. Newer ones exist; this one is
/// stable and still answers.
const API: &str = "https://api.cloudflareclient.com/v0a1922";
const CLIENT_VERSION: &str = "a-6.3-1922";
const AGENT: &str = "okhttp/3.12.1";

/// Where to dial when the registration comes back without a usable address.
const FALLBACK_ENDPOINT: (&str, u16) = ("162.159.192.1", 2408);

/// A registered device, kept on disk as `warp.json`.
///
/// Cloudflare only keeps one live session per key, so a single account backs
/// both the standalone node and the layer — never two tunnels at once.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WarpAccount {
    pub device_id: String,
    /// Bearer token for later calls against this device.
    pub token: String,
    pub license: String,
    /// `free`, or `limited`/`unlimited` once a WARP+ licence is applied.
    pub account_type: String,

    pub private_key: String,
    pub public_key: String,
    pub peer_public_key: String,
    /// Addresses of our end of the tunnel, bare.
    pub v4: String,
    pub v6: String,
    /// Three bytes derived from the account's `client_id`; WARP tags every
    /// packet with them and drops the ones that arrive without.
    pub reserved: Vec<u8>,

    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub created: String,
}

// ------------------------------------------------------------------ responses

#[derive(Deserialize)]
struct RegisterResponse {
    #[serde(default)]
    id: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    account: Account,
    #[serde(default)]
    config: Config,
}

#[derive(Deserialize, Default)]
struct Account {
    #[serde(default)]
    license: String,
    #[serde(default)]
    account_type: String,
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    interface: Interface,
    #[serde(default)]
    peers: Vec<Peer>,
}

#[derive(Deserialize, Default)]
struct Interface {
    #[serde(default)]
    addresses: Addresses,
}

#[derive(Deserialize, Default)]
struct Addresses {
    #[serde(default)]
    v4: String,
    #[serde(default)]
    v6: String,
}

#[derive(Deserialize, Default)]
struct Peer {
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    endpoint: Endpoint,
}

#[derive(Deserialize, Default)]
struct Endpoint {
    #[serde(default)]
    v4: String,
    #[serde(default)]
    host: String,
}

// ------------------------------------------------------------------ requests

fn client() -> Result<reqwest::Client> {
    Ok(crate::net::http_builder()
        .timeout(Duration::from_secs(30))
        // Registration happens while the tunnel is being set up, and a
        // half-configured system proxy would deadlock it — same reasoning as
        // the subscription refresh.
        .no_proxy()
        .user_agent(AGENT)
        .build()?)
}

/// Register a fresh device and return an account ready to be dialled.
pub async fn register() -> Result<WarpAccount> {
    let secret = StaticSecret::random();
    let private_key = STANDARD.encode(secret.to_bytes());
    let public_key = STANDARD.encode(PublicKey::from(&secret).to_bytes());

    let http = client()?;
    let body = serde_json::json!({
        "key": public_key,
        "install_id": "",
        "fcm_token": "",
        "tos": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "model": "PC",
        "serial_number": "",
        "locale": "en_US",
        "type": "Android",
    });

    let response = http
        .post(format!("{API}/reg"))
        .header("CF-Client-Version", CLIENT_VERSION)
        .json(&body)
        .send()
        .await?
        .error_for_status()
        .map_err(|e| AppError::msg(format!("Cloudflare отказал в регистрации: {e}")))?;
    let registration: RegisterResponse = response.json().await?;

    if registration.id.is_empty() || registration.token.is_empty() {
        return Err(AppError::msg(
            "Cloudflare вернул регистрацию без идентификатора устройства",
        ));
    }

    let peer = registration.config.peers.first();
    let peer_public_key = peer.map(|p| p.public_key.clone()).unwrap_or_default();
    if peer_public_key.is_empty() {
        return Err(AppError::msg("Cloudflare вернул регистрацию без ключа пира"));
    }

    let (endpoint_host, endpoint_port) = peer
        .map(|p| endpoint_of(&p.endpoint))
        .unwrap_or((FALLBACK_ENDPOINT.0.to_string(), FALLBACK_ENDPOINT.1));

    let account = WarpAccount {
        device_id: registration.id,
        token: registration.token,
        license: registration.account.license,
        account_type: registration.account.account_type,
        private_key,
        public_key,
        peer_public_key,
        v4: registration.config.interface.addresses.v4,
        v6: registration.config.interface.addresses.v6,
        reserved: reserved_from(&registration.config.client_id),
        endpoint_host,
        endpoint_port,
        created: chrono::Utc::now().to_rfc3339(),
    };

    // Without this the device stays registered but unrouted: the handshake
    // succeeds, the endpoint looks alive, and not a byte comes back.
    enable(&http, &account).await?;
    Ok(account)
}

async fn enable(http: &reqwest::Client, account: &WarpAccount) -> Result<()> {
    http.patch(format!("{API}/reg/{}", account.device_id))
        .header("CF-Client-Version", CLIENT_VERSION)
        .bearer_auth(&account.token)
        .json(&serde_json::json!({ "warp_enabled": true }))
        .send()
        .await?
        .error_for_status()
        .map_err(|e| AppError::msg(format!("Cloudflare не включил WARP на устройстве: {e}")))?;
    Ok(())
}

/// Prefer the literal address Cloudflare handed back over the hostname it also
/// offers: one fewer name to resolve is one fewer thing a censor can block.
/// Its port arrives as `0`, so the well-known one is filled in.
fn endpoint_of(endpoint: &Endpoint) -> (String, u16) {
    for candidate in [&endpoint.v4, &endpoint.host] {
        let Some((host, port)) = candidate.rsplit_once(':') else {
            continue;
        };
        if host.is_empty() {
            continue;
        }
        let port = port.parse::<u16>().unwrap_or(0);
        return (
            host.to_string(),
            if port == 0 { FALLBACK_ENDPOINT.1 } else { port },
        );
    }
    (FALLBACK_ENDPOINT.0.to_string(), FALLBACK_ENDPOINT.1)
}

/// `"ve/E"` → `[189, 239, 196]`. Standard base64, four characters, no padding.
fn reserved_from(client_id: &str) -> Vec<u8> {
    STANDARD_NO_PAD
        .decode(client_id.trim_end_matches('='))
        .ok()
        .filter(|bytes| bytes.len() == 3)
        .unwrap_or_default()
}

impl WarpAccount {
    /// Whether this account can actually be dialled.
    pub fn is_usable(&self) -> bool {
        !self.private_key.is_empty() && !self.peer_public_key.is_empty() && !self.v4.is_empty()
    }

    /// A node carrying this account, for the server list.
    pub fn to_node(&self, id: String, name: String) -> ServerNode {
        ServerNode {
            id,
            name,
            protocol: Protocol::Wireguard,
            address: self.endpoint_host.clone(),
            port: self.endpoint_port,
            private_key: self.private_key.clone(),
            peer_public_key: self.peer_public_key.clone(),
            local_v4: self.v4.clone(),
            local_v6: self.v6.clone(),
            reserved: self.reserved.clone(),
            raw_link: format!("warp://{}:{}", self.endpoint_host, self.endpoint_port),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_becomes_three_reserved_bytes() {
        assert_eq!(reserved_from("ve/E"), vec![189, 239, 196]);
        // A padded form is what some responses carry; both must land the same.
        assert_eq!(reserved_from("ve/E="), vec![189, 239, 196]);
    }

    #[test]
    fn a_client_id_that_is_not_three_bytes_is_dropped() {
        // Sending a wrong-length `reserved` would have sing-box refuse the whole
        // document; an absent one merely means "no tag", which plain WireGuard
        // is fine with.
        assert!(reserved_from("").is_empty());
        assert!(reserved_from("bogus!!").is_empty());
    }

    #[test]
    fn the_zero_port_of_the_v4_endpoint_is_replaced() {
        // Cloudflare answers `162.159.192.10:0` — the address is real, the port
        // is not, and dialling port 0 goes nowhere.
        let endpoint = Endpoint {
            v4: "162.159.192.10:0".into(),
            host: "engage.cloudflareclient.com:2408".into(),
        };
        assert_eq!(endpoint_of(&endpoint), ("162.159.192.10".into(), 2408));
    }

    #[test]
    fn the_hostname_carries_the_registration_when_no_address_came_back() {
        let endpoint = Endpoint {
            v4: String::new(),
            host: "engage.cloudflareclient.com:2408".into(),
        };
        assert_eq!(
            endpoint_of(&endpoint),
            ("engage.cloudflareclient.com".into(), 2408)
        );
    }

    #[test]
    fn an_empty_endpoint_falls_back_to_the_well_known_one() {
        assert_eq!(
            endpoint_of(&Endpoint::default()),
            (FALLBACK_ENDPOINT.0.to_string(), FALLBACK_ENDPOINT.1)
        );
    }

    /// Registers a real device with Cloudflare, so it is opt-in:
    /// `cargo test --manifest-path src-tauri/Cargo.toml -- --ignored registers`.
    ///
    /// Everything else here checks our own arithmetic; this is the only thing
    /// that catches Cloudflare changing the shape of an answer under us.
    #[tokio::test]
    #[ignore = "ходит в сеть и заводит устройство в Cloudflare"]
    async fn registers_a_usable_account_against_the_live_api() {
        let account = register().await.expect("регистрация должна пройти");
        assert!(account.is_usable(), "{account:?}");
        assert_eq!(account.reserved.len(), 3);
        assert!(!account.device_id.is_empty());
        assert!(!account.token.is_empty());
        // Известный публичный ключ WARP: если он изменится, туннель не встанет,
        // и узнать об этом лучше здесь.
        assert_eq!(
            account.peer_public_key,
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
        );
    }

    #[test]
    fn an_account_without_keys_is_not_usable() {
        assert!(!WarpAccount::default().is_usable());
        let account = WarpAccount {
            private_key: "k".into(),
            peer_public_key: "p".into(),
            v4: "172.16.0.2".into(),
            ..Default::default()
        };
        assert!(account.is_usable());
    }
}
