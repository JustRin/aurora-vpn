//! Исходящие: протоколы и группы.

pub mod direct;
pub mod group;
pub mod hysteria2;
pub mod shadowsocks;
pub mod socks;
pub mod trojan;
pub mod vless;
pub mod vmess;
pub mod xudp;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use crate::common::{other, BoxStream, PacketConn, Target};
use crate::config::OutboundOpts;

#[async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    fn kind(&self) -> &'static str;
    async fn dial(&self, target: &Target) -> io::Result<BoxStream>;
    async fn dial_udp(&self, _target: &Target) -> io::Result<Box<dyn PacketConn>> {
        Err(other(format!("{}: UDP не поддержан", self.kind())))
    }
    /// У группы — текущий участник. У всех остальных `None`.
    fn member(&self) -> Option<String> {
        None
    }
    fn select(&self, _member: &str) -> Result<(), String> {
        Err("не группа-селектор".to_string())
    }
    fn members(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Узел, который движок пока не умеет. Документ из-за него не падает: замер честно
/// скажет «недоступен», и балансировщик обойдёт такой узел сам.
struct Unsupported {
    tag: String,
    reason: String,
}

#[async_trait]
impl Outbound for Unsupported {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "unsupported"
    }
    async fn dial(&self, _: &Target) -> io::Result<BoxStream> {
        Err(other(self.reason.clone()))
    }
}

pub struct Outbounds {
    map: HashMap<String, Arc<dyn Outbound>>,
    pub order: Vec<String>,
}

fn build_one(o: &OutboundOpts) -> Result<Arc<dyn Outbound>, String> {
    Ok(match o.kind.as_str() {
        "direct" => Arc::new(direct::Direct::new(&o.tag)),
        "block" => Arc::new(direct::Block::new(&o.tag)),
        "socks" => Arc::new(socks::Socks::new(o)),
        "selector" => Arc::new(group::Selector::new(o)),
        "urltest" => Arc::new(group::UrlTest::new(o)),
        "vless" => Arc::new(vless::Vless::new(o)?),
        "trojan" => Arc::new(trojan::Trojan::new(o)?),
        "shadowsocks" => Arc::new(shadowsocks::Shadowsocks::new(o)?),
        "vmess" => Arc::new(vmess::Vmess::new(o)?),
        "hysteria2" => Arc::new(hysteria2::Hysteria2::new(o)?),
        other => return Err(format!("протокол {other} пока не поддержан")),
    })
}

impl Outbounds {
    /// `(тег, причина)` для узлов, ставших заглушками — их покажет `check`.
    pub fn build(list: &[OutboundOpts], endpoints: &[serde_json::Value]) -> (Self, Vec<(String, String)>) {
        let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::with_capacity(list.len());
        let mut order = Vec::with_capacity(list.len());
        let mut skipped = Vec::new();
        for o in list {
            let outbound = build_one(o).unwrap_or_else(|reason| {
                skipped.push((o.tag.clone(), reason.clone()));
                Arc::new(Unsupported { tag: o.tag.clone(), reason })
            });
            order.push(o.tag.clone());
            map.insert(o.tag.clone(), outbound);
        }
        for e in endpoints {
            let tag = e["tag"].as_str().unwrap_or_default().to_string();
            let reason = format!("endpoint {} пока не поддержан", e["type"].as_str().unwrap_or("?"));
            skipped.push((tag.clone(), reason.clone()));
            order.push(tag.clone());
            map.insert(tag.clone(), Arc::new(Unsupported { tag, reason }));
        }
        if !map.contains_key("direct") {
            map.insert("direct".to_string(), Arc::new(direct::Direct::new("direct")));
        }
        (Self { map, order }, skipped)
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.map.get(tag).cloned()
    }

    /// Пройти группы до настоящего узла. `chains` в формате Clash: от узла к группе.
    pub fn leaf(&self, tag: &str) -> Option<(Arc<dyn Outbound>, Vec<String>)> {
        let mut chain = vec![tag.to_string()];
        let mut current = self.map.get(tag)?.clone();
        // Защита от кольца групп в испорченном конфиге.
        for _ in 0..8 {
            let Some(next) = current.member() else {
                chain.reverse();
                return Some((current, chain));
            };
            chain.push(next.clone());
            current = self.map.get(&next)?.clone();
        }
        None
    }
}
