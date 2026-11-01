//! NAT для TCP: пакет приложения разворачивается обратно в TUN, но уже как входящий
//! к нашему слушателю. Весь TCP — окна, ретрансляции, SACK — делает ядро Windows.
//!
//! ```text
//! приложение 172.19.0.1:50000 → сайт 1.2.3.4:443
//!      ↓ (в TUN, переписали)
//! 172.19.0.2:10001 → 172.19.0.1:LISTEN  — ядро принимает соединение на слушателе
//!      ↑ (ответ ядра, переписали обратно)
//! 1.2.3.4:443 → 172.19.0.1:50000
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

const PORT_FIRST: u16 = 10_000;
/// Простаивающее соединение без FIN держим долго: ssh без keep-alive живёт часами.
const IDLE_OPEN_SECS: u64 = 2 * 3600;
const IDLE_CLOSED_SECS: u64 = 60;

pub type FlowKey = (IpAddr, u16, IpAddr, u16);

#[derive(Debug)]
pub struct Flow {
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    pub nat_port: u16,
    last_seen: AtomicU64,
    closing: AtomicBool,
}

impl Flow {
    pub fn touch(&self, now: u64) {
        // Сравнение перед записью: не пачкать строку кэша на каждом пакете.
        if self.last_seen.load(Ordering::Relaxed) != now {
            self.last_seen.store(now, Ordering::Relaxed);
        }
    }

    pub fn mark_closing(&self) {
        self.closing.store(true, Ordering::Relaxed);
    }

    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
struct Tables {
    forward: HashMap<FlowKey, Arc<Flow>>,
    reverse: HashMap<u16, Arc<Flow>>,
    cursor: u16,
}

#[derive(Default)]
pub struct Nat {
    tables: RwLock<Tables>,
}

impl Nat {
    pub fn lookup(&self, key: &FlowKey) -> Option<Arc<Flow>> {
        self.tables.read().forward.get(key).cloned()
    }

    pub fn by_port(&self, port: u16) -> Option<Arc<Flow>> {
        self.tables.read().reverse.get(&port).cloned()
    }

    /// Новый поток. `None` — порты кончились: SYN просто теряется, клиент повторит.
    pub fn create(&self, key: FlowKey, now: u64) -> Option<Arc<Flow>> {
        let mut t = self.tables.write();
        if let Some(flow) = t.forward.get(&key) {
            if !flow.is_closing() {
                return Some(flow.clone());
            }
            let old = t.forward.remove(&key)?;
            t.reverse.remove(&old.nat_port);
        }
        let range = u32::from(u16::MAX - PORT_FIRST) + 1;
        let mut port = None;
        for _ in 0..range {
            t.cursor = if t.cursor < PORT_FIRST || t.cursor == u16::MAX { PORT_FIRST } else { t.cursor + 1 };
            if !t.reverse.contains_key(&t.cursor) {
                port = Some(t.cursor);
                break;
            }
        }
        let nat_port = port?;
        let flow = Arc::new(Flow {
            src: key.0,
            sport: key.1,
            dst: key.2,
            dport: key.3,
            nat_port,
            last_seen: AtomicU64::new(now),
            closing: AtomicBool::new(false),
        });
        t.forward.insert(key, flow.clone());
        t.reverse.insert(nat_port, flow.clone());
        Some(flow)
    }

    pub fn sweep(&self, now: u64) -> usize {
        let mut t = self.tables.write();
        let stale: Vec<FlowKey> = t
            .forward
            .iter()
            .filter(|(_, flow)| {
                let limit = if flow.is_closing() { IDLE_CLOSED_SECS } else { IDLE_OPEN_SECS };
                now.saturating_sub(flow.last_seen.load(Ordering::Relaxed)) > limit
            })
            .map(|(key, _)| *key)
            .collect();
        for key in &stale {
            if let Some(flow) = t.forward.remove(key) {
                t.reverse.remove(&flow.nat_port);
            }
        }
        stale.len()
    }

    pub fn len(&self) -> usize {
        self.tables.read().forward.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(sport: u16) -> FlowKey {
        ("172.19.0.1".parse().unwrap(), sport, "1.2.3.4".parse().unwrap(), 443)
    }

    #[test]
    fn same_flow_keeps_its_port_and_both_directions_agree() {
        let nat = Nat::default();
        let a = nat.create(key(1), 0).unwrap();
        let b = nat.create(key(1), 0).unwrap();
        assert_eq!(a.nat_port, b.nat_port);
        assert_eq!(nat.by_port(a.nat_port).unwrap().sport, 1);
        assert_eq!(nat.lookup(&key(1)).unwrap().nat_port, a.nat_port);
        assert_ne!(nat.create(key(2), 0).unwrap().nat_port, a.nat_port);
    }

    #[test]
    fn reopening_a_closed_flow_gets_a_fresh_port() {
        // Старый порт ещё в TIME_WAIT у ядра: тот же кортеж с ним не пройдёт.
        let nat = Nat::default();
        let a = nat.create(key(1), 0).unwrap();
        a.mark_closing();
        let b = nat.create(key(1), 0).unwrap();
        assert_ne!(a.nat_port, b.nat_port);
        assert!(nat.by_port(a.nat_port).is_none());
    }

    #[test]
    fn sweep_treats_closed_and_open_flows_differently() {
        let nat = Nat::default();
        let open = nat.create(key(1), 0).unwrap();
        let closed = nat.create(key(2), 0).unwrap();
        closed.mark_closing();
        assert_eq!(nat.sweep(IDLE_CLOSED_SECS + 1), 1);
        assert_eq!(nat.len(), 1);
        open.touch(IDLE_OPEN_SECS);
        assert_eq!(nat.sweep(IDLE_OPEN_SECS + 10), 0);
        assert_eq!(nat.sweep(IDLE_OPEN_SECS * 3), 1);
    }

    #[test]
    fn ports_are_reused_after_wrapping() {
        let nat = Nat::default();
        nat.tables.write().cursor = u16::MAX - 1;
        let a = nat.create(key(1), 0).unwrap();
        let b = nat.create(key(2), 0).unwrap();
        assert_eq!(a.nat_port, u16::MAX);
        assert_eq!(b.nat_port, PORT_FIRST);
    }
}
