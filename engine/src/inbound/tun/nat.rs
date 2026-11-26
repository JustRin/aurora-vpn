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

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use fnv::FnvHashMap;
use parking_lot::RwLock;

const PORT_FIRST: u16 = 10_000;
const PORT_SLOTS: usize = (u16::MAX as usize - PORT_FIRST as usize) + 1;
/// Простаивающее соединение без FIN держим долго: ssh без keep-alive живёт часами.
const IDLE_OPEN_SECS: u64 = 2 * 3600;
const IDLE_CLOSED_SECS: u64 = 60;

pub type FlowKey = (IpAddr, u16, IpAddr, u16);

/// Плоская копия адресов потока: возвращается из горячего пути без клонирования `Arc`.
#[derive(Debug, Clone, Copy)]
pub struct FlowAddr {
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    pub nat_port: u16,
}

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
    #[inline]
    pub fn addr(&self) -> FlowAddr {
        FlowAddr {
            src: self.src,
            sport: self.sport,
            dst: self.dst,
            dport: self.dport,
            nat_port: self.nat_port,
        }
    }

    #[inline]
    pub fn touch(&self, now: u64) {
        // Сравнение перед записью: не пачкать строку кэша на каждом пакете.
        if self.last_seen.load(Ordering::Relaxed) != now {
            self.last_seen.store(now, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn mark_closing(&self) {
        if !self.closing.load(Ordering::Relaxed) {
            self.closing.store(true, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Relaxed)
    }
}

struct Tables {
    forward: FnvHashMap<FlowKey, Arc<Flow>>,
    /// Прямой массив по `nat_port - PORT_FIRST`: O(1) без хэширования на каждом пакете.
    reverse: Vec<Option<Arc<Flow>>>,
    cursor: u16,
}

impl Default for Tables {
    fn default() -> Self {
        Self {
            forward: FnvHashMap::default(),
            reverse: vec![None; PORT_SLOTS],
            cursor: 0,
        }
    }
}

impl Tables {
    #[inline]
    fn slot(port: u16) -> Option<usize> {
        port.checked_sub(PORT_FIRST).map(usize::from)
    }

    #[inline]
    fn get_port(&self, port: u16) -> Option<&Arc<Flow>> {
        self.reverse.get(Self::slot(port)?)?.as_ref()
    }
}

#[derive(Default)]
pub struct Nat {
    tables: RwLock<Tables>,
}

impl Nat {
    #[cfg(test)]
    pub fn lookup(&self, key: &FlowKey) -> Option<Arc<Flow>> {
        self.tables.read().forward.get(key).cloned()
    }

    pub fn by_port(&self, port: u16) -> Option<Arc<Flow>> {
        self.tables.read().get_port(port).cloned()
    }

    /// Горячий путь обратного направления: один read-lock, ноль клонирований `Arc`.
    #[inline]
    pub fn by_port_packet(&self, port: u16, now: u64, closing: bool) -> Option<FlowAddr> {
        let t = self.tables.read();
        let flow = t.get_port(port)?;
        flow.touch(now);
        if closing {
            flow.mark_closing();
        }
        Some(flow.addr())
    }

    /// Горячий путь прямого направления: на существующем потоке берётся только read-lock
    /// и не трогаются счётчики `Arc`.
    #[inline]
    pub fn forward_packet(&self, key: FlowKey, is_syn: bool, now: u64, closing: bool) -> Option<FlowAddr> {
        {
            let t = self.tables.read();
            if let Some(flow) = t.forward.get(&key) {
                if !(is_syn && flow.is_closing()) {
                    flow.touch(now);
                    if closing {
                        flow.mark_closing();
                    }
                    return Some(flow.addr());
                }
            }
        }
        if !is_syn {
            return None;
        }
        let flow = self.create(key, now)?;
        flow.touch(now);
        if closing {
            flow.mark_closing();
        }
        Some(flow.addr())
    }

    /// Новый поток. `None` — порты кончились: SYN просто теряется, клиент повторит.
    pub fn create(&self, key: FlowKey, now: u64) -> Option<Arc<Flow>> {
        let mut t = self.tables.write();
        if let Some(flow) = t.forward.get(&key) {
            if !flow.is_closing() {
                return Some(flow.clone());
            }
            let old = t.forward.remove(&key)?;
            if let Some(idx) = Tables::slot(old.nat_port) {
                t.reverse[idx] = None;
            }
        }
        let mut port = None;
        for _ in 0..PORT_SLOTS {
            t.cursor = if t.cursor < PORT_FIRST || t.cursor == u16::MAX { PORT_FIRST } else { t.cursor + 1 };
            let idx = usize::from(t.cursor - PORT_FIRST);
            if t.reverse[idx].is_none() {
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
        t.reverse[usize::from(nat_port - PORT_FIRST)] = Some(flow.clone());
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
                if let Some(idx) = Tables::slot(flow.nat_port) {
                    t.reverse[idx] = None;
                }
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
