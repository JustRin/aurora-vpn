//! TUN на Windows: адаптер Wintun, маршруты, фильтры DNS, смена сетевого интерфейса.

mod route;
mod wfp;

use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::{parse_addresses, Device, TunHandle};
use crate::common::{bump_network_generation, set_bypass_interface};
use crate::config::InboundOpts;
use crate::engine::Context;

/// 8 МиБ на кольцо, как у sing-box/WireGuard: в схеме loopback-NAT через кольца
/// Wintun идут оба направления (сегменты и ACK), и на 2 МиБ всплески скачивания
/// переполняли TX-кольцо, вызывая потери локальных пакетов и 300–1000 мс RTO.
const RING_CAPACITY: u32 = 0x80_0000;
const ADAPTER_NAME: &str = "Aurora";

struct Wintun {
    session: Arc<wintun::Session>,
}

impl Device for Wintun {
    fn recv(&self, handle: &mut dyn FnMut(&[u8])) -> io::Result<bool> {
        match self.session.receive_blocking() {
            Ok(packet) => {
                handle(packet.bytes());
                drop(packet);
                // Сразу выбираем пачку уже лежащих в кольце пакетов без лишних кругов.
                for _ in 0..64 {
                    match self.session.try_receive() {
                        Ok(Some(p)) => handle(p.bytes()),
                        Ok(None) => break,
                        Err(wintun::Error::ShuttingDown) => return Ok(false),
                        Err(e) => return Err(io::Error::other(e.to_string())),
                    }
                }
                Ok(true)
            }
            Err(wintun::Error::ShuttingDown) => Ok(false),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn send(&self, len: u16, fill: &mut dyn FnMut(&mut [u8]) -> bool) {
        // Если TX-кольцо на мгновение забито (NDIS ещё забирает), коротко уступаем
        // вместо мгновенной потери локального TCP-сегмента и 300 мс RTO-паузы.
        let mut packet = match self.session.allocate_send_packet(len) {
            Ok(p) => p,
            Err(_) => {
                let mut got = None;
                for attempt in 0..8 {
                    if attempt < 4 {
                        std::thread::yield_now();
                    } else {
                        std::thread::sleep(Duration::from_micros(250));
                    }
                    if let Ok(p) = self.session.allocate_send_packet(len) {
                        got = Some(p);
                        break;
                    }
                }
                let Some(p) = got else { return };
                p
            }
        };
        if fill(packet.bytes_mut()) {
            self.session.send_packet(packet);
        } else {
            // Выделенный у Wintun пакет обязан уйти в send_packet, иначе кольцо
            // отправки заблокируется навсегда (Wintun ждёт пакеты в порядке выдачи).
            packet.bytes_mut().fill(0);
            self.session.send_packet(packet);
        }
    }

    fn shutdown(&self) {
        let _ = self.session.shutdown();
    }
}

fn default_dll_path() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(|dir| dir.join("wintun.dll"))
}

pub async fn start(
    opts: &InboundOpts,
    ctx: Arc<Context>,
    auto_detect: bool,
    wintun_dll: Option<&Path>,
    exempt: &[String],
) -> Result<TunHandle, String> {
    let (v4, v6) = parse_addresses(&opts.address);
    if v4.is_none() && v6.is_none() {
        return Err("у tun-входа нет адреса".to_string());
    }

    let dll = wintun_dll.map(Path::to_path_buf).or_else(default_dll_path).ok_or("не удалось найти каталог программы")?;
    let library = unsafe { wintun::load_from_path(&dll) }.map_err(|e| format!("wintun.dll ({}): {e}", dll.display()))?;

    // Пока наших маршрутов нет, лучший маршрут — настоящий.
    let phys_v4 = route::default_v4(0);
    let phys_v6 = route::default_v6(0);
    if auto_detect {
        if phys_v4.is_none() && v4.is_some() {
            return Err("не найден интерфейс с выходом в сеть".to_string());
        }
        set_bypass_interface(phys_v4.unwrap_or(0), phys_v6.unwrap_or(0));
    }

    // Адаптер мог остаться после аварийного завершения.
    let adapter = match wintun::Adapter::open(&library, ADAPTER_NAME) {
        Ok(existing) => existing,
        Err(_) => wintun::Adapter::create(&library, ADAPTER_NAME, "Aurora VPN", None)
            .map_err(|e| format!("создание адаптера (нужны права администратора): {e}"))?,
    };
    let index = adapter.get_adapter_index().map_err(|e| format!("индекс адаптера: {e}"))?;
    let session = Arc::new(adapter.start_session(RING_CAPACITY).map_err(|e| format!("сессия Wintun: {e}"))?);

    let addressing = route::Addressing {
        v4: v4.as_ref().map(|p| (p.tun, p.bits)),
        v6: v6.as_ref().map(|p| (p.tun, p.bits)),
        dns_v4: v4.as_ref().map(|p| p.server).unwrap_or(Ipv4Addr::UNSPECIFIED),
        dns_v6: v6.as_ref().map(|p| p.server),
        mtu: if opts.mtu == 0 { 9000 } else { opts.mtu },
        auto_route: opts.auto_route,
    };
    tokio::task::spawn_blocking(move || {
        route::allow_listener()?;
        route::configure(index, &addressing)
    })
    .await
    .map_err(|e| e.to_string())??;

    if auto_detect {
        tokio::spawn(watch_interface(index, phys_v4.unwrap_or(0), phys_v6.unwrap_or(0)));
    }

    // Туннель без IPv6 при строгом режиме закрывает публичный IPv6 вовсе — как
    // sing-box («block ipv6» в sing-tun). Иначе IPv6 идёт мимо туннеля: DNS отдаёт
    // только A, но браузер с DoH, кэш или явный адрес достают AAAA, и Google видит
    // настоящий адрес абонента — у российских провайдеров IPv6 есть почти везде.
    let filters = if opts.strict_route {
        let block_v6 = v6.is_none();
        wfp::Filters::strict(index, block_v6, exempt)
            .map_err(|e| crate::warn!("tun", "strict_route: {e}; DNS и IPv6 могут идти мимо туннеля"))
            .ok()
    } else {
        None
    };

    let device: Arc<dyn Device> = Arc::new(Wintun { session });
    // Адаптер держит и библиотеку: всё это живёт, пока жив туннель.
    let platform = Box::new((adapter, filters));
    super::run(device, v4.as_ref(), v6.as_ref(), ctx, platform).await
}

/// Ноутбук сменил Wi-Fi: новые дозвоны должны уйти через новый интерфейс.
async fn watch_interface(tun_index: u32, mut current_v4: u32, mut current_v6: u32) {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let (v4, v6) = tokio::task::spawn_blocking(move || (route::default_v4(tun_index), route::default_v6(tun_index)))
            .await
            .unwrap_or((None, None));
        let (v4, v6) = (v4.unwrap_or(0), v6.unwrap_or(0));
        if (v4, v6) != (current_v4, current_v6) {
            crate::info!("tun", "сетевой интерфейс сменился: {v4}/{v6}");
            set_bypass_interface(v4, v6);
            bump_network_generation();
            current_v4 = v4;
            current_v6 = v6;
        }
    }
}
