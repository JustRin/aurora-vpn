//! TUN на Windows: адаптер Wintun, маршруты, фильтры DNS, смена сетевого интерфейса.

mod route;
mod wfp;

use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::{parse_addresses, Device, TunHandle};
use crate::common::set_bypass_interface;
use crate::config::InboundOpts;
use crate::engine::Context;

/// 2 МиБ на кольцо, колец два. Память кольца занята всегда, поэтому тут компромисс:
/// ёмкость нужна только на всплески, а просевший пакет TCP перепошлёт сам.
const RING_CAPACITY: u32 = 0x20_0000;
const ADAPTER_NAME: &str = "Aurora";

struct Wintun {
    session: Arc<wintun::Session>,
}

impl Device for Wintun {
    fn recv(&self, handle: &mut dyn FnMut(&[u8])) -> io::Result<bool> {
        match self.session.receive_blocking() {
            Ok(packet) => {
                handle(packet.bytes());
                Ok(true)
            }
            Err(wintun::Error::ShuttingDown) => Ok(false),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn send(&self, len: u16, fill: &mut dyn FnMut(&mut [u8]) -> bool) {
        let Ok(mut packet) = self.session.allocate_send_packet(len) else { return };
        if fill(packet.bytes_mut()) {
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

    let filters = if opts.strict_route {
        wfp::Filters::block_outside_dns(index)
            .map_err(|e| crate::warn!("tun", "strict_route: {e}; DNS может идти мимо туннеля"))
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
            current_v4 = v4;
            current_v6 = v6;
        }
    }
}
