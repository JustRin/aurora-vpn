//! ICMP-эхо — тот же вопрос, что задаёт системный `ping`.
//!
//! Задержку до узла меряют рукопожатием TCP, но у Hysteria2 и TUIC его нет
//! вовсе: они живут на UDP поверх QUIC, и порт на TCP молчит по устройству, а
//! не потому что сервер лёг. Прочерк в таких строках отвечал не «не
//! отвечает», а «мы не спрашивали». ICMP спрашивает саму машину — и отвечает
//! ровно то, что человек и ждёт от слова «пинг».
//!
//! Своих сокетов не поднимаем: IcmpSendEcho живёт в iphlpapi и правами
//! администратора не интересуется, в отличие от raw-сокетов.

use std::net::Ipv4Addr;
use std::time::Duration;

/// Полезная нагрузка эха. 32 байта — столько же шлёт `ping` из Windows.
#[cfg(windows)]
const PAYLOAD: [u8; 32] = [b'a'; 32];

/// Круговая задержка в миллисекундах. None — ответа нет: сервер молчит, ICMP
/// режет провайдер или адрес шестой версии (Icmp6 здесь не заведён — узлов на
/// голом IPv6 в списках не встречается).
#[cfg(windows)]
pub fn ping(ip: Ipv4Addr, timeout: Duration) -> Option<u32> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
    };

    let handle = unsafe { IcmpCreateFile() };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return None;
    }

    // Ответ приходит в один буфер: заголовок, эхо целиком и место под
    // сообщение об ошибке — так требует iphlpapi.
    let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8];
    // IPAddr держит байты в сетевом порядке — октеты ложатся как есть.
    let destination = u32::from_ne_bytes(ip.octets());
    let count = unsafe {
        IcmpSendEcho(
            handle,
            destination,
            PAYLOAD.as_ptr().cast(),
            PAYLOAD.len() as u16,
            std::ptr::null(),
            reply.as_mut_ptr().cast(),
            reply.len() as u32,
            timeout.as_millis().min(u128::from(u32::MAX)) as u32,
        )
    };

    let rtt = if count == 0 {
        None
    } else {
        // Буфер выделен под ICMP_ECHO_REPLY и заполнен системой.
        let echo = unsafe { &*(reply.as_ptr() as *const ICMP_ECHO_REPLY) };
        // Status 0 — IP_SUCCESS; всё остальное (недоступен, TTL, таймаут)
        // приходит тем же путём и ответом не считается.
        //
        // Ноль отбрасывается вместе с ними: до сервера за океаном столько не
        // бывает, а получается он там, где эхо до места не дошло — его
        // подделал кто-то по дороге. Живой туннель в системе отвечает так на
        // любой адрес, и «0 мс» в списке было бы хуже прочерка.
        (echo.Status == 0 && echo.RoundTripTime > 0).then_some(echo.RoundTripTime)
    };
    unsafe { IcmpCloseHandle(handle) };
    rtt
}

#[cfg(not(windows))]
pub fn ping(_ip: Ipv4Addr, _timeout: Duration) -> Option<u32> {
    None
}

