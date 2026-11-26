//! Какому процессу принадлежит соединение.
//!
//! sing-box запрашивает таблицу TCP/UDP на каждое соединение, и в режиме
//! раздельного туннеля это именно то место, где он тратит процессор: чем больше у
//! системы соединений, тем дороже каждая новая вкладка. Здесь снимок разбирается в
//! хэш по локальному порту и живёт `SNAPSHOT_MS`: пачка одновременных соединений
//! обходится одним снятием, а UDP и TCP снимаются порознь — только то, что спросили.

use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Process {
    pub name_lower: String,
    pub path_lower: String,
    pub path: String,
}

#[cfg(windows)]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use fnv::FnvHashMap;
    use parking_lot::Mutex;
    use windows_sys::Win32::Foundation::{CloseHandle, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID,
        MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::Process;

    const SNAPSHOT_MS: u64 = 250;
    const PROCESS_TTL: Duration = Duration::from_secs(60);

    #[derive(Default)]
    struct Table {
        by_addr: FnvHashMap<(IpAddr, u16), u32>,
        /// Время начала последнего снятия таблицы: всё, что открылось раньше, в ней уже есть.
        taken: Option<Instant>,
    }

    struct Tables {
        tcp4: Table,
        tcp6: Table,
        udp4: Table,
        udp6: Table,
        /// Буфер живёт между снимками: таблица у всех большая и размер стабилен.
        buffer: Vec<u8>,
    }

    fn tables() -> &'static Mutex<Tables> {
        static T: OnceLock<Mutex<Tables>> = OnceLock::new();
        T.get_or_init(|| {
            Mutex::new(Tables {
                tcp4: Table::default(),
                tcp6: Table::default(),
                udp4: Table::default(),
                udp6: Table::default(),
                buffer: Vec::new(),
            })
        })
    }

    fn processes() -> &'static Mutex<FnvHashMap<u32, (Option<Process>, Instant)>> {
        static P: OnceLock<Mutex<FnvHashMap<u32, (Option<Process>, Instant)>>> = OnceLock::new();
        P.get_or_init(Default::default)
    }

    /// Порт в таблицах лежит в младших 16 битах DWORD в сетевом порядке.
    fn port_of(raw: u32) -> u16 {
        u16::from_be(raw as u16)
    }

    fn query<F>(buffer: &mut Vec<u8>, call: F) -> bool
    where
        F: Fn(*mut core::ffi::c_void, *mut u32) -> u32,
    {
        for _ in 0..3 {
            let mut size = buffer.capacity().max(16 * 1024) as u32;
            buffer.clear();
            buffer.reserve(size as usize);
            let rc = call(buffer.as_mut_ptr() as *mut _, &mut size);
            if rc == NO_ERROR {
                unsafe { buffer.set_len(size as usize) };
                return true;
            }
            // Таблица подросла: просим с запасом и пробуем снова.
            buffer.reserve(size as usize + 4096);
        }
        false
    }

    fn refresh_one(table: &mut Table, buffer: &mut Vec<u8>, udp: bool, v6: bool) {
        let started = Instant::now();
        table.by_addr.clear();
        let family = if v6 { AF_INET6 } else { AF_INET };
        if !udp {
            let ok = query(buffer, |p, s| unsafe {
                GetExtendedTcpTable(p, s, 0, u32::from(family), TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
            });
            if ok && buffer.len() >= 4 {
                let count = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                if !v6 {
                    let raw = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                    let rows = unsafe { core::ptr::addr_of!((*raw).table) as *const MIB_TCPROW_OWNER_PID };
                    let limit = (buffer.len().saturating_sub(4)) / core::mem::size_of::<MIB_TCPROW_OWNER_PID>();
                    for i in 0..count.min(limit) {
                        let row = unsafe { rows.add(i).read_unaligned() };
                        if row.dwOwningPid != 0 {
                            let ip = IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()));
                            table.by_addr.insert((ip, port_of(row.dwLocalPort)), row.dwOwningPid);
                        }
                    }
                } else {
                    // MIB_TCP6ROW_OWNER_PID: адрес 16, scope 4, порт 4, удалённые 24, state 4, pid 4.
                    const ROW: usize = 56;
                    let limit = (buffer.len().saturating_sub(4)) / ROW;
                    for i in 0..count.min(limit) {
                        let at = 4 + i * ROW;
                        let pid = u32::from_ne_bytes(buffer[at + 52..at + 56].try_into().unwrap());
                        if pid != 0 {
                            let octets: [u8; 16] = buffer[at..at + 16].try_into().unwrap();
                            let port = u32::from_ne_bytes(buffer[at + 20..at + 24].try_into().unwrap());
                            table.by_addr.insert((IpAddr::V6(Ipv6Addr::from(octets)), port_of(port)), pid);
                        }
                    }
                }
            }
        } else {
            let ok = query(buffer, |p, s| unsafe {
                GetExtendedUdpTable(p, s, 0, u32::from(family), UDP_TABLE_OWNER_PID, 0)
            });
            if ok && buffer.len() >= 4 {
                let count = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                if !v6 {
                    let raw = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
                    let rows = unsafe { core::ptr::addr_of!((*raw).table) as *const MIB_UDPROW_OWNER_PID };
                    let limit = (buffer.len().saturating_sub(4)) / core::mem::size_of::<MIB_UDPROW_OWNER_PID>();
                    for i in 0..count.min(limit) {
                        let row = unsafe { rows.add(i).read_unaligned() };
                        if row.dwOwningPid != 0 {
                            let ip = IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()));
                            table.by_addr.insert((ip, port_of(row.dwLocalPort)), row.dwOwningPid);
                        }
                    }
                } else {
                    // MIB_UDP6ROW_OWNER_PID: адрес 16, scope 4, порт 4, pid 4.
                    const ROW: usize = 28;
                    let limit = (buffer.len().saturating_sub(4)) / ROW;
                    for i in 0..count.min(limit) {
                        let at = 4 + i * ROW;
                        let pid = u32::from_ne_bytes(buffer[at + 24..at + 28].try_into().unwrap());
                        if pid != 0 {
                            let octets: [u8; 16] = buffer[at..at + 16].try_into().unwrap();
                            let port = u32::from_ne_bytes(buffer[at + 20..at + 24].try_into().unwrap());
                            table.by_addr.insert((IpAddr::V6(Ipv6Addr::from(octets)), port_of(port)), pid);
                        }
                    }
                }
            }
        }
        table.taken = Some(started);
    }

    fn find_in(table: &Table, ip: IpAddr, port: u16, udp: bool) -> Option<u32> {
        if let Some(&pid) = table.by_addr.get(&(ip, port)) {
            return Some(pid);
        }
        if udp {
            let any = match ip {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };
            if ip != any {
                if let Some(&pid) = table.by_addr.get(&(any, port)) {
                    return Some(pid);
                }
            }
        }
        None
    }

    fn lookup_table(
        table: &mut Table,
        buffer: &mut Vec<u8>,
        udp: bool,
        v6: bool,
        ip: IpAddr,
        port: u16,
        requested_at: Instant,
    ) -> Option<u32> {
        let fresh = table.taken.is_some_and(|at| at.elapsed() < Duration::from_millis(SNAPSHOT_MS));
        if fresh {
            if let Some(pid) = find_in(table, ip, port, udp) {
                return Some(pid);
            }
            // Снимок уже снят после того, как этот запрос попал в очередь: пачка
            // одновременных промахов обходится одним вызовом WinAPI.
            if table.taken.is_some_and(|at| at >= requested_at) {
                return None;
            }
        }
        refresh_one(table, buffer, udp, v6);
        find_in(table, ip, port, udp)
    }

    fn pid_for(network: &str, source: SocketAddr, requested_at: Instant) -> Option<u32> {
        let mut guard = tables().lock();
        let t = &mut *guard;
        let udp = network == "udp";
        let port = source.port();
        match source.ip() {
            IpAddr::V4(v4) => {
                let table = if udp { &mut t.udp4 } else { &mut t.tcp4 };
                if let Some(pid) = lookup_table(table, &mut t.buffer, udp, false, IpAddr::V4(v4), port, requested_at) {
                    return Some(pid);
                }
                // Dual-stack IPv6-сокет (IPV6_V6ONLY=0) при отправке IPv4 виден только в таблице AF_INET6.
                let table6 = if udp { &mut t.udp6 } else { &mut t.tcp6 };
                lookup_table(table6, &mut t.buffer, udp, true, IpAddr::V6(v4.to_ipv6_mapped()), port, requested_at)
            }
            IpAddr::V6(v6) => {
                let table = if udp { &mut t.udp6 } else { &mut t.tcp6 };
                lookup_table(table, &mut t.buffer, udp, true, IpAddr::V6(v6), port, requested_at)
            }
        }
    }

    fn image_path(pid: u32) -> Option<String> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
            CloseHandle(handle);
            (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    pub fn find(network: &str, source: SocketAddr, requested_at: Instant) -> Option<Process> {
        let pid = pid_for(network, source, requested_at)?;
        if pid == 0 {
            return None;
        }
        if let Some((process, at)) = processes().lock().get(&pid) {
            if at.elapsed() < PROCESS_TTL {
                return process.clone();
            }
        }
        let process = image_path(pid).map(|path| {
            let name = path.rsplit(['\\', '/']).next().unwrap_or(&path).to_string();
            Process { name_lower: name.to_lowercase(), path_lower: path.to_lowercase(), path }
        });
        let mut cache = processes().lock();
        if cache.len() > 2048 {
            cache.clear();
        }
        cache.insert(pid, (process.clone(), Instant::now()));
        process
    }
}

/// Системные вызовы блокируют поток: не на рабочих потоках рантайма.
pub async fn lookup(network: &'static str, source: SocketAddr) -> Option<Process> {
    #[cfg(windows)]
    {
        let requested_at = std::time::Instant::now();
        tokio::task::spawn_blocking(move || imp::find(network, source, requested_at))
            .await
            .ok()
            .flatten()
    }
    #[cfg(not(windows))]
    {
        let _ = (network, source);
        None
    }
}
