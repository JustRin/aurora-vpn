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
    use std::collections::HashMap;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use parking_lot::Mutex;
    use windows_sys::Win32::Foundation::{CloseHandle, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID,
        MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::Process;

    const SNAPSHOT_MS: u64 = 250;
    const PROCESS_TTL: Duration = Duration::from_secs(60);

    #[derive(Default)]
    struct Snapshot {
        tcp: HashMap<u16, u32>,
        udp: HashMap<u16, u32>,
    }

    struct Tables {
        snapshot: Snapshot,
        taken_tcp: Option<Instant>,
        taken_udp: Option<Instant>,
        /// Буфер живёт между снимками: таблица у всех большая и размер стабилен.
        buffer: Vec<u8>,
    }

    fn tables() -> &'static Mutex<Tables> {
        static T: OnceLock<Mutex<Tables>> = OnceLock::new();
        T.get_or_init(|| Mutex::new(Tables { snapshot: Snapshot::default(), taken_tcp: None, taken_udp: None, buffer: Vec::new() }))
    }

    fn processes() -> &'static Mutex<HashMap<u32, (Option<Process>, Instant)>> {
        static P: OnceLock<Mutex<HashMap<u32, (Option<Process>, Instant)>>> = OnceLock::new();
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

    fn refresh(tables: &mut Tables, udp: bool) {
        let mut snap = Snapshot::default();
        let mut buffer = std::mem::take(&mut tables.buffer);

        for family in [AF_INET, AF_INET6] {
            let ok = !udp && query(&mut buffer, |p, s| unsafe {
                GetExtendedTcpTable(p, s, 0, u32::from(family), TCP_TABLE_OWNER_PID_ALL, 0)
            });
            if ok && buffer.len() >= 4 {
                let count = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                if family == AF_INET {
                    let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                    let rows = unsafe { core::ptr::addr_of!((*table).table) as *const MIB_TCPROW_OWNER_PID };
                    let limit = (buffer.len().saturating_sub(4)) / core::mem::size_of::<MIB_TCPROW_OWNER_PID>();
                    for i in 0..count.min(limit) {
                        let row = unsafe { rows.add(i).read_unaligned() };
                        snap.tcp.insert(port_of(row.dwLocalPort), row.dwOwningPid);
                    }
                } else {
                    // MIB_TCP6ROW_OWNER_PID: адрес 16, scope 4, порт 4, удалённые 24, state 4, pid 4.
                    const ROW: usize = 56;
                    let limit = (buffer.len().saturating_sub(4)) / ROW;
                    for i in 0..count.min(limit) {
                        let at = 4 + i * ROW;
                        let port = u32::from_ne_bytes(buffer[at + 20..at + 24].try_into().unwrap());
                        let pid = u32::from_ne_bytes(buffer[at + 52..at + 56].try_into().unwrap());
                        snap.tcp.entry(port_of(port)).or_insert(pid);
                    }
                }
            }

            let ok = udp && query(&mut buffer, |p, s| unsafe {
                GetExtendedUdpTable(p, s, 0, u32::from(family), UDP_TABLE_OWNER_PID, 0)
            });
            if ok && buffer.len() >= 4 {
                let count = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                if family == AF_INET {
                    let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
                    let rows = unsafe { core::ptr::addr_of!((*table).table) as *const MIB_UDPROW_OWNER_PID };
                    let limit = (buffer.len().saturating_sub(4)) / core::mem::size_of::<MIB_UDPROW_OWNER_PID>();
                    for i in 0..count.min(limit) {
                        let row = unsafe { rows.add(i).read_unaligned() };
                        snap.udp.insert(port_of(row.dwLocalPort), row.dwOwningPid);
                    }
                } else {
                    // MIB_UDP6ROW_OWNER_PID: адрес 16, scope 4, порт 4, pid 4.
                    const ROW: usize = 28;
                    let limit = (buffer.len().saturating_sub(4)) / ROW;
                    for i in 0..count.min(limit) {
                        let at = 4 + i * ROW;
                        let port = u32::from_ne_bytes(buffer[at + 20..at + 24].try_into().unwrap());
                        let pid = u32::from_ne_bytes(buffer[at + 24..at + 28].try_into().unwrap());
                        snap.udp.entry(port_of(port)).or_insert(pid);
                    }
                }
            }
        }
        tables.buffer = buffer;
        if udp {
            tables.snapshot.udp = snap.udp;
            tables.taken_udp = Some(Instant::now());
        } else {
            tables.snapshot.tcp = snap.tcp;
            tables.taken_tcp = Some(Instant::now());
        }
    }

    fn pid_for(network: &str, port: u16) -> Option<u32> {
        let mut t = tables().lock();
        let udp = network == "udp";
        let taken = if udp { t.taken_udp } else { t.taken_tcp };
        let fresh = taken.is_some_and(|at| at.elapsed() < Duration::from_millis(SNAPSHOT_MS));
        let find = |t: &Tables| {
            let map = if udp { &t.snapshot.udp } else { &t.snapshot.tcp };
            map.get(&port).copied()
        };
        if fresh {
            if let Some(pid) = find(&t) {
                return Some(pid);
            }
        }
        // Промах по свежему снимку значит лишь, что сокет моложе снимка.
        refresh(&mut t, udp);
        find(&t)
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

    pub fn find(network: &str, port: u16) -> Option<Process> {
        let pid = pid_for(network, port)?;
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
        let port = source.port();
        tokio::task::spawn_blocking(move || imp::find(network, port)).await.ok().flatten()
    }
    #[cfg(not(windows))]
    {
        let _ = (network, source);
        None
    }
}
