//! Настройка адаптера и поиск физического интерфейса.
//!
//! Адрес, MTU, маршруты и DNS ставятся через netsh: это на старте и один раз, а
//! `store=active` гарантирует, что после падения в системе ничего не останется.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::process::CommandExt;
use std::process::Command;

use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPFORWARD_TABLE2,
    MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn run(program: &str, args: &[String]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() {
        return Ok(stdout);
    }
    Err(format!("{program} {}: {stdout}", args.join(" ")))
}

fn netsh(line: String) -> Result<String, String> {
    let args: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    run("netsh", &args)
}

pub struct Addressing {
    pub v4: Option<(Ipv4Addr, u8)>,
    pub v6: Option<(Ipv6Addr, u8)>,
    pub dns_v4: Ipv4Addr,
    pub dns_v6: Option<Ipv6Addr>,
    pub mtu: u32,
    pub auto_route: bool,
}

fn v4_mask(bits: u8) -> Ipv4Addr {
    Ipv4Addr::from(if bits == 0 { 0 } else { u32::MAX << (32 - u32::from(bits)) })
}

pub fn configure(index: u32, a: &Addressing) -> Result<(), String> {
    if let Some((ip, bits)) = a.v4 {
        netsh(format!("interface ipv4 set address name={index} static {ip} {}", v4_mask(bits)))?;
        netsh(format!("interface ipv4 set subinterface {index} mtu={} store=active", a.mtu))?;
        // Метрика ниже любой физической: иначе Windows разделит трафик по интерфейсам.
        netsh(format!("interface ipv4 set interface {index} metric=1"))?;
        netsh(format!("interface ipv4 set dnsservers {index} static {} register=none validate=no", a.dns_v4))?;
        if a.auto_route {
            for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
                netsh(format!("interface ipv4 add route {prefix} {index} 0.0.0.0 metric=0 store=active"))?;
            }
        }
    }
    if let Some((ip, bits)) = a.v6 {
        netsh(format!("interface ipv6 add address {index} {ip}/{bits} store=active"))?;
        netsh(format!("interface ipv6 set subinterface {index} mtu={} store=active", a.mtu))?;
        netsh(format!("interface ipv6 set interface {index} metric=1"))?;
        if let Some(dns) = a.dns_v6 {
            netsh(format!("interface ipv6 set dnsservers {index} static {dns} register=none validate=no"))?;
        }
        if a.auto_route {
            for prefix in ["::/1", "8000::/1"] {
                netsh(format!("interface ipv6 add route {prefix} {index} :: metric=0 store=active"))?;
            }
        }
    }
    // Старые ответы системного кэша могли прийти не тем резолвером.
    let _ = run("ipconfig", &["/flushdns".to_string()]);
    Ok(())
}

/// Разрешить входящие к слушателю. Без этого Брандмауэр Windows молча отбрасывает
/// SYN с адреса туннеля, и «интернет пропадает» при живом ядре.
pub fn allow_listener() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = exe.to_string_lossy().to_string();
    let name = "name=Aurora Engine".to_string();
    // Правило одно на установку: удалить старое и поставить заново проще, чем сравнивать.
    let _ = run(
        "netsh",
        &["advfirewall".into(), "firewall".into(), "delete".into(), "rule".into(), name.clone()],
    );
    run(
        "netsh",
        &[
            "advfirewall".into(),
            "firewall".into(),
            "add".into(),
            "rule".into(),
            name,
            "dir=in".into(),
            "action=allow".into(),
            "protocol=TCP".into(),
            format!("program={path}"),
            "enable=yes".into(),
            "profile=any".into(),
        ],
    )
    .map(|_| ())
}

/// Индекс интерфейса с лучшим маршрутом по умолчанию, не считая нашего адаптера.
pub fn default_interface(family: u16, exclude: u32) -> Option<u32> {
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if GetIpForwardTable2(family, &mut table) != NO_ERROR || table.is_null() {
            return None;
        }
        let count = (*table).NumEntries as usize;
        let rows = std::ptr::addr_of!((*table).Table) as *const windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2;
        let mut best: Option<(u32, u32)> = None;
        for i in 0..count {
            let row = &*rows.add(i);
            if row.DestinationPrefix.PrefixLength != 0 || row.InterfaceIndex == exclude {
                continue;
            }
            let mut entry: MIB_IPINTERFACE_ROW = std::mem::zeroed();
            InitializeIpInterfaceEntry(&mut entry);
            entry.Family = family;
            entry.InterfaceIndex = row.InterfaceIndex;
            if GetIpInterfaceEntry(&mut entry) != NO_ERROR || !entry.Connected {
                continue;
            }
            let metric = row.Metric.saturating_add(entry.Metric);
            if best.is_none_or(|(_, m)| metric < m) {
                best = Some((row.InterfaceIndex, metric));
            }
        }
        FreeMibTable(table as *const _);
        best.map(|(index, _)| index)
    }
}

pub fn default_v4(exclude: u32) -> Option<u32> {
    default_interface(AF_INET, exclude)
}

pub fn default_v6(exclude: u32) -> Option<u32> {
    default_interface(AF_INET6, exclude)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(v4_mask(30), Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(v4_mask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn route_table_is_readable_without_elevation() {
        // На машине без сети это None, но вызов не должен падать.
        let _ = default_v4(0);
        let _ = default_v6(0);
    }
}
