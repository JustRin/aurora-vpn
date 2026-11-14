//! strict_route: что должно идти через туннель, идёт только через него.
//!
//! - DNS. Windows рассылает DNS-запросы по всем интерфейсам (Smart Multi-Homed Name
//!   Resolution), и запрос уходит провайдеру рядом с туннелем. Фильтры закрывают
//!   53-й порт вне адаптера.
//! - IPv6. Если у туннеля нет IPv6, публичный IPv6 закрыт целиком, как у sing-box
//!   («block ipv6» в sing-tun). Без этого IPv6 идёт мимо туннеля: системный DNS
//!   отдаёт только A, но браузер с DoH, свой кэш или явный адрес достают AAAA — и
//!   Google видит российский адрес абонента. Закрыт только 2000::/3: локальные
//!   fe80::/10, fc00::/7 и ::1 — это домашняя сеть и сама машина, не интернет.
//!
//! Мимо фильтров ходят сам процесс движка и программы, которые конфиг целиком шлёт
//! напрямую (сайдкар Xray: из РФ сервер доступен только по IPv6).
//!
//! Сессия динамическая: фильтры исчезают вместе с процессом, даже если он упадёт,
//! так что сеть машины от сбоя движка не ломается.

use std::ptr::{null, null_mut};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

const RPC_C_AUTHN_WINNT: u32 = 10;

/// Веса внутри подслоя: побеждает первый совпавший фильтр с наибольшим весом.
const W_PERMIT_APP: u8 = 15;
const W_PERMIT_TUN_DNS: u8 = 14;
const W_BLOCK_V6: u8 = 12;
const W_BLOCK_DNS: u8 = 10;

pub struct Filters {
    engine: HANDLE,
}

// Хэндл движка WFP — обычный процессный дескриптор, вызовы потокобезопасны.
unsafe impl Send for Filters {}
unsafe impl Sync for Filters {}

impl Drop for Filters {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.engine);
        }
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check(code: u32, what: &str) -> Result<(), String> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("{what}: {code:#x}"))
    }
}

/// Подслой: случайный GUID на запуск, живёт вместе с сессией.
fn random_guid() -> GUID {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    GUID {
        data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        data2: u16::from_le_bytes([b[4], b[5]]),
        data3: u16::from_le_bytes([b[6], b[7]]),
        data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
    }
}

/// Публичный IPv6 — 2000::/3: всё, что маршрутизируется в интернете.
fn global_unicast_v6() -> FWP_V6_ADDR_AND_MASK {
    let mut addr = [0u8; 16];
    addr[0] = 0x20;
    FWP_V6_ADDR_AND_MASK { addr, prefixLength: 3 }
}

/// Идентификаторы приложений WFP; память выдаёт и забирает сам WFP.
struct AppIds(Vec<*mut FWP_BYTE_BLOB>);

impl AppIds {
    fn add(&mut self, path: &str) -> Result<(), String> {
        let path_wide = wide(path);
        let mut blob: *mut FWP_BYTE_BLOB = null_mut();
        check(unsafe { FwpmGetAppIdFromFileName0(path_wide.as_ptr(), &mut blob) }, "FwpmGetAppIdFromFileName0")?;
        self.0.push(blob);
        Ok(())
    }
}

impl Drop for AppIds {
    fn drop(&mut self) {
        for blob in &mut self.0 {
            unsafe { FwpmFreeMemory0(blob as *mut _ as *mut *mut core::ffi::c_void) };
        }
    }
}

impl Filters {
    /// `block_v6` — у туннеля нет IPv6, публичный IPv6 закрыть. `exempt` — пути
    /// программ, которым можно наружу мимо туннеля.
    pub fn strict(tun_index: u32, block_v6: bool, exempt: &[String]) -> Result<Self, String> {
        unsafe {
            let mut session: FWPM_SESSION0 = std::mem::zeroed();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;

            let mut engine: HANDLE = null_mut();
            check(
                FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut engine),
                "FwpmEngineOpen0",
            )?;
            let filters = Filters { engine };

            let mut name = wide("Aurora");
            let mut sublayer: FWPM_SUBLAYER0 = std::mem::zeroed();
            sublayer.subLayerKey = random_guid();
            sublayer.displayData.name = name.as_mut_ptr();
            sublayer.weight = 0xffff;
            check(FwpmSubLayerAdd0(engine, &sublayer, null_mut()), "FwpmSubLayerAdd0")?;

            let mut luid: NET_LUID_LH = std::mem::zeroed();
            check(ConvertInterfaceIndexToLuid(tun_index, &mut luid), "ConvertInterfaceIndexToLuid")?;
            let mut luid_value: u64 = luid.Value;

            let mut apps = AppIds(Vec::new());
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            apps.add(&exe.to_string_lossy())?;
            for path in exempt {
                // Программы может не оказаться на диске (удалили, не скачали) —
                // тогда и разрешать нечего.
                if let Err(e) = apps.add(path) {
                    crate::warn!("tun", "strict_route: {path}: {e}");
                }
            }

            let mut port_cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            port_cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            port_cond.matchType = FWP_MATCH_EQUAL;
            port_cond.conditionValue.r#type = FWP_UINT16;
            port_cond.conditionValue.Anonymous.uint16 = 53;

            let mut iface_cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            iface_cond.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
            iface_cond.matchType = FWP_MATCH_EQUAL;
            iface_cond.conditionValue.r#type = FWP_UINT64;
            iface_cond.conditionValue.Anonymous.uint64 = &mut luid_value;

            let mut global_v6 = global_unicast_v6();
            let mut v6_cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            v6_cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            v6_cond.matchType = FWP_MATCH_EQUAL;
            v6_cond.conditionValue.r#type = FWP_V6_ADDR_MASK;
            v6_cond.conditionValue.Anonymous.v6AddrMask = &mut global_v6;

            let app_conds: Vec<FWPM_FILTER_CONDITION0> = apps
                .0
                .iter()
                .map(|&blob| {
                    let mut cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    cond.matchType = FWP_MATCH_EQUAL;
                    cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                    cond.conditionValue.Anonymous.byteBlob = blob;
                    cond
                })
                .collect();

            let add = |layer: GUID, conditions: &[FWPM_FILTER_CONDITION0], action: FWP_ACTION_TYPE, weight: u8, title: &str| {
                let mut title_wide = wide(title);
                let mut filter: FWPM_FILTER0 = std::mem::zeroed();
                filter.displayData.name = title_wide.as_mut_ptr();
                filter.layerKey = layer;
                filter.subLayerKey = sublayer.subLayerKey;
                filter.weight.r#type = FWP_UINT8;
                filter.weight.Anonymous.uint8 = weight;
                filter.numFilterConditions = conditions.len() as u32;
                filter.filterCondition = conditions.as_ptr() as *mut _;
                filter.action.r#type = action;
                check(FwpmFilterAdd0(engine, &filter, null_mut(), null_mut()), &format!("FwpmFilterAdd0 ({title})"))
            };

            let mut first_error = None;
            for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
                let mut added = Vec::new();
                for cond in &app_conds {
                    added.push(add(layer, std::slice::from_ref(cond), FWP_ACTION_PERMIT, W_PERMIT_APP, "Aurora: мимо туннеля можно"));
                }
                added.push(add(layer, &[port_cond, iface_cond], FWP_ACTION_PERMIT, W_PERMIT_TUN_DNS, "Aurora: DNS в туннеле"));
                added.push(add(layer, std::slice::from_ref(&port_cond), FWP_ACTION_BLOCK, W_BLOCK_DNS, "Aurora: DNS мимо туннеля"));
                if let Some(Err(e)) = added.into_iter().find(Result::is_err) {
                    first_error.get_or_insert(e);
                }
            }
            // Сбой фильтра IPv6 не должен снять защиту DNS: сессия динамическая,
            // и отказ от неё убрал бы все фильтры разом.
            if block_v6 {
                let blocked =
                    add(FWPM_LAYER_ALE_AUTH_CONNECT_V6, std::slice::from_ref(&v6_cond), FWP_ACTION_BLOCK, W_BLOCK_V6, "Aurora: IPv6 мимо туннеля");
                if let Err(e) = blocked {
                    crate::warn!("tun", "strict_route: {e}; IPv6 может идти мимо туннеля");
                }
            }

            match first_error {
                Some(error) => Err(error),
                None => Ok(filters),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_v6_block_covers_the_internet_and_spares_the_lan() {
        let mask = global_unicast_v6();
        let inside = |ip: &str| {
            let ip: std::net::Ipv6Addr = ip.parse().unwrap();
            let bits = u128::from(ip) >> (128 - u32::from(mask.prefixLength));
            bits == u128::from_be_bytes(mask.addr) >> (128 - u32::from(mask.prefixLength))
        };
        // Google, адрес российского провайдера, Teredo и 6to4 — закрыты.
        for ip in ["2a00:1450:4010:c05::64", "2a01:540:1:2::3", "2001:0:4136:e378::1", "2002:c000:204::1"] {
            assert!(inside(ip), "{ip}");
        }
        // Сама машина, локальная сеть и мультикаст — нет.
        for ip in ["::1", "fe80::1", "fd12:3456::1", "ff02::1"] {
            assert!(!inside(ip), "{ip}");
        }
    }

    /// WFP принимает все фильтры. Нужен админ:
    /// `cargo test --lib -- --ignored wfp_accepts` из повышенной консоли.
    /// Фильтры вешаются на петлю (индекс 1) и снимаются с концом теста.
    #[test]
    #[ignore = "нужны права администратора"]
    fn wfp_accepts_the_strict_filters() {
        let warnings = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let sink = warnings.clone();
        crate::log::set_sink(Some(crate::log_sink(move |_, line| sink.lock().push(line.to_string()))));
        let exempt = [r"C:\Windows\System32\curl.exe".to_string(), r"C:\нет\такой.exe".to_string()];
        let filters = Filters::strict(1, true, &exempt);
        crate::log::set_sink(None);
        assert!(filters.is_ok(), "{:?}", filters.err());
        let warnings = warnings.lock();
        // Предупреждение только про отсутствующую программу — фильтр IPv6 принят.
        assert!(warnings.iter().all(|w| !w.contains("IPv6")), "{warnings:?}");
    }
}
