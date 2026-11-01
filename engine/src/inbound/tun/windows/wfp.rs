//! strict_route: DNS только через туннель.
//!
//! Windows рассылает DNS-запросы по всем интерфейсам (Smart Multi-Homed Name
//! Resolution), и запрос уходит провайдеру рядом с туннелем. Фильтры WFP закрывают
//! 53-й порт вне адаптера. Сессия динамическая: фильтры исчезают вместе с процессом,
//! даже если он упадёт, так что сеть машины от сбоя движка не ломается.

use std::ptr::{null, null_mut};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

const RPC_C_AUTHN_WINNT: u32 = 10;

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

struct Layer {
    guid: GUID,
    remote_port: GUID,
    local_interface: GUID,
    app_id: GUID,
}

impl Filters {
    pub fn block_outside_dns(tun_index: u32) -> Result<Self, String> {
        unsafe {
            let mut session: FWPM_SESSION0 = std::mem::zeroed();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;

            let mut engine: HANDLE = null_mut();
            check(
                FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut engine),
                "FwpmEngineOpen0",
            )?;
            let filters = Filters { engine };

            let mut name = wide("Aurora DNS");
            let mut sublayer: FWPM_SUBLAYER0 = std::mem::zeroed();
            sublayer.subLayerKey = random_guid();
            sublayer.displayData.name = name.as_mut_ptr();
            sublayer.weight = 0xffff;
            check(FwpmSubLayerAdd0(engine, &sublayer, null_mut()), "FwpmSubLayerAdd0")?;

            let mut luid: NET_LUID_LH = std::mem::zeroed();
            check(ConvertInterfaceIndexToLuid(tun_index, &mut luid), "ConvertInterfaceIndexToLuid")?;
            let mut luid_value: u64 = luid.Value;

            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let exe_wide = wide(&exe.to_string_lossy());
            let mut app_blob: *mut FWP_BYTE_BLOB = null_mut();
            check(FwpmGetAppIdFromFileName0(exe_wide.as_ptr(), &mut app_blob), "FwpmGetAppIdFromFileName0")?;

            let layers = [
                Layer {
                    guid: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    remote_port: FWPM_CONDITION_IP_REMOTE_PORT,
                    local_interface: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    app_id: FWPM_CONDITION_ALE_APP_ID,
                },
                Layer {
                    guid: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    remote_port: FWPM_CONDITION_IP_REMOTE_PORT,
                    local_interface: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    app_id: FWPM_CONDITION_ALE_APP_ID,
                },
            ];

            let mut result = Ok(());
            for layer in &layers {
                let mut port_cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                port_cond.fieldKey = layer.remote_port;
                port_cond.matchType = FWP_MATCH_EQUAL;
                port_cond.conditionValue.r#type = FWP_UINT16;
                port_cond.conditionValue.Anonymous.uint16 = 53;

                let mut iface_cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                iface_cond.fieldKey = layer.local_interface;
                iface_cond.matchType = FWP_MATCH_EQUAL;
                iface_cond.conditionValue.r#type = FWP_UINT64;
                iface_cond.conditionValue.Anonymous.uint64 = &mut luid_value;

                let mut app_cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                app_cond.fieldKey = layer.app_id;
                app_cond.matchType = FWP_MATCH_EQUAL;
                app_cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                app_cond.conditionValue.Anonymous.byteBlob = app_blob;

                // Порядок решает вес: наш процесс и адаптер разрешены, остальное закрыто.
                let attempts: [(&[FWPM_FILTER_CONDITION0], FWP_ACTION_TYPE, u8, &str); 3] = [
                    (std::slice::from_ref(&app_cond), FWP_ACTION_PERMIT, 15, "Aurora: движок"),
                    (&[port_cond, iface_cond], FWP_ACTION_PERMIT, 14, "Aurora: DNS в туннеле"),
                    (std::slice::from_ref(&port_cond), FWP_ACTION_BLOCK, 10, "Aurora: DNS мимо туннеля"),
                ];
                for (conditions, action, weight, title) in attempts {
                    let mut title_wide = wide(title);
                    let mut filter: FWPM_FILTER0 = std::mem::zeroed();
                    filter.displayData.name = title_wide.as_mut_ptr();
                    filter.layerKey = layer.guid;
                    filter.subLayerKey = sublayer.subLayerKey;
                    filter.weight.r#type = FWP_UINT8;
                    filter.weight.Anonymous.uint8 = weight;
                    filter.numFilterConditions = conditions.len() as u32;
                    filter.filterCondition = conditions.as_ptr() as *mut _;
                    filter.action.r#type = action;
                    let code = FwpmFilterAdd0(engine, &filter, null_mut(), null_mut());
                    if code != ERROR_SUCCESS {
                        result = Err(format!("FwpmFilterAdd0 ({title}): {code:#x}"));
                    }
                }
            }
            FwpmFreeMemory0(&mut app_blob as *mut _ as *mut *mut core::ffi::c_void);
            result.map(|()| filters)
        }
    }
}
