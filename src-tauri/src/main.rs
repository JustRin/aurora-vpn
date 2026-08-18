// Keep the console window from appearing behind the UI in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    aurora_vpn_lib::run()
}
