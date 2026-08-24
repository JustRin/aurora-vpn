//! Platform integration. Everything here is behind a stable, OS-agnostic API so
//! the rest of the app never needs a `cfg` block.

pub mod autostart;
pub mod clipboard;
pub mod dialog;
pub mod elevate;
pub mod flash;
pub mod icmp;
pub mod notify;
pub mod open;
pub mod procs;
pub mod sysproxy;
