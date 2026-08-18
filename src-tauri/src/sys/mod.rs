//! Platform integration. Everything here is behind a stable, OS-agnostic API so
//! the rest of the app never needs a `cfg` block.

pub mod autostart;
pub mod elevate;
pub mod procs;
pub mod sysproxy;
