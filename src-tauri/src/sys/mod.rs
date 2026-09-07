//! Platform integration. Everything here is behind a stable, OS-agnostic API so
//! the rest of the app never needs a `cfg` block.

pub mod autostart;
pub mod elevate;
pub mod procs;
/// Reading the desktop is a desktop-only idea; a phone scans with its camera.
#[cfg(desktop)]
pub mod screen;
pub mod sysproxy;
