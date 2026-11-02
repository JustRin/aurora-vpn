#[cfg(target_os = "android")]
pub mod android;
pub mod balancer;
pub mod clash;
pub mod config;
pub mod log;
#[cfg(not(target_os = "android"))]
pub mod process;
pub mod rules;
pub mod ruleset;
pub mod veil;
#[cfg(not(target_os = "android"))]
pub mod xray;

#[cfg(test)]
mod tests;
