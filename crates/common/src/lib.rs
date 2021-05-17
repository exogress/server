#[macro_use]
extern crate serde_with;

pub mod assistant;
pub mod clap;
#[cfg(feature = "crypto")]
pub mod crypto;
pub mod director;
pub mod dns_rules;
#[cfg(feature = "geoip")]
pub mod geoip;
pub mod kafka;
pub mod logging;
pub mod presence;
pub mod prometheus;
pub mod statistics;
pub mod transformer;

pub type ContentHash = sha2::Sha256;
