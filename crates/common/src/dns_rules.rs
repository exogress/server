use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
pub struct WeightedAddr {
    pub addr: IpAddr,
    pub weight: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
pub enum LocationStatus {
    #[serde(rename = "enabled")]
    Enabled,

    #[serde(rename = "disabled")]
    Disabled,
}

impl LocationStatus {
    pub fn is_enabled(&self) -> bool {
        if let LocationStatus::Enabled = self {
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
pub struct Location {
    pub name: SmolStr,
    pub lat: Decimal,
    pub lon: Decimal,
    pub addrs: Vec<WeightedAddr>,
    pub status: LocationStatus,
}

#[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
pub struct Main {
    // pub classes: Classes,
    pub locations: Vec<Location>,
}
