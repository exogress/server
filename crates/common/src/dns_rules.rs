use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::net::IpAddr;

// #[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
// pub struct Conditions {
//     pub iso_code: Option<SmolStr>,
//     pub max_distance_km: Option<u32>,
//     // city: Option<SmolStr>,
//     // region: Option<SmolStr>,
// }
//
#[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
pub struct WeightedAddr {
    pub addr: IpAddr,
    pub weight: u8,
}
//
// #[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
// pub struct OrderedRules {
//     pub conditions: Conditions,
//     pub sample_rate: Decimal,
//     pub enabled: bool,
//     pub location: SmolStr,
// }
//
// #[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
// pub struct Rules {
//     pub rules: Vec<OrderedRules>,
//     pub fallback_addrs: Vec<WeightedAddr>,
// }
//
// #[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
// pub struct Classes {
//     pub main: Rules,
// }

#[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
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

#[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
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
