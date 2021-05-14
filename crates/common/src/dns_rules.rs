use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::net::IpAddr;

#[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
pub struct Conditions {
    pub iso_code: SmolStr,
    pub max_distance_km: Option<u32>,
    // city: Option<SmolStr>,
    // region: Option<SmolStr>,
}

#[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
pub struct WeightedAddr {
    pub addr: IpAddr,
    pub weight: u8,
}

#[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
pub struct OrderedRules {
    pub conditions: Conditions,
    pub lat: Decimal,
    pub lon: Decimal,
    pub location: SmolStr,
    pub sample_rate: Decimal,
    pub addrs: Vec<WeightedAddr>,
    pub enabled: bool,
}

#[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
pub struct Rules {
    pub rules: Vec<OrderedRules>,
    pub fallback_addrs: Vec<WeightedAddr>,
}

#[derive(Clone, Serialize, Deserialize, Hash, PartialOrd, PartialEq)]
pub struct EnvironmentsRules {
    pub main: Rules,
}
