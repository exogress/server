use exogress_server_common::{
    dns_rules,
    dns_rules::WeightedAddr,
    geoip::{
        model::{
            model::{Country, Location},
            LocationAndIsp,
        },
        GeoipReader, MaxMindDBError,
    },
};
use geo::{algorithm::geodesic_distance::GeodesicDistance, point};
use hashbrown::HashSet;
use rand::{thread_rng, Rng};
use smol_str::SmolStr;
use std::{convert::TryFrom, net::IpAddr, sync::Arc};
use weighted_rs::{SmoothWeight, Weight};

fn to_weighted_balancer(weighted: Vec<WeightedAddr>) -> SmoothWeight<IpAddr> {
    let mut balancer = SmoothWeight::new();

    for item in weighted {
        balancer.add(item.addr, item.weight.into());
    }

    balancer
}

pub struct Conditions {
    iso_code: SmolStr,
    max_distance_km: Option<u32>,
}

impl From<dns_rules::Conditions> for Conditions {
    fn from(r: dns_rules::Conditions) -> Self {
        Conditions {
            iso_code: r.iso_code,
            max_distance_km: r.max_distance_km,
        }
    }
}

pub struct Rule {
    conditions: Conditions,
    lat: f64,
    lon: f64,
    location: SmolStr,
    sample_rate: f32,
    addrs: SmoothWeight<IpAddr>,
    enabled: bool,
}

impl From<dns_rules::OrderedRules> for Rule {
    fn from(r: dns_rules::OrderedRules) -> Self {
        Rule {
            conditions: r.conditions.into(),
            lat: f64::try_from(r.lat).unwrap(),
            lon: f64::try_from(r.lon).unwrap(),
            location: r.location,
            sample_rate: f32::try_from(r.sample_rate).unwrap(),
            addrs: to_weighted_balancer(r.addrs),
            enabled: r.enabled,
        }
    }
}

pub struct Rules {
    rules: Vec<Rule>,
    fallback_addrs: SmoothWeight<IpAddr>,
}

impl From<dns_rules::Rules> for Rules {
    fn from(r: dns_rules::Rules) -> Self {
        Rules {
            rules: r.rules.into_iter().map(From::from).collect(),
            fallback_addrs: to_weighted_balancer(r.fallback_addrs),
        }
    }
}

#[derive(Clone)]
pub struct RulesProcessor {
    rules: Arc<parking_lot::Mutex<Option<Rules>>>,
    geoip: Option<GeoipReader>,
}

impl RulesProcessor {
    pub fn new(geoip: Option<GeoipReader>) -> Self {
        RulesProcessor {
            rules: Arc::new(Default::default()),
            geoip,
        }
    }

    pub fn update_rules(&self, rules: dns_rules::Rules) {
        *self.rules.lock() = Some(rules.into());
    }

    pub fn find_gateways(
        &self,
        remote_addr: IpAddr,
        upto_num: usize,
    ) -> anyhow::Result<HashSet<IpAddr>> {
        let maybe_geoip = &self.geoip;

        let maybe_remote_geo = if let Some(geoip) = maybe_geoip {
            match geoip.lookup::<LocationAndIsp>(remote_addr) {
                Err(MaxMindDBError::AddressNotFoundError(_)) => None,
                Ok(r) => Some(r),
                Err(e) => return Err(e.into()),
            }
        } else {
            None
        };

        let locked = &mut *self.rules.lock();
        match locked {
            None => Ok(Default::default()),
            Some(ref mut r) => {
                if let Some(remote_geo_info) = maybe_remote_geo {
                    for rule in &mut r.rules {
                        if !rule.enabled {
                            continue;
                        }

                        if rule.sample_rate > thread_rng().gen_range(0.0..1.0) {
                            continue;
                        }

                        if let LocationAndIsp {
                            country:
                                Some(Country {
                                    iso_code: Some(ref remote_iso_code),
                                    ..
                                }),
                            location:
                                Some(Location {
                                    latitude: Some(remote_lat),
                                    longitude: Some(remote_lon),
                                    ..
                                }),
                            ..
                        } = remote_geo_info
                        {
                            if remote_iso_code != &rule.conditions.iso_code {
                                continue;
                            }

                            if let Some(max_distance_km) = rule.conditions.max_distance_km {
                                let remote_location = point!(x: remote_lon, y: remote_lat);
                                let rule_location = point!(x: rule.lon, y: rule.lat);

                                let distance_km =
                                    (remote_location.geodesic_distance(&rule_location) / 1000.0)
                                        as u32;

                                if distance_km > max_distance_km {
                                    continue;
                                }
                            }
                        }

                        // at this point the rule matches

                        let mut res = HashSet::new();

                        for _ in 0..upto_num {
                            if let Some(addr) = rule.addrs.next() {
                                res.insert(addr);
                            }
                        }

                        return Ok(res);
                    }
                };

                let mut res = HashSet::new();

                for _ in 0..upto_num {
                    if let Some(addr) = r.fallback_addrs.next() {
                        res.insert(addr);
                    }
                }

                Ok(res)
            }
        }
    }
}
