use exogress_server_common::{
    dns_rules,
    dns_rules::{LocationStatus, WeightedAddr},
    geoip::{
        model::{model::Location, LocationAndIsp},
        GeoipReader, MaxMindDBError,
    },
};
use geo::{algorithm::geodesic_distance::GeodesicDistance, point, Point};
use hashbrown::HashSet;
use itertools::Itertools;
use smol_str::SmolStr;
use std::{convert::TryInto, net::IpAddr, sync::Arc};
use weighted_rs::{SmoothWeight, Weight};

fn to_weighted_balancer(weighted: Vec<WeightedAddr>) -> SmoothWeight<IpAddr> {
    let mut balancer = SmoothWeight::new();

    for item in weighted {
        balancer.add(item.addr, item.weight.into());
    }

    balancer
}

pub struct LocationDefinition {
    pub name: SmolStr,
    pub point: Point<f64>,
    pub addrs: SmoothWeight<IpAddr>,
    pub status: LocationStatus,
}

impl From<dns_rules::Location> for LocationDefinition {
    fn from(s: dns_rules::Location) -> Self {
        LocationDefinition {
            name: s.name,
            point: point!(x: s.lon.try_into().unwrap(), y: s.lat.try_into().unwrap()),
            addrs: to_weighted_balancer(s.addrs),
            status: s.status,
        }
    }
}

// pub struct Conditions {
//     iso_code: Option<SmolStr>,
//     max_distance_km: Option<u32>,
// }
//
// impl From<dns_rules::Conditions> for Conditions {
//     fn from(r: dns_rules::Conditions) -> Self {
//         Conditions {
//             iso_code: r.iso_code,
//             max_distance_km: r.max_distance_km,
//         }
//     }
// }
//
// pub struct Rule {
//     conditions: Conditions,
//     lat: f64,
//     lon: f64,
//     location: SmolStr,
//     sample_rate: f32,
//     addrs: SmoothWeight<IpAddr>,
//     enabled: bool,
// }

// impl From<dns_rules::OrderedRules> for Rule {
//     fn from(r: dns_rules::OrderedRules) -> Self {
//         Rule {
//             conditions: r.conditions.into(),
//             lat: f64::try_from(r.lat).unwrap(),
//             lon: f64::try_from(r.lon).unwrap(),
//             location: r.location,
//             sample_rate: f32::try_from(r.sample_rate).unwrap(),
//             addrs: to_weighted_balancer(r.addrs),
//             enabled: r.enabled,
//         }
//     }
// }

// pub struct Rules {
//     rules: Vec<Rule>,
//     fallback_addrs: SmoothWeight<IpAddr>,
// }
//
// impl From<dns_rules::Rules> for Rules {
//     fn from(r: dns_rules::Rules) -> Self {
//         Rules {
//             rules: r.rules.into_iter().map(From::from).collect(),
//             fallback_addrs: to_weighted_balancer(r.fallback_addrs),
//         }
//     }
// }

#[derive(Clone)]
pub struct BestPopFinder {
    locations: Arc<parking_lot::Mutex<Vec<LocationDefinition>>>,
    geoip: Option<GeoipReader>,
}

impl BestPopFinder {
    pub fn new(geoip: Option<GeoipReader>) -> Self {
        BestPopFinder {
            locations: Arc::new(Default::default()),
            geoip,
        }
    }

    pub fn update_rules(&self, main_rules: dns_rules::Main) {
        *self.locations.lock() = main_rules.locations.into_iter().map(From::from).collect();
    }

    pub fn find_best(
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

        let locations = &mut *self.locations.lock();
        if let Some(remote_geo_info) = maybe_remote_geo {
            if let LocationAndIsp {
                location:
                    Some(Location {
                        latitude: Some(remote_lat),
                        longitude: Some(remote_lon),
                        ..
                    }),
                ..
            } = remote_geo_info
            {
                let remote_location = point!(x: remote_lon, y: remote_lat);
                if let Some((_, loc)) = locations
                    .iter_mut()
                    .filter(|l| l.status.is_enabled())
                    .map(|location: &mut LocationDefinition| {
                        (location.point.geodesic_distance(&remote_location), location)
                    })
                    .sorted_by(|(l, _), (r, _)| l.partial_cmp(&r).unwrap())
                    .next()
                {
                    let mut res = HashSet::new();
                    for _ in 0..upto_num {
                        if let Some(addr) = loc.addrs.next() {
                            res.insert(addr);
                        }
                    }
                    return Ok(res);
                }
            }
        }

        Ok(Default::default())
    }

    //     pub fn find_gateways(
    //         &self,
    //         remote_addr: IpAddr,
    //         upto_num: usize,
    //     ) -> anyhow::Result<HashSet<IpAddr>> {
    //         let maybe_geoip = &self.geoip;
    //
    //         let maybe_remote_geo = if let Some(geoip) = maybe_geoip {
    //             match geoip.lookup::<LocationAndIsp>(remote_addr) {
    //                 Err(MaxMindDBError::AddressNotFoundError(_)) => None,
    //                 Ok(r) => Some(r),
    //                 Err(e) => return Err(e.into()),
    //             }
    //         } else {
    //             None
    //         };
    //
    //         let locked = &mut *self.rules.lock();
    //         match locked {
    //             None => Ok(Default::default()),
    //             Some(ref mut r) => {
    //                 if let Some(remote_geo_info) = maybe_remote_geo {
    //                     for rule in &mut r.rules {
    //                         if !rule.enabled {
    //                             continue;
    //                         }
    //
    //                         if rule.sample_rate > thread_rng().gen_range(0.0..1.0) {
    //                             continue;
    //                         }
    //
    //                         if let LocationAndIsp {
    //                             country:
    //                                 Some(Country {
    //                                     iso_code: Some(ref remote_iso_code),
    //                                     ..
    //                                 }),
    //                             location:
    //                                 Some(Location {
    //                                     latitude: Some(remote_lat),
    //                                     longitude: Some(remote_lon),
    //                                     ..
    //                                 }),
    //                             ..
    //                         } = remote_geo_info
    //                         {
    //                             if remote_iso_code != &rule.conditions.iso_code {
    //                                 continue;
    //                             }
    //
    //                             if let Some(max_distance_km) = rule.conditions.max_distance_km {
    //                                 let remote_location = point!(x: remote_lon, y: remote_lat);
    //                                 let rule_location = point!(x: rule.lon, y: rule.lat);
    //
    //                                 let distance_km =
    //                                     (remote_location.geodesic_distance(&rule_location) / 1000.0)
    //                                         as u32;
    //
    //                                 if distance_km > max_distance_km {
    //                                     continue;
    //                                 }
    //                             }
    //                         }
    //
    //                         // at this point the rule matches
    //
    //                         let mut res = HashSet::new();
    //
    //                         for _ in 0..upto_num {
    //                             if let Some(addr) = rule.addrs.next() {
    //                                 res.insert(addr);
    //                             }
    //                         }
    //
    //                         return Ok(res);
    //                     }
    //                 };
    //
    //                 let mut res = HashSet::new();
    //
    //                 for _ in 0..upto_num {
    //                     if let Some(addr) = r.fallback_addrs.next() {
    //                         res.insert(addr);
    //                     }
    //                 }
    //
    //                 Ok(res)
    //             }
    //         }
    //     }
}
