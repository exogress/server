use exogress_server_common::{
    dns_rules,
    dns_rules::WeightedAddr,
    geoip::{
        model::{model::Location, LocationAndIsp},
        GeoipReader, MaxMindDBError,
    },
};
use geo::{algorithm::geodesic_distance::GeodesicDistance, point, Point};
use hashbrown::HashSet;
use itertools::Itertools;
use rand::prelude::*;
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
}

impl core::fmt::Debug for LocationDefinition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocationDefinition")
            .field("name", &self.name)
            .field("point", &self.point)
            .finish()
    }
}

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
        let new_rules = main_rules
            .locations
            .into_iter()
            .filter_map(|l| {
                if l.addrs.is_empty() || !l.status.is_enabled() {
                    None
                } else {
                    Some(LocationDefinition {
                        name: l.name,
                        point: point!(x: l.lon.try_into().unwrap(), y: l.lat.try_into().unwrap()),
                        addrs: to_weighted_balancer(l.addrs),
                    })
                }
            })
            .collect();

        *self.locations.lock() = new_rules;
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
        let mut res = None;

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
                    .map(|location: &mut LocationDefinition| {
                        (location.point.geodesic_distance(&remote_location), location)
                    })
                    .sorted_by(|(l, _), (r, _)| l.partial_cmp(&r).unwrap())
                    .next()
                {
                    res = Some(loc);
                }
            }
        };

        if res.is_none() {
            res = locations.iter_mut().choose(&mut thread_rng());
        }

        if let Some(res) = res {
            let mut out = HashSet::new();
            for _ in 0..upto_num {
                if let Some(addr) = res.addrs.next() {
                    out.insert(addr);
                }
            }
            return Ok(out);
        }

        Ok(Default::default())
    }
}
