use core::cmp;
use itertools::Itertools;
use lru_time_cache::{LruCache, TimedEntry};
use rand::RngCore;
use rand_xoshiro::rand_core::SeedableRng;
use rand_xoshiro::Xoshiro256PlusPlus;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

pub struct GwSelectionPolicy {
    active_idx: usize,
    main_pool_len: usize,
    active: Vec<IpAddr>,
    unhealthy: LruCache<IpAddr, ()>,
    main_gateways: BTreeSet<IpAddr>,
    reserved_gateways: BTreeSet<IpAddr>,
}

pub struct ShardedGateways {
    shards: Vec<IpAddr>,
    num_of_gateways: usize,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("empty list of gateways")]
    EmptyGateways,

    #[error("sum of weights is bigger than number of shards")]
    WeightsOverflow,

    #[error("duplicated ip addresses detected")]
    DuplicatesDetected,

    #[error("zero weight detected")]
    ZeroWeightFound,
}

impl ShardedGateways {
    pub fn new(weighted: Vec<(IpAddr, u8)>, num_shards: u16) -> Result<Self, Error> {
        if weighted.is_empty() {
            return Err(Error::EmptyGateways);
        }

        if weighted.len() != weighted.iter().map(|(addr, _)| *addr).unique().count() {
            return Err(Error::DuplicatesDetected);
        }

        if weighted.iter().find(|(_, weight)| *weight == 0).is_some() {
            return Err(Error::ZeroWeightFound);
        }

        let num_of_gateways = weighted.len();

        let sum_weights: u32 = weighted.iter().map(|(_, weight)| *weight as u32).sum();
        let num_shards = num_shards as u32;
        if sum_weights > num_shards {
            return Err(Error::WeightsOverflow);
        }

        let multiplication_coefficient = (num_shards as f32 / sum_weights as f32).floor() as u32;
        let pre_sum: u32 = weighted
            .iter()
            .map(|(_, weight)| (*weight as u32) * multiplication_coefficient)
            .sum();
        let mut per_slot_lengths = Vec::new();
        for (_item, weight) in &weighted {
            per_slot_lengths.push((*weight as u32) * multiplication_coefficient);
        }
        let mut rest_bytes = num_shards - pre_sum;
        while rest_bytes > 0 {
            for length in per_slot_lengths.iter_mut() {
                if rest_bytes == 0 {
                    break;
                }
                rest_bytes -= 1;
                *length += 1;
            }
        }

        let mut res = Vec::new();

        for (idx, num) in per_slot_lengths.into_iter().enumerate() {
            for _ in 0..num {
                res.push(weighted[idx].0);
            }
        }

        assert_eq!(res.len() as u32, num_shards);

        Ok(Self {
            shards: res,
            num_of_gateways,
        })
    }

    pub fn policy(
        &self,
        seed: u64,
        max_active_gateways: u16,
        max_reserved_gateways: u16,
        unhealthy_ttl: Duration,
    ) -> GwSelectionPolicy {
        let mut rng_seq = Xoshiro256PlusPlus::seed_from_u64(seed);
        let active_gateways_num = cmp::min(max_active_gateways as usize, self.num_of_gateways);
        let reserved_gateways_num = cmp::min(
            max_reserved_gateways as usize,
            self.num_of_gateways - active_gateways_num,
        );

        let shards_len = self.shards.len();

        let mut active_gateways = BTreeSet::new();
        let mut reserved_gateways = BTreeSet::new();

        if active_gateways_num > 0 {
            loop {
                let rnd = rng_seq.next_u32() as usize;
                let idx = rnd % shards_len;
                active_gateways.insert(self.shards[idx]);
                if active_gateways.len() == active_gateways_num {
                    break;
                }
            }
        }

        if reserved_gateways_num > 0 {
            loop {
                let rnd = rng_seq.next_u32() as usize;
                let idx = rnd % shards_len;
                let addr = self.shards[idx];
                if active_gateways.contains(&addr) {
                    continue;
                }
                reserved_gateways.insert(addr);
                if reserved_gateways.len() == reserved_gateways_num {
                    break;
                }
            }
        }

        GwSelectionPolicy {
            active_idx: 0,
            main_pool_len: active_gateways_num,
            active: vec![],
            unhealthy: LruCache::with_expiry_duration(unhealthy_ttl),
            main_gateways: active_gateways,
            reserved_gateways,
        }
    }
}

impl GwSelectionPolicy {
    pub fn next(&mut self) -> Option<IpAddr> {
        let is_unhealthy_expired = self
            .unhealthy
            .notify_iter()
            .find(|entry| match entry {
                TimedEntry::Valid(_, _) => false,
                TimedEntry::Expired(_, _) => true,
            })
            .is_some();

        if is_unhealthy_expired {
            self.gen_balancer();
        }

        if self.active.is_empty() {
            return None;
        }

        self.active_idx = (self.active_idx + 1) % self.active.len();

        self.active.get(self.active_idx).cloned()
    }

    fn is_ip_addr_exist(&self, addr: &IpAddr) -> bool {
        self.main_gateways.contains(addr) || self.reserved_gateways.contains(addr)
    }

    fn gen_balancer(&mut self) {
        let mut main = self.main_gateways.clone();
        for (unhealthy, _) in self.unhealthy.iter() {
            main.remove(unhealthy);
        }
        let mut reserved_iter = self.reserved_gateways.iter();
        while main.len() < self.main_pool_len {
            if let Some(reserved) = reserved_iter.next() {
                if !self.unhealthy.contains_key(reserved) {
                    main.insert(reserved.clone());
                }
            } else {
                break;
            }
        }
    }

    pub fn mark_unhealthy(&mut self, addr: &IpAddr) {
        if !self.is_ip_addr_exist(addr) {
            return;
        }

        self.unhealthy.insert(addr.clone(), ());
        self.gen_balancer();
    }

    #[cfg(test)]
    pub fn mark_healthy(&mut self, addr: &IpAddr) {
        if !self.is_ip_addr_exist(addr) {
            return;
        }

        self.unhealthy.remove(addr);
        self.gen_balancer();
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use quickcheck::TestResult;

    #[quickcheck]
    fn generation_works(
        weighted: Vec<(IpAddr, u8)>,
        num_shards: u16,
        seed: u64,
        max_active_gateways: u8,
        max_reserved_gateways: u8,
    ) -> TestResult {
        if weighted.is_empty()
            || weighted
                .iter()
                .map(|(_, weight)| *weight as u32)
                .sum::<u32>()
                > num_shards as u32
            || weighted.iter().find(|(_, weight)| *weight == 0).is_some()
            || weighted.len() != weighted.iter().map(|(addr, _)| *addr).unique().count()
        {
            return TestResult::from_bool(ShardedGateways::new(weighted, num_shards).is_err());
        }

        let num_gateways = weighted.len();

        let sharded = ShardedGateways::new(weighted, num_shards).unwrap();

        let mut policy = sharded.policy(
            seed,
            max_active_gateways.into(),
            max_reserved_gateways.into(),
            Duration::from_secs(60),
        );

        let main_gateways_set = policy.main_gateways.clone();
        let reserved_gateways_set = policy.reserved_gateways.clone();

        assert_eq!(main_gateways_set.len(), policy.main_pool_len);
        assert!(main_gateways_set.len() <= max_active_gateways as usize);
        assert!(main_gateways_set.len() <= max_active_gateways as usize);
        assert!(reserved_gateways_set.len() <= max_reserved_gateways as usize);
        assert!(main_gateways_set.len() <= num_gateways);
        assert!(reserved_gateways_set.len() <= num_gateways);
        assert!(reserved_gateways_set.is_disjoint(&main_gateways_set));

        if policy.is_empty() {
            return TestResult::passed();
        }

        let unhealthy = *main_gateways_set.iter().next().unwrap();

        policy.mark_unhealthy(&unhealthy);
        let num_loops = policy.main_pool_len * 6;
        for _ in 0..num_loops {
            let selected = policy.next().unwrap();
            assert_ne!(selected, unhealthy)
        }
        policy.mark_healthy(&unhealthy);
        assert!((0..num_loops)
            .find(|_| {
                let selected = policy.next().unwrap();
                selected == unhealthy
            })
            .is_some());

        TestResult::passed()
    }
}
