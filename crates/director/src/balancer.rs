use core::{cmp, fmt};
use itertools::Itertools;
use lru_time_cache::{LruCache, TimedEntry};
use rand::RngCore;
use rand_xoshiro::{rand_core::SeedableRng, Xoshiro256PlusPlus};
use std::{collections::BTreeSet, net::IpAddr, time::Duration};

pub struct GwSelectionPolicy {
    active_idx: usize,
    active_pool_len: usize,
    active: Vec<IpAddr>,
    unhealthy: LruCache<IpAddr, ()>,
    main_gateways: BTreeSet<IpAddr>,
    reserved_gateways: BTreeSet<IpAddr>,
}

impl fmt::Debug for GwSelectionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GwSelectionPolicy")
            .field("active_idx", &self.active_idx)
            .field("active_pool_len", &self.active_pool_len)
            .field("active", &self.active)
            .field("main_gateways", &self.main_gateways)
            .field("reserved_gateways", &self.reserved_gateways)
            .field(
                "unhealthy",
                &self
                    .unhealthy
                    .peek_iter()
                    .map(|(k, _)| k.clone())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Debug)]
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

#[derive(thiserror::Error, Debug)]
pub enum GwSelectionPolicyError {
    #[error("zero-sized active pool")]
    ZeroActivePool,
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
    ) -> Result<GwSelectionPolicy, GwSelectionPolicyError> {
        if max_active_gateways == 0 {
            return Err(GwSelectionPolicyError::ZeroActivePool);
        }
        let mut rng_seq = Xoshiro256PlusPlus::seed_from_u64(seed);
        let main_gateways_num = cmp::min(max_active_gateways as usize, self.num_of_gateways);
        let reserved_gateways_num = cmp::min(
            max_reserved_gateways as usize,
            self.num_of_gateways - main_gateways_num,
        );

        let shards_len = self.shards.len();

        let mut main_gateways = BTreeSet::new();
        let mut reserved_gateways = BTreeSet::new();

        if main_gateways_num > 0 {
            loop {
                let rnd = rng_seq.next_u32() as usize;
                let idx = rnd % shards_len;
                main_gateways.insert(self.shards[idx]);
                if main_gateways.len() == main_gateways_num {
                    break;
                }
            }
        }

        if reserved_gateways_num > 0 {
            loop {
                let rnd = rng_seq.next_u32() as usize;
                let idx = rnd % shards_len;
                let addr = self.shards[idx];
                if main_gateways.contains(&addr) {
                    continue;
                }
                reserved_gateways.insert(addr);
                if reserved_gateways.len() == reserved_gateways_num {
                    break;
                }
            }
        }

        let mut policy = GwSelectionPolicy {
            active_idx: 0,
            active: Default::default(),
            active_pool_len: main_gateways_num,
            unhealthy: LruCache::with_expiry_duration(unhealthy_ttl),
            main_gateways,
            reserved_gateways,
        };

        policy.gen_balancer();

        Ok(policy)
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
        let mut new_active = self.main_gateways.clone();
        for (unhealthy, _) in self.unhealthy.iter() {
            new_active.remove(unhealthy);
        }
        let mut reserved_iter = self.reserved_gateways.iter();
        while new_active.len() < self.active_pool_len {
            if let Some(reserved) = reserved_iter.next() {
                if !self.unhealthy.contains_key(reserved) {
                    new_active.insert(reserved.clone());
                }
            } else {
                break;
            }
        }
        self.active = new_active.into_iter().collect();
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
    use hashbrown::HashSet;
    use quickcheck::TestResult;

    #[quickcheck]
    fn generation_works(
        weighted: Vec<(IpAddr, u8)>,
        num_shards: u16,
        seed: u64,
        max_main_gateways: u8,
        max_reserved_gateways: u8,
    ) -> TestResult {
        let max_main_gateways = max_main_gateways as u16;
        let max_reserved_gateways = max_reserved_gateways as u16;
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

        let policy_result = sharded.policy(
            seed,
            max_main_gateways.into(),
            max_reserved_gateways.into(),
            Duration::from_secs(10),
            Duration::from_secs(10),
        );

        if policy_result.is_err() && max_main_gateways == 0 {
            return TestResult::passed();
        }

        let mut policy = policy_result.unwrap();

        let main_gateways_set = policy.main_gateways.clone();
        let reserved_gateways_set = policy.reserved_gateways.clone();

        assert_eq!(main_gateways_set.len(), policy.active_pool_len);
        assert!(main_gateways_set.len() <= max_main_gateways as usize);
        assert!(main_gateways_set.len() <= max_main_gateways as usize);
        assert!(reserved_gateways_set.len() <= max_reserved_gateways as usize);
        assert!(main_gateways_set.len() <= num_gateways);
        assert!(reserved_gateways_set.len() <= num_gateways);
        assert!(reserved_gateways_set.is_disjoint(&main_gateways_set));

        if policy.is_empty() && max_main_gateways == 0 && max_reserved_gateways == 0 {
            return TestResult::passed();
        }

        let unhealthy = *main_gateways_set.iter().next().unwrap();

        policy.mark_unhealthy(&unhealthy);
        let num_loops = policy.active_pool_len * 6;

        for _ in 0..num_loops {
            let next_gw = policy.next();
            if (max_main_gateways + max_reserved_gateways == 1 || num_gateways == 1)
                && next_gw.is_none()
            {
                return TestResult::passed();
            }
            let selected = next_gw.unwrap();
            if selected == unhealthy {
                return TestResult::error("unhealthy gateway returned");
            }
        }
        policy.mark_healthy(&unhealthy);
        if (0..num_loops)
            .find(|_| {
                let selected = policy.next().unwrap();
                selected == unhealthy
            })
            .is_none()
        {
            return TestResult::error("gw which become healthy didn't haven't ever returned");
        }

        TestResult::passed()
    }

    #[test]
    fn simple_check_two_active_gateways() {
        let gws = vec![
            ("127.0.0.1".parse().unwrap(), 100),
            ("127.0.0.2".parse().unwrap(), 100),
        ];
        let sharded = ShardedGateways::new(gws.clone(), 4096).unwrap();

        let mut policy_result = sharded.policy(1, 2, 2, Duration::from_secs(60)).unwrap();

        let first = policy_result.next().unwrap();
        let second = policy_result.next().unwrap();

        let expected: HashSet<_> = gws.iter().map(|(addr, _)| addr.clone()).collect();
        let selected: HashSet<_> = [first, second].iter().copied().collect();

        assert_eq!(expected, selected);
    }
}
