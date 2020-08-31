use chrono::{DateTime, Utc};
use exogress_entities::RateLimiterName;
use governor::clock::MonotonicClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::Jitter;
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::delay_for;

#[derive(Debug, Clone)]
pub enum RateLimiterResponse {
    DelayedBy(SmallVec<[(RateLimiterName, Duration); 4]>),
    LimitedError {
        rate_limiter_name: RateLimiterName,
        not_until: DateTime<Utc>,
    },
    Passthrough,
}

impl RateLimiterResponse {
    #[cfg(test)]
    fn applied_limits(&self) -> Option<&SmallVec<[(RateLimiterName, Duration); 4]>> {
        if let RateLimiterResponse::DelayedBy(limits) = self {
            Some(limits)
        } else {
            None
        }
    }

    fn add_limiter_wait(&mut self, name: RateLimiterName, dur: Duration) {
        match self {
            RateLimiterResponse::DelayedBy(limits) => {
                limits.push((name, dur));
            }
            RateLimiterResponse::LimitedError {
                rate_limiter_name: _,
                not_until: _,
            } => {
                unreachable!("should never happen");
            }
            RateLimiterResponse::Passthrough => {
                *self = RateLimiterResponse::DelayedBy(smallvec::smallvec![(name, dur)]);
            }
        }
    }

    fn increase_last(&mut self, dur: Duration) {
        match self {
            RateLimiterResponse::DelayedBy(limits) => {
                limits.iter_mut().rev().next().as_mut().expect("FIXME").1 += dur;
            }
            _ => {
                unreachable!("should never happen");
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RateLimiterKind {
    /// Return Failure
    FailResponse,

    /// Wait until request is allowed to serve
    Wait,
}

#[derive(Debug)]
pub struct RateLimiter {
    inner: governor::RateLimiter<NotKeyed, InMemoryState, MonotonicClock>,
    name: RateLimiterName,
    kind: RateLimiterKind,
}

impl RateLimiter {
    pub fn new(name: RateLimiterName, kind: RateLimiterKind, quota: governor::Quota) -> Self {
        RateLimiter {
            inner: governor::RateLimiter::direct_with_clock(quota, &MonotonicClock::default()),
            name,
            kind,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimiters {
    inner: Arc<SmallVec<[Mutex<RateLimiter>; 4]>>,
}

impl RateLimiters {
    pub fn new(v: impl IntoIterator<Item = RateLimiter>) -> Self {
        RateLimiters {
            inner: Arc::new(v.into_iter().map(Mutex::new).collect()),
        }
    }
}

const JITTER: Duration = Duration::from_millis(100);

impl RateLimiters {
    /// Process a single unit of work
    pub async fn process(&self) -> RateLimiterResponse {
        let mut resp = RateLimiterResponse::Passthrough;

        for rate_limiter in self.inner.iter() {
            let kind = rate_limiter.lock().kind;
            match kind {
                RateLimiterKind::FailResponse => {
                    let check_res = rate_limiter.lock().inner.check().map_err(|negative| {
                        chrono::Duration::from_std(
                            Jitter::up_to(JITTER) + negative.wait_time_from(Instant::now()),
                        )
                        .expect("duration overflow!")
                    });
                    match check_res {
                        Ok(_) => {
                            //all ok, go ahead to the next rate limiter
                        }
                        Err(wait_at_least) => {
                            return RateLimiterResponse::LimitedError {
                                rate_limiter_name: rate_limiter.lock().name.clone(),
                                not_until: Utc::now() + wait_at_least,
                            };
                        }
                    }
                }
                RateLimiterKind::Wait => {
                    let mut already_added = false;
                    loop {
                        let with_not_until =
                            rate_limiter.lock().inner.check().map_err(|negative| {
                                Jitter::up_to(JITTER) + negative.wait_time_from(Instant::now())
                            });
                        match with_not_until {
                            Ok(_) => {
                                // all ok, go ahead to next rate limiter
                                // exit from inner retrying cycle
                                break;
                            }
                            Err(not_until) => {
                                if !already_added {
                                    let limiter = rate_limiter.lock();
                                    resp.add_limiter_wait(limiter.name.clone(), not_until);
                                    already_added = true;
                                } else {
                                    resp.increase_last(not_until);
                                }
                                delay_for(not_until).await;
                            }
                        }
                    }
                }
            }
        }

        resp
    }
}

impl Default for RateLimiters {
    fn default() -> Self {
        RateLimiters {
            inner: Arc::new(Default::default()),
        }
    }
}

// pub struct HitsCounter {
//     inner: Arc<DashMap<Endpoint, u64, ahash::RandomState>>,
// }
//
// impl HitsCounter {
//     pub fn new() -> Self {
//         HitsCounter {
//             inner: Arc::new(Default::default()),
//         }
//     }
//
//     pub fn hit(&self, endpoint: Endpoint) {
//         *self.inner.entry(endpoint).or_default() += 1;
//     }
// }

#[cfg(test)]
mod test {
    use super::*;
    use core::num::NonZeroU32;

    #[tokio::test]
    async fn test_default() {
        let rate_limiters = RateLimiters::default();

        let res = rate_limiters.process().await;
        assert!(matches!(res, RateLimiterResponse::Passthrough));
    }

    #[tokio::test]
    async fn test_failure() {
        let simple_limiter: RateLimiterName = "simple".parse().unwrap();
        let rate_limiters = RateLimiters::new(vec![RateLimiter::new(
            simple_limiter.clone(),
            RateLimiterKind::FailResponse,
            governor::Quota::with_period(Duration::from_secs(1))
                .unwrap()
                .allow_burst(NonZeroU32::new(1).unwrap()),
        )]);

        let res = rate_limiters.process().await;
        assert!(matches!(res, RateLimiterResponse::Passthrough));

        let res = rate_limiters.process().await;
        assert!(matches!(
            res,
            RateLimiterResponse::LimitedError { .. }
        ));
    }

    #[tokio::test]
    async fn test_await() {
        let first_limiter: RateLimiterName = "first".parse().unwrap();
        let second_limiter: RateLimiterName = "second".parse().unwrap();
        let third_limiter: RateLimiterName = "third".parse().unwrap();
        let rate_limiters = RateLimiters::new(vec![
            RateLimiter::new(
                first_limiter.clone(),
                RateLimiterKind::Wait,
                governor::Quota::with_period(Duration::from_millis(5))
                    .unwrap()
                    .allow_burst(NonZeroU32::new(60).unwrap()),
            ),
            RateLimiter::new(
                second_limiter.clone(),
                RateLimiterKind::Wait,
                governor::Quota::with_period(Duration::from_secs(1))
                    .unwrap()
                    .allow_burst(NonZeroU32::new(1).unwrap()),
            ),
            RateLimiter::new(
                third_limiter.clone(),
                RateLimiterKind::Wait,
                governor::Quota::with_period(Duration::from_secs(2))
                    .unwrap()
                    .allow_burst(NonZeroU32::new(1).unwrap()),
            ),
        ]);

        let res = rate_limiters.process().await;
        assert!(matches!(res, RateLimiterResponse::Passthrough));

        let started_at = Instant::now();
        let res = rate_limiters.process().await;
        assert!(matches!(res, RateLimiterResponse::DelayedBy(_)));
        assert_eq!(
            res.applied_limits()
                .unwrap()
                .iter()
                .map(|r| r.0.clone())
                .collect::<Vec<_>>(),
            vec![second_limiter.clone(), third_limiter.clone()]
        );
        assert!(Instant::now() - started_at >= Duration::from_secs(2));

        let started_at = Instant::now();
        let res = rate_limiters.process().await;
        assert!(matches!(res.clone(), RateLimiterResponse::DelayedBy(_)));

        assert_eq!(
            res.applied_limits()
                .unwrap()
                .iter()
                .map(|r| r.0.clone())
                .collect::<Vec<_>>(),
            vec![third_limiter]
        );
        assert!(Instant::now() - started_at >= Duration::from_secs(1));
    }
}
