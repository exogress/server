use chrono::{DateTime, Utc};
use exogress_common::entities::{AccountUniqueId, ProjectUniqueId};
use hashbrown::HashMap;
use parking_lot::RwLock;
use std::{mem, sync::Arc};

#[derive(Debug)]
struct Counter {
    pub rules_processed: u64,
    pub requests_processed: u64,
    pub from: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AccountCounters {
    inner: Arc<RwLock<HashMap<(AccountUniqueId, ProjectUniqueId), Counter>>>,
}

#[derive(Debug)]
pub struct RecordedRulesStatistics {
    pub account_unique_id: AccountUniqueId,
    pub project_unique_id: ProjectUniqueId,
    pub rules_processed: u64,
    pub requests_processed: u64,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

impl AccountCounters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_rule(&self, account: &AccountUniqueId, project_unique_id: &ProjectUniqueId) {
        self.inner
            .write()
            .entry((account.clone(), project_unique_id.clone()))
            .or_insert_with(|| Counter {
                rules_processed: 0,
                requests_processed: 0,
                from: Utc::now(),
            })
            .rules_processed += 1;
    }

    pub fn register_request(&self, account: &AccountUniqueId, project_unique_id: &ProjectUniqueId) {
        self.inner
            .write()
            .entry((account.clone(), project_unique_id.clone()))
            .or_insert_with(|| Counter {
                rules_processed: 0,
                requests_processed: 0,
                from: Utc::now(),
            })
            .requests_processed += 1;
    }

    pub fn flush(&self) -> Option<Vec<RecordedRulesStatistics>> {
        let len = self.inner.read().len();
        if len == 0 {
            return None;
        }
        let mut result = Vec::with_capacity(len);
        let old = mem::replace(&mut *self.inner.write(), Default::default());

        for ((account_unique_id, project_unique_id), counter) in old.into_iter() {
            result.push(RecordedRulesStatistics {
                account_unique_id,
                project_unique_id,
                rules_processed: counter.rules_processed,
                requests_processed: counter.requests_processed,
                from: counter.from,
                to: Utc::now(),
            });
        }

        Some(result)
    }
}

impl Default for AccountCounters {
    fn default() -> Self {
        AccountCounters {
            inner: Arc::new(Default::default()),
        }
    }
}
