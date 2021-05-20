// Taken from https://docs.rs/trust-dns-server/0.20.0/src/trust_dns_server/store/in_memory/authority.rs.html#37-49
// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

#![allow(unused)]

use std::{borrow::Borrow, collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use futures::future::{self, TryFutureExt};

use trust_dns_server::client::{
    op::{LowerQuery, ResponseCode},
    rr::{
        dnssec::{DnsSecResult, Signer, SupportedAlgorithms},
        rdata::{key::KEY, DNSSECRecordType, SOA},
        DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey,
    },
};

use crate::{authority::Authority, int_api_client::IntApiClient};
use anyhow::Error;
use exogress_server_common::geoip::{model::LocationAndIsp, GeoipReader};
use futures::{channel::oneshot, FutureExt};
use std::net::IpAddr;
use tokio::time::{sleep, Duration};
use trust_dns_server::{
    authority::{
        AnyRecords, AuthLookup, LookupError, LookupRecords, LookupResult, MessageRequest,
        UpdateResult, ZoneType,
    },
    client::proto::rr::rdata::CAA,
    proto::rr::rdata::TXT,
};

/// InMemoryAuthorityWithConstCname is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a Secondary, or a cached zone.
#[derive(Clone)]
pub struct ShortZoneAuthority {
    origin: LowerName,
    class: DNSClass,
    records: BTreeMap<RrKey, Arc<RecordSet>>,
    cname_record: Name,

    // Private key mapped to the Record of the DNSKey
    //  TODO: these private_keys should be stored securely. Ideally, we have keys only stored per
    //   server instance, but that requires requesting updates from the parent zone, which may or
    //   may not support dynamic updates to register the new key... Trust-DNS will provide support
    //   for this, in some form, perhaps alternate root zones...
    // secure_keys: Vec<Signer>,
    int_api_client: IntApiClient,

    acme_resp_cache:
        Arc<tokio::sync::Mutex<lru_time_cache::LruCache<(String, String), Option<String>>>>,
}

impl ShortZoneAuthority {
    /// Creates a new Authority.
    ///
    /// # Arguments
    ///
    /// * `origin` - The zone `Name` being created, this should match that of the `RecordType::SOA`
    ///              record.
    /// * `records` - The map of the initial set of records in the zone.
    /// * `zone_type` - The type of zone, i.e. is this authoritative?
    /// * `allow_update` - If true, then this zone accepts dynamic updates.
    /// * `is_dnssec_enabled` - If true, then the zone will sign the zone with all registered keys,
    ///                         (see `add_zone_signing_key()`)
    ///
    /// # Return value
    ///
    /// The new `Authority`.
    pub fn new(
        origin: Name,
        records: BTreeMap<RrKey, RecordSet>,
        cname_record: Name,
        int_api_client: IntApiClient,
    ) -> Result<Self, String> {
        let mut this = Self::empty(origin.clone(), cname_record, int_api_client);

        // SOA must be present
        let serial = records
            .iter()
            .find(|(key, _)| key.record_type == RecordType::SOA)
            .and_then(|(_, rrset)| rrset.records_without_rrsigs().next())
            .and_then(|record| record.rdata().as_soa())
            .map(SOA::serial)
            .ok_or_else(|| format!("SOA record must be present: {}", origin))?;

        let iter = records.into_iter().map(|(_key, record)| record);

        // add soa to the records
        for rrset in iter {
            let name = rrset.name().clone();
            let rr_type = rrset.record_type();

            for record in rrset.records_without_rrsigs() {
                if !this.upsert(record.clone(), serial) {
                    return Err(format!(
                        "Failed to insert {} {} to zone: {}",
                        name, rr_type, origin
                    ));
                };
            }
        }

        Ok(this)
    }

    /// Creates an empty Authority
    ///
    /// # Warning
    ///
    /// This is an invalid zone, SOA must be added
    pub fn empty(origin: Name, cname_record: Name, int_api_client: IntApiClient) -> Self {
        Self {
            origin: LowerName::new(&origin),
            class: DNSClass::IN,
            records: BTreeMap::new(),
            cname_record,
            // secure_keys: Vec::new(),
            int_api_client,
            acme_resp_cache: Arc::new(tokio::sync::Mutex::new(
                lru_time_cache::LruCache::with_expiry_duration(Duration::from_secs(30)),
            )),
        }
    }

    /// Clears all records (including SOA, etc)
    pub fn clear(&mut self) {
        self.records.clear()
    }

    /// Get the DNSClass of the zone
    pub fn class(&self) -> DNSClass {
        self.class
    }

    // /// Retrieve the Signer, which contains the private keys, for this zone
    // pub fn secure_keys(&self) -> &[Signer] {
    //     &self.secure_keys
    // }

    /// Get all the records
    pub fn records(&self) -> &BTreeMap<RrKey, Arc<RecordSet>> {
        &self.records
    }

    /// Get a mutable reference to the records
    pub fn records_mut(&mut self) -> &mut BTreeMap<RrKey, Arc<RecordSet>> {
        &mut self.records
    }

    fn inner_soa(&self) -> Option<&SOA> {
        let rr_key = RrKey::new(self.origin.clone(), RecordType::SOA);

        self.records
            .get(&rr_key)
            .and_then(|rrset| rrset.records_without_rrsigs().next())
            .and_then(|record| record.rdata().as_soa())
    }

    /// Returns the minimum ttl (as used in the SOA record)
    pub fn minimum_ttl(&self) -> u32 {
        let soa = self.inner_soa();

        let soa = match soa {
            Some(soa) => soa,
            None => {
                error!("could not lookup SOA for authority: {}", self.origin);
                return 0;
            }
        };

        soa.minimum()
    }

    /// get the current serial number for the zone.
    pub fn serial(&self) -> u32 {
        let soa = self.inner_soa();

        let soa = match soa {
            Some(soa) => soa,
            None => {
                error!("could not lookup SOA for authority: {}", self.origin);
                return 0;
            }
        };

        soa.serial()
    }

    async fn inner_lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        and_rrsigs: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> Option<Arc<RecordSet>> {
        if name.to_string().starts_with("_acme-challenge.") {
            let (result_tx, result_rx) = oneshot::channel();

            let int_api_client = self.int_api_client.clone();
            let mut acme_resp_cache = self.acme_resp_cache.clone();

            let record_type_string = record_type.to_string();
            let record_base_name = name.base_name().to_string();

            tokio::spawn(async move {
                let result = tokio::time::timeout(Duration::from_millis(500), async move {
                    let res = acme_resp_cache
                        .lock()
                        .await
                        .get_mut(&(record_type_string.clone(), record_base_name.clone()))
                        .cloned();
                    if let Some(cached) = res {
                        result_tx.send(cached).unwrap();
                    } else {
                        loop {
                            match int_api_client
                                .acme_dns_challenge_verification(
                                    "_acme-challenge",
                                    record_type_string.as_str(),
                                    record_base_name.as_str(),
                                )
                                .await
                            {
                                Ok(maybe_res) => {
                                    info!("acme resp retrieved from cloud: {:?}", maybe_res);
                                    acme_resp_cache.lock().await.insert(
                                        (record_type_string, record_base_name),
                                        maybe_res.clone(),
                                    );
                                    result_tx.send(maybe_res).unwrap();
                                    break;
                                }
                                Err(err) => {
                                    error!("acme resp error: {:?}", err);
                                    sleep(Duration::from_millis(10)).await;
                                }
                            }
                        }
                    }
                })
                .await;

                info!("Result of ACME request loop: {:?}", result);
            });

            match result_rx.await {
                Ok(Some(res)) => {
                    // TODO: properly track erroneous DNS requests
                    let mut rs = RecordSet::new(&name.clone().into(), record_type, 1);

                    let rdata: Option<_> = (|| match record_type {
                        RecordType::CNAME => Some(RData::CNAME(res.parse().ok()?)),
                        RecordType::TXT => Some(RData::TXT(TXT::new(vec![res]))),
                        _ => None,
                    })();

                    let rdata = match rdata {
                        Some(rdata) => rdata,
                        None => {
                            crate::statistics::NUM_DNS_REQUESTS
                                .with_label_values(&["0"])
                                .inc();
                            return None;
                        }
                    };

                    rs.insert(
                        Record::from_rdata(name.clone().into(), self.minimum_ttl(), rdata),
                        1,
                    );

                    crate::statistics::NUM_DNS_REQUESTS
                        .with_label_values(&["1"])
                        .inc();

                    return Some(Arc::new(rs));
                }
                Ok(None) => {
                    return None;
                }
                Err(_e) => {
                    crate::statistics::NUM_DNS_REQUESTS
                        .with_label_values(&["0"])
                        .inc();

                    info!("Error resolving {} addr", name);

                    return None;
                }
            }
        }

        match record_type {
            RecordType::CNAME | RecordType::A | RecordType::AAAA => {
                let mut cname_record_set =
                    RecordSet::new(&name.clone().into(), RecordType::CNAME, 1);

                cname_record_set.insert(
                    Record::from_rdata(
                        name.clone().into(),
                        self.minimum_ttl(),
                        RData::CNAME(self.cname_record.clone()),
                    ),
                    1,
                );

                crate::statistics::NUM_DNS_REQUESTS
                    .with_label_values(&["1"])
                    .inc();

                return Some(Arc::new(cname_record_set));
            }
            RecordType::CAA => {
                //
                let mut caa_record = RecordSet::new(&name.clone().into(), RecordType::CAA, 1);

                caa_record.insert(
                    Record::from_rdata(
                        name.clone().into(),
                        self.minimum_ttl(),
                        RData::CAA(CAA::new_issue(
                            true,
                            Some("letsencrypt.org".parse().unwrap()),
                            Default::default(),
                        )),
                    ),
                    1,
                );

                crate::statistics::NUM_DNS_REQUESTS
                    .with_label_values(&["1"])
                    .inc();

                return Some(Arc::new(caa_record));
            }
            _ => {}
        }

        // this range covers all the records for any of the RecordTypes at a given label.
        let start_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MIN));
        let end_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MAX));

        fn aname_covers_type(key_type: RecordType, query_type: RecordType) -> bool {
            (query_type == RecordType::A || query_type == RecordType::AAAA)
                && key_type == RecordType::ANAME
        }

        self.records
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .find(|(key, _)| {
                key.record_type == record_type
                    || key.record_type == RecordType::CNAME
                    || aname_covers_type(key.record_type, record_type)
            })
            .map(|(_key, rr_set)| rr_set.clone())
    }

    /// Inserts or updates a `Record` depending on it's existence in the authority.
    ///
    /// Guarantees that SOA, CNAME only has one record, will implicitly update if they already exist.
    ///
    /// # Arguments
    ///
    /// * `record` - The `Record` to be inserted or updated.
    /// * `serial` - Current serial number to be recorded against updates.
    ///
    /// # Return value
    ///
    /// true if the value was inserted, false otherwise
    pub fn upsert(&mut self, record: Record, serial: u32) -> bool {
        assert_eq!(self.class, record.dns_class());

        fn is_nsec(_upsert_type: RecordType, _occupied_type: RecordType) -> bool {
            // TODO: we should make the DNSSec RecordTypes always visible
            false
        }

        /// returns true if an only if the label can not cooccupy space with the checked type
        #[allow(clippy::nonminimal_bool)]
        fn label_does_not_allow_multiple(
            upsert_type: RecordType,
            occupied_type: RecordType,
            check_type: RecordType,
        ) -> bool {
            // it's a CNAME/ANAME but there's a record that's not a CNAME/ANAME at this location
            (upsert_type == check_type && occupied_type != check_type) ||
                // it's a different record, but there is already a CNAME/ANAME here
                (upsert_type != check_type && occupied_type == check_type)
        }

        // check that CNAME and ANAME is either not already present, or no other records are if it's a CNAME
        let start_range_key =
            RrKey::new(record.name().into(), RecordType::Unknown(u16::min_value()));
        let end_range_key = RrKey::new(record.name().into(), RecordType::Unknown(u16::max_value()));

        let multiple_records_at_label_disallowed = self
            .records
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .any(|(key, _)| {
                !is_nsec(record.record_type(), key.record_type)
                    && label_does_not_allow_multiple(
                        record.record_type(),
                        key.record_type,
                        RecordType::CNAME,
                    )
            });

        if multiple_records_at_label_disallowed {
            // consider making this an error?
            return false;
        }

        let rr_key = RrKey::new(record.name().into(), record.rr_type());
        let records: &mut Arc<RecordSet> = self
            .records
            .entry(rr_key)
            .or_insert_with(|| Arc::new(RecordSet::new(record.name(), record.rr_type(), serial)));

        // because this is and Arc, we need to clone and then replace the entry
        let mut records_clone = RecordSet::clone(&*records);
        if records_clone.insert(record, serial) {
            *records = Arc::new(records_clone);
            true
        } else {
            false
        }
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    pub fn secure_zone(&mut self) -> Result<(), &str> {
        Err("DNSSEC was not enabled during compilation.")
    }
}

impl Authority for ShortZoneAuthority {
    type Lookup = AuthLookup;
    type LookupFuture = future::Ready<Result<Self::Lookup, LookupError>>;

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    fn lookup(
        &self,
        name: &LowerName,
        query_type: RecordType,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        let authority = self.clone();
        let name = name.clone();

        Box::pin(async move {
            match query_type {
                RecordType::AXFR | RecordType::ANY => {
                    Ok(AuthLookup::answers(LookupRecords::Empty, None))
                }
                _ => {
                    // perform the lookup
                    let result = authority
                        .inner_lookup(&name, query_type, is_secure, supported_algorithms, src)
                        .await
                        .map_or(Err(LookupError::from(ResponseCode::NXDomain)), |rr_set| {
                            Ok(LookupRecords::new(is_secure, supported_algorithms, rr_set))
                        });

                    // This is annoying. The 1035 spec literally specifies that most DNS authorities would want to store
                    //   records in a list except when there are a lot of records. But this makes indexed lookups by name+type
                    //   always return empty sets. This is only important in the negative case, where other DNS authorities
                    //   generally return NoError and no results when other types exist at the same name. bah.
                    // TODO: can we get rid of this?
                    match result {
                        Err(LookupError::ResponseCode(ResponseCode::NXDomain)) => {
                            if authority
                                .records
                                .keys()
                                .any(|key| key.name() == &name || name.zone_of(key.name()))
                            {
                                Err(LookupError::NameExists)
                            } else {
                                let code = if authority.origin().zone_of(&name) {
                                    ResponseCode::NXDomain
                                } else {
                                    ResponseCode::Refused
                                };
                                Err(LookupError::from(code))
                            }
                        }
                        Err(e) => Err(e),
                        o => Ok(AuthLookup::answers(o?, None)),
                    }
                }
            }
        })
    }

    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        let lookup_name = query.name();
        let record_type: RecordType = query.query_type();

        // if this is an AXFR zone transfer, verify that this is either the Secondary or Primary
        //  for AXFR the first and last record must be the SOA
        if RecordType::AXFR == record_type {
            return Box::pin(future::err(LookupError::from(ResponseCode::Refused)));
        }

        // perform the actual lookup
        match record_type {
            RecordType::SOA => Box::pin(self.lookup(
                self.origin(),
                record_type,
                is_secure,
                supported_algorithms,
                src,
            )),
            RecordType::AXFR => {
                unreachable!()
            }
            // A standard Lookup path
            _ => Box::pin(self.lookup(
                lookup_name,
                record_type,
                is_secure,
                supported_algorithms,
                src,
            )),
        }
    }

    fn get_nsec_records(
        &self,
        _name: &LowerName,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        Box::pin(future::ok(AuthLookup::default()))
    }
}
