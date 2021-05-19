/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// TODO, I've implemented this as a separate entity from the cache, but I wonder if the cache
//  should be the only "front-end" for lookups, where if that misses, then we go to the catalog
//  then, if requested, do a recursive lookup... i.e. the catalog would only point to files.
use std::{borrow::Borrow, future::Future, io, pin::Pin};

use tracing::{debug, error, info, trace, warn};

use crate::{
    authority::AuthorityObject, cdn_zone::CdnZoneAuthority, ecs::parse_ecs,
    int_api_client::IntApiClient, rules_processor::BestPopFinder, short_zone::ShortZoneAuthority,
};
use parking_lot::RwLock;
use std::{collections::BTreeMap, net::IpAddr, sync::Arc};
use trust_dns_server::{
    authority::{
        AuthLookup, BoxedLookupFuture, LookupError, LookupObject, MessageRequest, MessageResponse,
        MessageResponseBuilder,
    },
    client::{
        op::{Edns, Header, LowerQuery, MessageType, OpCode, ResponseCode},
        rr::{
            dnssec::{Algorithm, SupportedAlgorithms},
            rdata::opt::{EdnsCode, EdnsOption},
            LowerName, RrKey,
        },
    },
    proto::rr::RecordSet,
    server::{Request, RequestHandler, ResponseHandler},
};

/// Set of authorities, zones, available to this server.
pub struct DynamicZones {
    short_zone: LowerName,
    short_zone_authority: Box<Arc<RwLock<ShortZoneAuthority>>>,
    net_zone: LowerName,
    net_zone_authority: Box<Arc<RwLock<CdnZoneAuthority>>>,
}

fn send_response<R: ResponseHandler>(
    response_edns: Option<Edns>,
    mut response: MessageResponse<'_, '_>,
    mut response_handle: R,
) -> io::Result<()> {
    if let Some(mut resp_edns) = response_edns {
        // set edns DAU and DHU
        // send along the algorithms which are supported by this authority
        let mut algorithms = SupportedAlgorithms::new();
        algorithms.set(Algorithm::RSASHA256);
        algorithms.set(Algorithm::ECDSAP256SHA256);
        algorithms.set(Algorithm::ECDSAP384SHA384);
        algorithms.set(Algorithm::ED25519);

        let dau = EdnsOption::DAU(algorithms);
        let dhu = EdnsOption::DHU(algorithms);

        resp_edns.options_mut().insert(dau);
        resp_edns.options_mut().insert(dhu);

        response.set_edns(resp_edns);
    }

    response_handle.send_response(response)
}

impl RequestHandler for DynamicZones {
    type ResponseFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

    /// Determines what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_handle` - sink for the response message to be sent
    fn handle_request<R: ResponseHandler>(
        &self,
        request: Request,
        mut response_handle: R,
    ) -> Self::ResponseFuture {
        let request_message = request.message;
        trace!("request: {:?}", request_message);

        let response_edns: Option<Edns>;

        // check if it's edns
        if let Some(req_edns) = request_message.edns() {
            let mut response = MessageResponseBuilder::new(Some(request_message.raw_queries()));
            let mut response_header = Header::default();
            response_header.set_id(request_message.id());

            let mut resp_edns: Edns = Edns::new();

            // check our version against the request
            // TODO: what version are we?
            let our_version = 0;
            resp_edns.set_dnssec_ok(true);
            resp_edns.set_max_payload(req_edns.max_payload().max(512));
            resp_edns.set_version(our_version);

            if req_edns.version() > our_version {
                warn!(
                    "request edns version greater than {}: {}",
                    our_version,
                    req_edns.version()
                );
                response_header.set_response_code(ResponseCode::BADVERS);
                response.edns(resp_edns);

                // TODO: should ResponseHandle consume self?
                let result =
                    response_handle.send_response(response.build_no_records(response_header));
                if let Err(e) = result {
                    error!("request error: {}", e);
                }
                return Box::pin(async {});
            }

            response_edns = Some(resp_edns);
        } else {
            response_edns = None;
        }

        let result = match request_message.message_type() {
            // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
            //  especially for recursive lookups
            MessageType::Query => match request_message.op_code() {
                OpCode::Query => {
                    debug!("query received: {}", request_message.id());
                    return Box::pin(self.lookup(
                        request_message,
                        response_edns,
                        response_handle,
                        request.src.ip(),
                    ));
                }
                c => {
                    warn!("unimplemented op_code: {:?}", c);
                    let response = MessageResponseBuilder::new(Some(request_message.raw_queries()));
                    response_handle.send_response(response.error_msg(
                        request_message.id(),
                        request_message.op_code(),
                        ResponseCode::NotImp,
                    ))
                }
            },
            MessageType::Response => {
                warn!(
                    "got a response as a request from id: {}",
                    request_message.id()
                );
                let response = MessageResponseBuilder::new(Some(request_message.raw_queries()));
                response_handle.send_response(response.error_msg(
                    request_message.id(),
                    request_message.op_code(),
                    ResponseCode::FormErr,
                ))
            }
        };

        if let Err(e) = result {
            error!("request failed: {}", e);
        }
        Box::pin(async {})
    }
}

impl DynamicZones {
    /// Constructs a new Catalog
    pub fn new(
        short_zone: &str,
        net_zone: &str,
        short_zone_records: BTreeMap<RrKey, RecordSet>,
        net_zone_records: BTreeMap<RrKey, RecordSet>,
        target: &str,
        int_api_client: IntApiClient,
        rules_processor: BestPopFinder,
    ) -> anyhow::Result<Self> {
        Ok(DynamicZones {
            short_zone_authority: Box::new(Arc::new(RwLock::new(
                ShortZoneAuthority::new(
                    short_zone.parse()?,
                    short_zone_records,
                    target.parse()?,
                    int_api_client.clone(),
                )
                .map_err(|e| anyhow!("{}", e))?,
            ))),
            short_zone: short_zone.parse()?,
            net_zone_authority: Box::new(Arc::new(RwLock::new(
                CdnZoneAuthority::new(
                    net_zone.parse()?,
                    net_zone_records,
                    int_api_client,
                    rules_processor,
                )
                .map_err(|e| anyhow!("{}", e))?,
            ))),
            net_zone: net_zone.parse()?,
        })
    }

    /// Given the requested query, lookup and return any matching results.
    ///
    /// # Arguments
    ///
    /// * `request` - the query message.
    /// * `response_handle` - sink for the response message to be sent
    pub fn lookup<R: ResponseHandler>(
        &self,
        request: MessageRequest,
        response_edns: Option<Edns>,
        response_handle: R,
        src: IpAddr,
    ) -> impl Future<Output = ()> + 'static {
        let queries_and_authorities = request
            .queries()
            .iter()
            .enumerate()
            .filter_map(|(i, q)| {
                self.find(q.name())
                    .map(|authority| (i, authority.box_clone()))
            })
            .collect::<Vec<_>>();

        if queries_and_authorities.is_empty() {
            let response = MessageResponseBuilder::new(Some(request.raw_queries()));
            send_response(
                response_edns
                    .as_ref()
                    .map(|arc| Borrow::<Edns>::borrow(arc).clone()),
                response.error_msg(request.id(), request.op_code(), ResponseCode::NXDomain),
                response_handle.clone(),
            )
            .map_err(|e| error!("failed to send response: {}", e))
            .ok();
        }

        lookup(
            queries_and_authorities,
            request,
            response_edns,
            response_handle,
            src,
        )
    }

    /// Recursively searches the catalog for a matching authority
    pub fn find(&self, name: &LowerName) -> Option<&(dyn AuthorityObject + 'static)> {
        if name == &self.short_zone {
            Some(&*self.short_zone_authority)
        } else if name == &self.net_zone {
            Some(&*self.net_zone_authority)
        } else {
            if !name.is_root() {
                let name = name.base_name();
                self.find(&name)
            } else {
                None
            }
        }
    }
}

async fn lookup<R: ResponseHandler + Unpin>(
    queries_and_authorities: Vec<(usize, Box<dyn AuthorityObject>)>,
    request: MessageRequest,
    response_edns: Option<Edns>,
    response_handle: R,
    src: IpAddr,
) {
    // TODO: the spec is very unclear on what to do with multiple queries
    //  we will search for each, in the future, maybe make this threaded to respond even faster.
    //  the current impl will return on the first query result
    for (query_idx, authority) in queries_and_authorities {
        let query = &request.queries()[query_idx];
        debug!(
            "request: {} found authority: {}",
            request.id(),
            authority.origin()
        );

        let (response_header, sections) =
            build_response(&*authority, request.id(), query, request.edns(), src).await;

        let response = MessageResponseBuilder::new(Some(request.raw_queries())).build(
            response_header,
            sections.answers.iter(),
            sections.ns.iter(),
            sections.soa.iter(),
            sections.additionals.iter(),
        );

        let result = send_response(response_edns.clone(), response, response_handle.clone());
        if let Err(e) = result {
            error!("error sending response: {}", e);
        }
    }
}

async fn build_response(
    authority: &dyn AuthorityObject,
    request_id: u16,
    query: &LowerQuery,
    edns: Option<&Edns>,
    src: IpAddr,
) -> (Header, LookupSections) {
    let (is_dnssec, supported_algorithms) =
        edns.map_or((false, SupportedAlgorithms::new()), |edns| {
            let supported_algorithms =
                if let Some(&EdnsOption::DAU(algs)) = edns.option(EdnsCode::DAU) {
                    algs
                } else {
                    debug!("no DAU in request, used default SupportAlgorithms");
                    Default::default()
                };

            (edns.dnssec_ok(), supported_algorithms)
        });

    // log algorithms being requested
    if is_dnssec {
        info!(
            "request: {} supported_algs: {}",
            request_id, supported_algorithms
        );
    }

    let mut response_header = Header::new();
    response_header.set_id(request_id);
    response_header.set_op_code(OpCode::Query);
    response_header.set_message_type(MessageType::Response);
    response_header.set_authoritative(true);

    info!("performing {} on {}", query, authority.origin());

    let remote_addr = if let Some(edns) = edns {
        // 8 - ClientSubnet
        if let Some(EdnsOption::Unknown(8, ref data)) = edns.option(EdnsCode::Subnet) {
            parse_ecs(data).ok()
        } else {
            None
        }
    } else {
        None
    }
    .unwrap_or(src);

    let future = authority.search(query, is_dnssec, supported_algorithms, remote_addr);

    let sections = send_authoritative_response(
        future,
        authority,
        &mut response_header,
        is_dnssec,
        supported_algorithms,
        request_id,
        &query,
        src,
    )
    .await;

    (response_header, sections)
}

async fn send_authoritative_response(
    future: BoxedLookupFuture,
    authority: &dyn AuthorityObject,
    response_header: &mut Header,
    is_dnssec: bool,
    supported_algorithms: SupportedAlgorithms,
    request_id: u16,
    query: &LowerQuery,
    src: IpAddr,
) -> LookupSections {
    // In this state we await the records, on success we transition to getting
    // NS records, which indicate an authoritative response.
    //
    // On Errors, the transition depends on the type of error.
    let answers = match future.await {
        Ok(records) => {
            response_header.set_response_code(ResponseCode::NoError);
            response_header.set_authoritative(true);
            Some(records)
        }
        // This request was refused
        // TODO: there are probably other error cases that should just drop through (FormErr, ServFail)
        Err(LookupError::ResponseCode(ResponseCode::Refused)) => {
            response_header.set_response_code(ResponseCode::Refused);
            return LookupSections {
                answers: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
                ns: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
                soa: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
                additionals: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
            };
        }
        Err(e) => {
            if e.is_nx_domain() {
                response_header.set_response_code(ResponseCode::NXDomain);
            } else if e.is_name_exists() {
                response_header.set_response_code(ResponseCode::NoError);
            };
            None
        }
    };

    let (ns, soa) = if answers.is_some() {
        // This was a successful authoritative lookup:
        //   get the NS records
        match authority.ns(is_dnssec, supported_algorithms, src).await {
            Ok(ns) => (Some(ns), None),
            Err(e) => {
                warn!("ns_lookup errored: {}", e);
                (None, None)
            }
        }
    } else {
        let nsecs = if is_dnssec {
            // in the dnssec case, nsec records should exist, we return NoError + NoData + NSec...
            debug!("request: {} non-existent adding nsecs", request_id);
            // run the nsec lookup future, and then transition to get soa
            let future = authority.get_nsec_records(query.name(), true, supported_algorithms);
            match future.await {
                // run the soa lookup
                Ok(nsecs) => Some(nsecs),
                Err(e) => {
                    warn!("failed to lookup nsecs: {}", e);
                    None
                }
            }
        } else {
            None
        };

        match authority
            .soa_secure(is_dnssec, supported_algorithms, src)
            .await
        {
            Ok(soa) => (nsecs, Some(soa)),
            Err(e) => {
                warn!("failed to lookup soa: {}", e);
                (nsecs, None)
            }
        }
    };

    // everything is done, return results.
    let (answers, additionals) = match answers {
        Some(mut answers) => match answers.take_additionals() {
            Some(additionals) => (answers, additionals),
            None => (
                answers,
                Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
            ),
        },
        None => (
            Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
            Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
        ),
    };

    LookupSections {
        answers,
        ns: ns.unwrap_or_else(|| Box::new(AuthLookup::default()) as Box<dyn LookupObject>),
        soa: soa.unwrap_or_else(|| Box::new(AuthLookup::default()) as Box<dyn LookupObject>),
        additionals,
    }
}

struct LookupSections {
    answers: Box<dyn LookupObject>,
    ns: Box<dyn LookupObject>,
    soa: Box<dyn LookupObject>,
    additionals: Box<dyn LookupObject>,
}
