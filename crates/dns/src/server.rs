use crate::{catalog::DynamicZones, int_api_client::IntApiClient, rules_processor::BestPopFinder};
use futures::channel::oneshot;
use std::{
    collections::BTreeMap,
    convert::TryInto,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    select,
};
use trust_dns_server::{
    client::{
        proto::rr::rdata::SOA,
        rr::{LowerName, RrKey},
    },
    proto::rr::{RData, Record, RecordSet, RecordType},
    ServerFuture,
};

pub struct DnsServer {
    _stop: oneshot::Sender<()>,
}

impl DnsServer {
    fn zone_records(
        short_zone_lower_name: &LowerName,
        ns_servers: &[String],
        soa_rname: &str,
    ) -> anyhow::Result<BTreeMap<RrKey, RecordSet>> {
        let mut short_zone_records = BTreeMap::new();
        let mut short_zone_soa_val = RecordSet::with_ttl(
            short_zone_lower_name.clone().into(),
            RecordType::SOA,
            Self::TTL.try_into()?,
        );
        short_zone_soa_val.insert(
            Record::from_rdata(
                short_zone_lower_name.clone().into(),
                Self::TTL.try_into()?,
                RData::SOA(SOA::new(
                    short_zone_lower_name.clone().into(),
                    soa_rname.parse()?,
                    Self::SERIAL,
                    Self::TTL,
                    3600,
                    259200,
                    300,
                )),
            ),
            Self::SERIAL,
        );
        short_zone_records.insert(
            RrKey::new(short_zone_lower_name.clone(), RecordType::SOA),
            short_zone_soa_val,
        );

        let mut ns_val = RecordSet::with_ttl(
            short_zone_lower_name.clone().into(),
            RecordType::NS,
            Self::TTL.try_into()?,
        );

        for ns_server in ns_servers {
            ns_val.insert(
                Record::from_rdata(
                    short_zone_lower_name.clone().into(),
                    Self::TTL.try_into()?,
                    RData::NS(ns_server.parse()?),
                ),
                Self::SERIAL,
            );
        }

        short_zone_records.insert(
            RrKey::new(short_zone_lower_name.clone(), RecordType::NS),
            ns_val,
        );

        Ok(short_zone_records)
    }

    const SERIAL: u32 = 1;
    const TTL: i32 = 21600;

    pub async fn new(
        short_zone: &str,
        net_zone: &str,
        ns_servers: &[String],
        soa_rname: &str,
        target: &str,
        int_api_client: IntApiClient,
        bind_to: &[IpAddr],
        port: u16,
        rules_processor: BestPopFinder,
    ) -> anyhow::Result<Self> {
        info!(
            "spawn DNS server for zone {} served by {:?}, with rname {}, CNAME all to {} on {:?} port {}",
            short_zone, ns_servers, soa_rname, target, bind_to, port);

        let short_zone_lower_name: LowerName = short_zone.parse()?;
        let net_zone_lower_name: LowerName = net_zone.parse()?;
        let catalog = DynamicZones::new(
            short_zone,
            net_zone,
            Self::zone_records(&short_zone_lower_name, ns_servers, soa_rname)?,
            Self::zone_records(&net_zone_lower_name, ns_servers, soa_rname)?,
            target,
            int_api_client,
            rules_processor,
        )?;

        let mut server = ServerFuture::new(catalog);

        for addr in bind_to {
            let udp = UdpSocket::bind(SocketAddr::from((*addr, port))).await?;
            server.register_socket(udp);

            let tcp = TcpListener::bind(SocketAddr::from((*addr, port))).await?;
            server.register_listener(tcp, Duration::from_secs(5));
        }

        let (stop_tx, stop_rx) = oneshot::channel();

        let f = async move {
            let bg = server.block_until_done();
            select! {
                _ = bg => {},
                _ = stop_rx => {
                    info!("DNS server stopped by request");
                },
            }
        };

        tokio::spawn(f);

        Ok(DnsServer { _stop: stop_tx })
    }
}
