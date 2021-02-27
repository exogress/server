use futures::channel::oneshot;
use std::{
    collections::BTreeMap,
    convert::TryInto,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    select,
};
use trust_dns_server::{
    authority::{Catalog, ZoneType},
    client::{
        proto::rr::rdata::SOA,
        rr::{LowerName, RrKey},
    },
    proto::rr::{RData, Record, RecordSet, RecordType},
    ServerFuture,
};

mod authority;

pub struct DnsServer {
    _stop: oneshot::Sender<()>,
}

impl DnsServer {
    const SERIAL: u32 = 1;
    const TTL: i32 = 21600;

    pub async fn new(
        short_zone: &str,
        ns_servers: &[String],
        soa_rname: &str,
        target: &str,
        port: u16,
    ) -> anyhow::Result<Self> {
        info!(
            "spawn DNS server for zone {} served by {:?}, with rname {}, CNAME all to {} on port {}", 
              short_zone, ns_servers, soa_rname, target, port);

        let short_zone_lower_name: LowerName = short_zone.parse()?;

        let mut records = BTreeMap::new();
        let mut soa_val = RecordSet::with_ttl(
            short_zone_lower_name.clone().into(),
            RecordType::SOA,
            Self::TTL.try_into()?,
        );
        soa_val.insert(
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
        records.insert(
            RrKey::new(short_zone_lower_name.clone(), RecordType::SOA),
            soa_val,
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

        records.insert(
            RrKey::new(short_zone_lower_name.clone(), RecordType::NS),
            ns_val,
        );

        let mut catalog = Catalog::new();
        catalog.upsert(
            short_zone_lower_name,
            Box::new(Arc::new(RwLock::new(
                authority::InMemoryAuthorityWithConstCname::new(
                    short_zone.parse()?,
                    records,
                    target.parse().unwrap(),
                    ZoneType::Primary,
                    false,
                )
                .map_err(|e| anyhow!("{}", e))?,
            ))),
        );

        let mut server = ServerFuture::new(catalog);

        let udp = UdpSocket::bind(SocketAddr::from(([0u8, 0, 0, 0], port))).await?;
        let tcp = TcpListener::bind(SocketAddr::from(([0u8, 0, 0, 0], port))).await?;

        server.register_socket(udp);
        server.register_listener(tcp, Duration::from_secs(5));

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
