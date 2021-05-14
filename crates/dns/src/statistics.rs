use lazy_static::lazy_static;
use prometheus::{register_int_counter_vec, Encoder, IntCounterVec, TextEncoder};
use std::net::SocketAddr;
use warp::Filter;

lazy_static! {
    pub static ref NUM_DNS_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "director_dns_requests",
        "Number of processed DNS requests",
        &["success"]
    )
    .unwrap();
}

fn dump_prometheus() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    String::from_utf8(buffer).expect("bad prometheus data")
}

pub async fn spawn(addr: SocketAddr) -> Result<(), anyhow::Error> {
    warp::serve(warp::path!("metrics").map(dump_prometheus))
        .run(addr)
        .await;

    Ok(())
}
