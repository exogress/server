use lazy_static::lazy_static;
use prometheus::{
    linear_buckets, register_histogram, register_int_counter_vec, Encoder, Histogram,
    IntCounterVec, TextEncoder,
};
use std::net::SocketAddr;
use warp::Filter;

lazy_static! {
    pub static ref BUF_FILL_BYTES: Histogram = register_histogram!(
        "director_buf_filling_bytes",
        "Number of bytes filled in the TCP forwarded buffer",
        linear_buckets(50.0, 50.0, 30).unwrap()
    )
    .unwrap();
    pub static ref NUM_PROXIED_REQUESTS: IntCounterVec =
        register_int_counter_vec!("director_requests", "Number of requests processed", c).unwrap();
}

fn dump_prometheus() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    String::from_utf8(buffer).expect("bad prometheus data")
}

pub async fn spawn(addr: SocketAddr) -> Result<(), anyhow::Error> {
    warp::serve(warp::path!("metrics").map(|| dump_prometheus()))
        .run(addr)
        .await;

    Ok(())
}
