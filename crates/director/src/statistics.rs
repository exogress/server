use lazy_static::lazy_static;
use prometheus::{register_histogram, Encoder, Histogram, TextEncoder};
use std::net::SocketAddr;
use warp::Filter;

lazy_static! {
    pub static ref BUF_FILL_BYTES: Histogram = register_histogram!(
        "director_buf_filling_bytes",
        "Number of bytes filled in the TCP forwarded buffer",
        vec![
            8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16536.0,
            32768.0, 65536.0
        ]
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
    warp::serve(warp::path!("metrics").map(|| dump_prometheus()))
        .run(addr)
        .await;

    Ok(())
}
