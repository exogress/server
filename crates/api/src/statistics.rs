use lazy_static::lazy_static;
use prometheus::{Encoder, TextEncoder};

lazy_static! {}

pub fn dump_prometheus() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    String::from_utf8(buffer).expect("bad prometheus data")
}
