use lazy_static::lazy_static;
use prometheus::{
    linear_buckets, register_histogram, register_int_counter_vec, Encoder, Histogram,
    IntCounterVec, TextEncoder,
};
use std::net::SocketAddr;
use warp::Filter;

lazy_static! {}

pub fn dump_prometheus() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    String::from_utf8(buffer).expect("bad prometheus data")
}
