use exogress_server_common::prometheus::DEFAULT_TIME_BUCKETS;
use lazy_static::lazy_static;
use prometheus::{
    register_gauge, register_histogram, register_int_counter_vec, Encoder, Gauge, Histogram,
    IntCounterVec, TextEncoder,
};

lazy_static! {
    pub static ref ACTIVE_CHANNELS: Gauge = register_gauge!(
        "assistant_active_channels",
        "Number of active channels with clients"
    )
    .unwrap();
    pub static ref CHANELS_ESTABLISHMENT_TIME: Histogram = register_histogram!(
        "assistant_channels_establishment_time",
        "Time taken to establish signaling channel",
        DEFAULT_TIME_BUCKETS.clone()
    )
    .unwrap();
    pub static ref GW_MESSAGES_PARSED: IntCounterVec = register_int_counter_vec!(
        "assistant_gw_messages_parsed",
        "Number of parsed gateway messages",
        &["error"]
    )
    .unwrap();
}

pub fn dump_prometheus() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    String::from_utf8(buffer).expect("bad prometheus data")
}
