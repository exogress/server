use exogress_server_common::prometheus::DEFAULT_TIME_BUCKETS;
use lazy_static::lazy_static;
use prometheus::{Encoder, Gauge, Histogram, IntCounter, TextEncoder};

lazy_static! {
    pub static ref CHANNEL_ESTABLISHMENT_ERRORS: IntCounter = register_int_counter!(
        "signaler_channels_establishment_errors",
        "Number of errors trying to establish channel"
    )
    .unwrap();
    pub static ref ACTIVE_CHANNELS: Gauge = register_gauge!(
        "signaler_active_channels",
        "Number of active channels with clients"
    )
    .unwrap();
    pub static ref CHANELS_ESTABLISHMENT_TIME: Histogram = register_histogram!(
        "signaler_channels_establishment_time",
        "Time taken to establish signaling channel",
        DEFAULT_TIME_BUCKETS.clone()
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
