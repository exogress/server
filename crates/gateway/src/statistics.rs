use prometheus::{Encoder, Gauge, TextEncoder};

lazy_static! {
    pub static ref TUNNELS_GAUGE: Gauge =
        register_gauge!(opts!("tunnels", "Number of tunnels with clients")).unwrap();
    // pub static ref TUNNELS_BYTES_SENT: Counter =
    //     register_counter!(opts!("tunnels_bytes_sent", "Bytes sent to tunnels")).unwrap();
    // pub static ref TUNNELS_BYTES_RECV: Counter =
    //     register_counter!(opts!("tunnels_bytes_recv", "Bytes received from tunnels")).unwrap();
}

pub fn dump_prometheus() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    String::from_utf8(buffer).expect("bad prometheus data")
}
