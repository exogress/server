use exogress_server_common::prometheus::DEFAULT_TIME_BUCKETS;
use prometheus::{Encoder, Gauge, Histogram, IntCounter, IntCounterVec, TextEncoder};

pub const HTTP_ERROR_REQUEST_ERROR: &str = "request_error";
pub const HTTP_ERROR_BAD_RESPONSE: &str = "bad_response";
pub const HTTP_ERROR_BAD_STATUS: &str = "bad_status";

pub const CACHE_ACTION_WRITE: &str = "write";
pub const CACHE_ACTION_READ: &str = "read";

lazy_static! {
    pub static ref CACHE_ERRORS: IntCounterVec =
        register_int_counter_vec!("gw_cache_errors", "Local cache errors", &["action"]).unwrap();
    pub static ref CACHE_SERVED: IntCounter =
        register_int_counter!("gw_cache_served", "Local cache served bytes").unwrap();
    pub static ref CACHE_SAVED: IntCounter =
        register_int_counter!("gw_cache_saved", "Local cache saved bytes").unwrap();
    pub static ref CONFIGS_CACHE_HIT: IntCounter =
        register_int_counter!("gw_configs_cache_hit", "Configs cache hit").unwrap();
    pub static ref CONFIGS_CACHE_MISS: IntCounter =
        register_int_counter!("gw_configs_cache_miss", "Configs cache miss").unwrap();
    pub static ref CONFIGS_RETRIEVAL_TIME: Histogram = register_histogram!(
        "gw_configs_retrieval_time",
        "Time take to retrieve the config",
        DEFAULT_TIME_BUCKETS.clone()
    )
    .unwrap();
    pub static ref TUNNEL_ESTABLISHMENT_TIME: Histogram = register_histogram!(
        "gw_tunnel_establishment_time",
        "Time take to establish tunnels with instances",
        DEFAULT_TIME_BUCKETS.clone()
    )
    .unwrap();
    pub static ref CONFIGS_RETRIEVAL_SUCCESS: IntCounter = register_int_counter!(
        "gw_configs_retrieval_success",
        "Number of successful configs retrieval (incl. not-found)"
    )
    .unwrap();
    pub static ref CONFIGS_PROCESSING_ERRORS: IntCounter = register_int_counter!(
        "gw_configs_processing_error",
        "Number of configs, where response couldn't be properly processed"
    )
    .unwrap();
    pub static ref CONFIGS_RETRIEVAL_ERROR: IntCounterVec = register_int_counter_vec!(
        "gw_configs_retrieval_error",
        "Number of erroneous configs retrievals",
        &["error", "status_code"]
    )
    .unwrap();
    pub static ref CONFIGS_FORGOTTEN: IntCounter =
        register_int_counter!("gw_configs_forgotten", "Number of forgotten configs").unwrap();
    pub static ref CERTIFICATES_CACHE_HIT: IntCounter =
        register_int_counter!("gw_certificates_cache_hit", "Certificates cache hit").unwrap();
    pub static ref CERTIFICATES_CACHE_MISS: IntCounter =
        register_int_counter!("gw_certificates_cache_miss", "Certificates cache miss").unwrap();
    pub static ref CERTIFICATES_RETRIEVAL_TIME: Histogram = register_histogram!(
        "gw_certificates_retrieval_time",
        "Time take to retrieve the certificate",
        DEFAULT_TIME_BUCKETS.clone()
    )
    .unwrap();
    pub static ref CERTIFICATES_RETRIEVAL_SUCCESS: IntCounter = register_int_counter!(
        "gw_certificates_retrieval_success",
        "Number of successful certificates retrieval (incl. not-found)"
    )
    .unwrap();
    pub static ref CERTIFICATES_FORGOTTEN: IntCounter = register_int_counter!(
        "gw_certificates_forgotten",
        "Number of forgotten certificates"
    )
    .unwrap();
    pub static ref CERTIFICATES_RETRIEVAL_ERROR: IntCounterVec = register_int_counter_vec!(
        "gw_certificates_retrieval_error",
        "Number of erroneous certificates retrievals",
        &["error", "status_code"]
    )
    .unwrap();
    pub static ref TUNNELS_GAUGE: Gauge =
        register_gauge!("gw_connected_tunnels", "Number of tunnels with clients").unwrap();
    pub static ref TUNNELS_BYTES_SENT: IntCounter =
        register_int_counter!("gw_tunnels_bytes_sent", "Bytes sent to tunnels").unwrap();
    pub static ref TUNNELS_BYTES_RECV: IntCounter =
        register_int_counter!("gw_tunnels_bytes_recv", "Bytes received from tunnels").unwrap();
    pub static ref PUBLIC_ENDPOINT_BYTES_SENT: IntCounter = register_int_counter!(
        "gw_public_endpoints_bytes_sent",
        "Bytes sent to public endpoints"
    )
    .unwrap();
    pub static ref PUBLIC_ENDPOINT_BYTES_RECV: IntCounter = register_int_counter!(
        "gw_public_endpoints_bytes_recv",
        "Bytes received from public endpoints"
    )
    .unwrap();
    pub static ref HTTPS_BYTES_SENT: IntCounter = register_int_counter!(
        "gw_https_bytes_sent",
        "Bytes sent through HTTPS (serving traffic)"
    )
    .unwrap();
    pub static ref HTTPS_BYTES_RECV: IntCounter = register_int_counter!(
        "gw_https_bytes_recv",
        "Bytes received from HTTPS (serving traffic)"
    )
    .unwrap();
    pub static ref HTTPS_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "gw_https_requests",
        "Number of HTTPS requests served",
        &["http_version"]
    )
    .unwrap();
    pub static ref ACTIVE_REQUESTS_PROCESSORS: Gauge = register_gauge!(
        "gw_active_requests_processors",
        "Number of active requests processors"
    )
    .unwrap();
    pub static ref UPTIME_SECS: Gauge = register_gauge!(
        "gw_uptime_secs",
        "Number of seconds since gateway was spawned"
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
