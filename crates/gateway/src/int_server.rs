use std::net::SocketAddr;
use warp::Filter;

pub async fn spawn(
    addr: SocketAddr,
    tls_cert_path: String,
    tls_key_path: String,
) -> Result<(), anyhow::Error> {
    let prometheus = warp::path!("metrics").map(crate::statistics::dump_prometheus);
    let jemalloc = warp::path!("mem").map(|| {
        match exogress_server_common::statistics::jemalloc::dump_jemalloc_statistics() {
            Ok(s) => s,
            Err(e) => e.to_string(),
        }
    });
    warp::serve(prometheus.or(jemalloc))
        .tls()
        .cert_path(tls_cert_path)
        .key_path(tls_key_path)
        .run(addr)
        .await;

    Ok(())
}
