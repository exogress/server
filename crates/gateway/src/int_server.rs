use std::net::SocketAddr;
use warp::Filter;

pub async fn spawn(
    addr: SocketAddr,
    tls_cert_path: String,
    tls_key_path: String,
) -> Result<(), anyhow::Error> {
    warp::serve(warp::path!("metrics").map(crate::statistics::dump_prometheus))
        .tls()
        .cert_path(tls_cert_path)
        .key_path(tls_key_path)
        .run(addr)
        .await;

    Ok(())
}
