use std::net::SocketAddr;
use std::sync::Arc;
use warp::Filter;

pub async fn spawn(
    addr: SocketAddr,
    tls_cert_path: String,
    tls_key_path: String,
) -> Result<(), anyhow::Error> {
    let tls = Arc::new(
        warp::TlsConfigBuilder::new()
            .cert_path(tls_cert_path)
            .key_path(tls_key_path)
            .build()?,
    );

    warp::serve(warp::path!("metrics").map(|| crate::statistics::dump_prometheus()))
        .tls(move |_| futures::future::ready(Some(tls.clone())))
        .run(addr)
        .await;

    Ok(())
}
