use exogress_entities::ConfigName;
use exogress_signaling::TunnelRequest;
use smartstring::alias::*;
use std::time::Duration;
use url::Url;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("client not connected")]
    ClientNotConnected,

    #[error("unexpected status code {0}")]
    UnexpectedStatusCode(reqwest::StatusCode),

    #[error("HTTP call error: `{0}`")]
    HttpCall(#[from] reqwest::Error),
}

// signaler_int_base_url =
pub async fn request_connection(
    mut signaler_int_base_url: Url,
    hostname: String,
    config_name: ConfigName,
) -> Result<(), Error> {
    let client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .use_rustls_tls()
        .trust_dns(true)
        .build()
        .expect("could not create reqwest client");

    let msg = TunnelRequest { hostname };

    info!("requesting connection for config_name {}", config_name);

    {
        let mut segments = signaler_int_base_url.path_segments_mut().unwrap();
        segments.push("api");
        segments.push("v1");
        segments.push("configs");
        segments.push(config_name.as_ref());
        segments.push("tunnels");
    }

    let resp = client
        .put(signaler_int_base_url)
        .header("authorization", "FIXME")
        .json(&msg)
        .send()
        .await?;

    match resp.status() {
        reqwest::StatusCode::NOT_FOUND => Err(Error::ClientNotConnected),
        s if s.is_success() => {
            info!("requesting connection succeeded");

            Ok(())
        }
        s => {
            info!("requesting connection failed with code {}", s);

            Err(Error::UnexpectedStatusCode(s))
        }
    }
}
