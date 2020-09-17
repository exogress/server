use crate::clients::tunnel::MAX_ALLOWED_TUNNELS;
use exogress_entities::{AccountName, ConfigId, ConfigName, ProjectName};
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

pub async fn request_connection(
    mut int_base_url: Url,
    hostname: String,
    config_id: ConfigId,
) -> Result<(), Error> {
    let client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .use_rustls_tls()
        .trust_dns(true)
        .build()
        .expect("could not create reqwest client");

    let msg = TunnelRequest {
        hostname,
        max_tunnels_count: MAX_ALLOWED_TUNNELS as u16,
    };

    info!("requesting connection for {}", config_id);

    {
        let mut segments = int_base_url.path_segments_mut().unwrap();
        segments.push("api");
        segments.push("v1");
        segments.push("accounts");
        segments.push(config_id.account_name.as_str());
        segments.push("projects");
        segments.push(config_id.project_name.as_str());
        segments.push("configs");
        segments.push(config_id.config_name.as_ref());
        segments.push("tunnels");
    }

    let resp = client
        .put(int_base_url)
        .header("authorization", "FIXME")
        .json(&msg)
        .send()
        .await?;

    info!("resp {:?}", resp);

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
