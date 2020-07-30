use exogress_entities::{ConfigName, InstanceId};
use exogress_signaling::TunnelRequest;
use smartstring::alias::*;
use std::time::Duration;

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
    hostname: String,
    config_name: ConfigName,
    log: slog::Logger,
) -> Result<(), Error> {
    let log = log.new(o!("config_name" => config_name.clone()));
    let client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .use_rustls_tls()
        .trust_dns(true)
        .build()
        .expect("could not create reqwest client");

    let msg = TunnelRequest {
        hostname,
        num_connections: 1,
    };

    info!(log, "requesting connection for instance {}", config_name);

    let resp = client
        .post(
            format!(
                "http://localhost:2999/api/v1/instances/{}/tunnels",
                config_name
            )
            .as_str(),
        )
        .json(&msg)
        .send()
        .await?;

    match resp.status() {
        reqwest::StatusCode::NOT_FOUND => Err(Error::ClientNotConnected),
        s if s.is_success() => {
            info!(log, "requesting connection succeeded");

            Ok(())
        }
        s => {
            info!(log, "requesting connection failed with code {}", s);

            Err(Error::UnexpectedStatusCode(s))
        }
    }
}
