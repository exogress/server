use exogress_server_common::dns_rules::EnvironmentsRules;
use reqwest::Identity;
use std::time::Duration;
use url::Url;

pub struct AssistantClient {
    client: reqwest::Client,
    assistant_base_url: Url,
}

impl AssistantClient {
    pub async fn new(
        assistant_base_url: Url,
        maybe_identity: Option<Vec<u8>>,
    ) -> anyhow::Result<AssistantClient> {
        let mut builder = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .use_rustls_tls()
            .trust_dns(true);

        if let Some(identity) = maybe_identity {
            builder = builder.identity(Identity::from_pem(&identity).unwrap());
        }

        Ok(AssistantClient {
            client: builder.build()?,
            assistant_base_url,
        })
    }

    pub async fn get_dns_rules(&self) -> anyhow::Result<EnvironmentsRules> {
        let mut url = self.assistant_base_url.clone();

        url.path_segments_mut()
            .unwrap()
            .push("int_api")
            .push("v1")
            .push("dns_rules");

        let res = self.client.get(url).send().await?;

        Ok(res.json().await?)
    }
}
