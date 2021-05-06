use anyhow::anyhow;
use elasticsearch::{
    cert::{Certificate, CertificateValidation},
    cluster::ClusterHealthParts,
    http::transport::{SingleNodeConnectionPool, TransportBuilder},
    BulkOperation, BulkParts, Elasticsearch,
};
use exogress_server_common::logging::LogMessage;
use serde_json::Value;
use tokio::{fs::File, io::AsyncReadExt};

#[derive(Clone)]
pub struct ElasticsearchClient {
    client: Elasticsearch,
}

impl ElasticsearchClient {
    pub async fn new(url: &str, elasticsearch_ca: Option<String>) -> anyhow::Result<Self> {
        let conn_pool = SingleNodeConnectionPool::new(url.parse()?);

        let mut transport_builder = TransportBuilder::new(conn_pool);

        if let Some(ca) = elasticsearch_ca {
            let mut buf = Vec::new();
            File::open(ca).await?.read_to_end(&mut buf).await?;
            let cert = Certificate::from_pem(&buf)?;
            transport_builder =
                transport_builder.cert_validation(CertificateValidation::Full(cert));
        }

        let transport = transport_builder.build()?;

        let client = Elasticsearch::new(transport);
        Ok(ElasticsearchClient { client })
    }

    pub async fn health(&self) -> bool {
        let res = self
            .client
            .cluster()
            .health(ClusterHealthParts::None)
            .send()
            .await;

        match res {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(r) => match r.get::<String>("status".to_string()) {
                    Some(r) => {
                        if r != "yellow" && r != "green" {
                            error!("cluster state is {}", r);
                            false
                        } else {
                            true
                        }
                    }
                    None => {
                        error!("bad response: no status field");
                        false
                    }
                },
                Err(e) => {
                    error!("bad response: json parse failed: {}", e);
                    false
                }
            },
            Err(e) => {
                error!("elasticsearch health status error: {}", e);
                false
            }
        }
    }

    pub async fn save_log_messages(
        &self,
        index: String,
        messages: Vec<LogMessage>,
    ) -> anyhow::Result<()> {
        let body: Vec<BulkOperation<_>> = messages
            .into_iter()
            .map(|msg| BulkOperation::create(msg.request_id, msg).into())
            .collect();

        match self
            .client
            .bulk(BulkParts::Index(index.as_str()))
            .body(body)
            .send()
            .await
        {
            Ok(resp) => {
                let status_code = resp.status_code();
                if status_code.is_success() {
                    let response_body = resp.json::<Value>().await?;
                    let successful = response_body["errors"].as_bool().unwrap() == false;
                    if successful {
                        Ok(())
                    } else {
                        error!("elastic save error: {:?}", response_body);
                        Err(anyhow!("couldn't save to elastic: error"))
                    }
                } else {
                    Err(anyhow!("bad response: {}", status_code))
                }
            }
            Err(e) => Err(anyhow!("Error saving to elasticsearch: {}", e)),
        }
    }
}
