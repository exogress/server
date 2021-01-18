use anyhow::anyhow;
use elasticsearch::cert::{Certificate, CertificateValidation};
use elasticsearch::http::transport::{SingleNodeConnectionPool, Transport, TransportBuilder};
use elasticsearch::{BulkOperation, BulkParts, Elasticsearch};
use exogress_server_common::logging::LogMessage;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

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

    pub async fn save_log_messages(&self, messages: &[LogMessage]) -> anyhow::Result<()> {
        let index = "accounts_logs";

        let mut body: Vec<BulkOperation<_>> = vec![];
        for msg in messages {
            let op = BulkOperation::index(msg).into();
            body.push(op);
        }

        match self
            .client
            .bulk(BulkParts::Index(index))
            .body(body)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status_code().is_success() {
                    Ok(())
                } else {
                    Err(anyhow!(
                        "bad response: {}. Body = {}",
                        resp.status_code(),
                        resp.text().await?
                    ))
                }
            }
            Err(e) => Err(anyhow!("Error saving to elasticsearch: {}", e)),
        }
    }
}
