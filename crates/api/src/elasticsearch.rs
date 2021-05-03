use elasticsearch::{
    cert::{Certificate, CertificateValidation},
    cluster::ClusterHealthParts,
    http::transport::{SingleNodeConnectionPool, TransportBuilder},
    Elasticsearch, GetParts, SearchParts,
};
use exogress_common::entities::{AccountUniqueId, Ulid};
use serde_json::{json, Value};
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

    pub(crate) async fn find_request_by_request_id(
        &self,
        account_unique_id: &AccountUniqueId,
        request_id: &Ulid,
    ) -> Result<Value, elasticsearch::Error> {
        let ds = format!("account-{}", account_unique_id.to_string().to_lowercase());
        self.client
            .search(SearchParts::Index(&[&ds]))
            .body(json!({
                "query": {
                    "match": {
                        "request_id.keyword": request_id.to_string()
                    }
                }
            }))
            .send()
            .await?
            .json::<Value>()
            .await
    }
}
