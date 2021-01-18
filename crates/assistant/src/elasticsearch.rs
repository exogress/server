use anyhow::anyhow;
use elasticsearch::http::transport::Transport;
use elasticsearch::{BulkOperation, BulkParts, Elasticsearch};
use exogress_server_common::logging::LogMessage;

#[derive(Clone)]
pub struct ElasticsearchClient {
    client: Elasticsearch,
}

impl ElasticsearchClient {
    pub fn new(url: &str) -> anyhow::Result<Self> {
        let transport = Transport::single_node(url)?;
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
