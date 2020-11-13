use exogress_server_common::assistant::StatisticsReport;

#[derive(Clone)]
pub struct MongoDbClient {
    db: mongodb::Database,
}

impl MongoDbClient {
    pub async fn new(url: &str, db: &str) -> Result<Self, anyhow::Error> {
        let mongodb_client_options = mongodb::options::ClientOptions::parse(&url)
            .await
            .expect("mongodb init error");
        let mongodb_client = mongodb::Client::with_options(mongodb_client_options)?;

        let db = mongodb_client.database(db);

        Ok(MongoDbClient { db })
    }

    pub async fn register_statistics_report(
        &self,
        report: StatisticsReport,
        gw_hostname: &str,
        gw_location: &str,
    ) -> Result<(), mongodb::error::Error> {
        let collection = self.db.collection("usage_counters");

        let datas = match report {
            StatisticsReport::Traffic { records } => records
                .iter()
                .map(|rec| {
                    bson::doc! {
                        "account_unique_id": rec.account_unique_id.to_string(),
                        "gw_hostname": gw_hostname,
                        "gw_location": gw_location,
                        "start_of_period": rec.flushed_at,
                        "tunnel_bytes_gw_rx": rec.tunnel_bytes_gw_rx,
                        "tunnel_bytes_gw_tx": rec.tunnel_bytes_gw_tx,
                        "https_bytes_gw_rx": rec.https_bytes_gw_rx,
                        "https_bytes_gw_tx": rec.https_bytes_gw_tx
                    }
                })
                .collect::<Vec<_>>(),
            StatisticsReport::Rules { records } => records
                .iter()
                .map(|rec| {
                    bson::doc! {
                        "account_unique_id": rec.account_unique_id.to_string(),
                        "gw_hostname": gw_hostname,
                        "gw_location": gw_location,
                        "start_of_period": rec.flushed_at,
                        "rules_processed": rec.rules_processed,
                        "requests_processed": rec.requests_processed
                    }
                })
                .collect::<Vec<_>>(),
            _ => unimplemented!(),
        };

        collection.insert_many(datas, None).await?;

        Ok(())
    }
}
