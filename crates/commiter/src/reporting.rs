use chrono::Timelike;
use core::cmp;
use exogress_server_common::assistant::StatisticsReport;
use itertools::Itertools;
use mongodb::{bson, options::UpdateOptions};
use std::time::Duration;

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

        let collections = db.list_collection_names(None).await;
        info!("collections = {:?}", collections);

        Ok(MongoDbClient { db })
    }

    pub async fn health(&self) -> bool {
        let r =
            tokio::time::timeout(Duration::from_secs(5), self.db.list_collection_names(None)).await;
        match r {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => {
                error!("mongo health error: {}", e);
                false
            }
            Err(_e) => {
                error!("mongo timeout");
                false
            }
        }
    }

    pub async fn register_statistics_report(
        &self,
        report: StatisticsReport,
        gw_hostname: &str,
        gw_location: &str,
    ) -> Result<(), mongodb::error::Error> {
        let usage_counters = self.db.collection::<bson::Document>("usage_counters");
        let accounts = self.db.collection::<bson::Document>("accounts");

        match &report {
            StatisticsReport::Traffic { records } => {
                let grouped = records
                    .iter()
                    .map(|rec| {
                        let start_of_hour = rec
                            .flushed_at
                            .with_minute(0)
                            .unwrap()
                            .with_second(0)
                            .unwrap()
                            .with_nanosecond(0)
                            .unwrap();
                        (
                            (rec.account_unique_id, rec.project_unique_id, start_of_hour),
                            (
                                rec.flushed_at,
                                rec.tunnel_bytes_gw_tx,
                                rec.tunnel_bytes_gw_rx,
                                rec.public_bytes_gw_tx,
                                rec.public_bytes_gw_rx,
                                rec.https_bytes_gw_tx,
                                rec.https_bytes_gw_rx,
                            ),
                        )
                    })
                    .into_grouping_map()
                    .fold_first(
                        |(f, a1, a2, a3, a4, a5, a6), _k, (vf, v1, v2, v3, v4, v5, v6)| {
                            (
                                cmp::max(f, vf),
                                a1 + v1,
                                a2 + v2,
                                a3 + v3,
                                a4 + v4,
                                a5 + v5,
                                a6 + v6,
                            )
                        },
                    );

                for (
                    (account_unique_id, project_unique_id, start_of_hour),
                    (
                        max_time,
                        tunnel_bytes_gw_tx,
                        tunnel_bytes_gw_rx,
                        public_bytes_gw_tx,
                        public_bytes_gw_rx,
                        https_bytes_gw_tx,
                        https_bytes_gw_rx,
                    ),
                ) in grouped
                {
                    let query = bson::doc! {
                        "account_unique_id": account_unique_id.to_string(),
                        "project_unique_id": project_unique_id.to_string(),
                        "gw_hostname": gw_hostname.to_string(),
                        "gw_location": gw_location.to_string(),
                        "start_of_period": start_of_hour,
                    };
                    let op = bson::doc! {
                        "$inc": {
                            "tunnel_bytes_gw_tx": tunnel_bytes_gw_tx,
                            "tunnel_bytes_gw_rx": tunnel_bytes_gw_rx,
                            "public_bytes_gw_tx": public_bytes_gw_tx,
                            "public_bytes_gw_rx": public_bytes_gw_rx,
                            "https_bytes_gw_tx": https_bytes_gw_tx,
                            "https_bytes_gw_rx": https_bytes_gw_rx,
                        }
                    };

                    usage_counters
                        .update_one(
                            query,
                            op,
                            Some(UpdateOptions::builder().upsert(true).build()),
                        )
                        .await?;

                    accounts
                        .update_one(
                            bson::doc! {
                                "unique_id": account_unique_id.to_string(),
                            },
                            bson::doc! {
                                "$set": {
                                     "last_traffic_recorded_at": max_time,
                                }
                            },
                            None,
                        )
                        .await?;
                }
            }
            StatisticsReport::Rules { records } => {
                let grouped = records
                    .iter()
                    .map(|rec| {
                        let start_of_hour = rec
                            .flushed_at
                            .with_minute(0)
                            .unwrap()
                            .with_second(0)
                            .unwrap()
                            .with_nanosecond(0)
                            .unwrap();

                        (
                            (rec.account_unique_id, rec.project_unique_id, start_of_hour),
                            (rec.rules_processed, rec.requests_processed),
                        )
                    })
                    .into_grouping_map()
                    .fold_first(|(a1, a2), _k, (v1, v2)| (a1 + v1, a2 + v2));

                for (
                    (account_unique_id, project_unique_id, start_of_hour),
                    (rules_processed, requests_processed),
                ) in grouped
                {
                    let query = bson::doc! {
                        "account_unique_id": account_unique_id.to_string(),
                        "project_unique_id": project_unique_id.to_string(),
                        "gw_hostname": gw_hostname.to_string(),
                        "gw_location": gw_location.to_string(),
                        "start_of_period": start_of_hour,
                    };
                    let op = bson::doc! {
                        "$inc": {
                            "rules_processed": rules_processed,
                            "requests_processed": requests_processed,
                        }
                    };

                    usage_counters
                        .update_one(
                            query,
                            op,
                            Some(UpdateOptions::builder().upsert(true).build()),
                        )
                        .await?;
                }
            }
            _ => unimplemented!(),
        };
        Ok(())
    }
}
