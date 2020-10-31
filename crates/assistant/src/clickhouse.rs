use chrono::{DateTime, TimeZone, Timelike, Utc};
use clickhouse_rs::errors::Error;
use clickhouse_rs::Block;
use exogress_server_common::assistant::{RulesRecord, StatisticsReport, TrafficRecord};

#[derive(Clone)]
pub struct Clickhouse {
    pool: clickhouse_rs::Pool,
}

impl Clickhouse {
    pub async fn new(clickhouse_url: &str) -> Result<Self, Error> {
        let pool = clickhouse_rs::Pool::new(clickhouse_url);

        let mut client = pool.get_handle().await?;

        let ddl_traffic_counters = r"
CREATE TABLE IF NOT EXISTS counters (
    account_unique_id String,
    gw_hostname String,
    gw_location String,
    start_of_period DateTime,
    tunnel_bytes_gw_rx  UInt64,
    tunnel_bytes_gw_tx  UInt64,
    https_bytes_gw_rx  UInt64,
    https_bytes_gw_tx  UInt64,
    rules_processed  UInt64,
    requests_processed  UInt64
) Engine=SummingMergeTree()
PARTITION BY toYYYYMM(start_of_period) 
PRIMARY KEY account_unique_id
ORDER BY (account_unique_id, start_of_period, gw_hostname, gw_location)";
        client.execute(ddl_traffic_counters).await?;
        // account_unique_id, gw_hostname, gw_location, start_of_period
        Ok(Clickhouse { pool })
    }

    pub async fn register_statistics_report(
        &self,
        report: StatisticsReport,
        gw_hostname: &str,
        gw_location: &str,
    ) -> Result<(), Error> {
        let block = match report {
            StatisticsReport::Traffic { records } => Block::new()
                .column(
                    "account_unique_id",
                    records
                        .iter()
                        .map(|rec| rec.account_unique_id.to_string())
                        .collect::<Vec<_>>(),
                )
                .column(
                    "gw_hostname",
                    records
                        .iter()
                        .map(|_| gw_hostname.to_string())
                        .collect::<Vec<_>>(),
                )
                .column(
                    "gw_location",
                    records
                        .iter()
                        .map(|_| gw_location.to_string())
                        .collect::<Vec<_>>(),
                )
                .column(
                    "start_of_period",
                    records
                        .iter()
                        .map(|rec| {
                            chrono_tz::Tz::UTC
                                .from_utc_datetime(&to_period_start(rec.flushed_at).naive_utc())
                        })
                        .collect::<Vec<_>>(),
                )
                .column(
                    "tunnel_bytes_gw_rx",
                    records
                        .iter()
                        .map(|rec| rec.tunnel_bytes_gw_rx)
                        .collect::<Vec<_>>(),
                )
                .column(
                    "tunnel_bytes_gw_tx",
                    records
                        .iter()
                        .map(|rec| rec.tunnel_bytes_gw_tx)
                        .collect::<Vec<_>>(),
                )
                .column(
                    "https_bytes_gw_rx",
                    records
                        .iter()
                        .map(|rec| rec.https_bytes_gw_rx)
                        .collect::<Vec<_>>(),
                )
                .column(
                    "https_bytes_gw_tx",
                    records
                        .iter()
                        .map(|rec| rec.https_bytes_gw_tx)
                        .collect::<Vec<_>>(),
                ),
            StatisticsReport::Rules { records } => Block::new()
                .column(
                    "account_unique_id",
                    records
                        .iter()
                        .map(|rec| rec.account_unique_id.to_string())
                        .collect::<Vec<_>>(),
                )
                .column(
                    "gw_hostname",
                    records
                        .iter()
                        .map(|_| gw_hostname.to_string())
                        .collect::<Vec<_>>(),
                )
                .column(
                    "gw_location",
                    records
                        .iter()
                        .map(|_| gw_location.to_string())
                        .collect::<Vec<_>>(),
                )
                .column(
                    "start_of_period",
                    records
                        .iter()
                        .map(|rec| {
                            chrono_tz::Tz::UTC
                                .from_utc_datetime(&to_period_start(rec.flushed_at).naive_utc())
                        })
                        .collect::<Vec<_>>(),
                )
                .column(
                    "rules_processed",
                    records
                        .iter()
                        .map(|rec| rec.rules_processed)
                        .collect::<Vec<_>>(),
                )
                .column(
                    "requests_processed",
                    records
                        .iter()
                        .map(|rec| rec.requests_processed)
                        .collect::<Vec<_>>(),
                ),
            _ => unimplemented!(),
        };

        let mut client = self.pool.get_handle().await?;
        client.insert("counters", block).await?;
        Ok(())
    }
}

fn to_period_start(dt: DateTime<Utc>) -> DateTime<Utc> {
    dt.with_minute(0)
        .unwrap()
        .with_second(0)
        .unwrap()
        .with_nanosecond(0)
        .unwrap()
}
