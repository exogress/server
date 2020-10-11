use chrono::TimeZone;
use clickhouse_rs::errors::Error;
use clickhouse_rs::Block;
use exogress_server_common::assistant::TrafficRecord;

#[derive(Clone)]
pub struct Clickhouse {
    pool: clickhouse_rs::Pool,
}

impl Clickhouse {
    pub async fn new(clickhouse_url: &str) -> Result<Self, Error> {
        let ddl = r"
CREATE TABLE IF NOT EXISTS traffic_counters (
    account_name String,
    gw_hostname String,
    gw_location String,
    from_datetime DateTime,
    to_datetime DateTime,
    tunnel_bytes_gw_rx  UInt64,
    tunnel_bytes_gw_tx  UInt64
) Engine=MergeTree() 
PARTITION BY toYYYYMM(from_datetime) 
ORDER BY (from_datetime, account_name)";

        let pool = clickhouse_rs::Pool::new(clickhouse_url);

        let mut client = pool.get_handle().await?;
        client.execute(ddl).await?;

        Ok(Clickhouse { pool })
    }

    pub async fn register_traffic_report(
        &self,
        record: Vec<TrafficRecord>,
        gw_hostname: &str,
        gw_location: &str,
    ) -> Result<(), Error> {
        let block = Block::new()
            .column(
                "account_name",
                record
                    .iter()
                    .map(|rec| rec.account_name.to_string())
                    .collect::<Vec<_>>(),
            )
            .column(
                "gw_hostname",
                record
                    .iter()
                    .map(|_| gw_hostname.to_string())
                    .collect::<Vec<_>>(),
            )
            .column(
                "gw_location",
                record
                    .iter()
                    .map(|_| gw_location.to_string())
                    .collect::<Vec<_>>(),
            )
            .column(
                "from_datetime",
                record
                    .iter()
                    .map(|rec| chrono_tz::Tz::UTC.from_utc_datetime(&rec.from.naive_utc()))
                    .collect::<Vec<_>>(),
            )
            .column(
                "to_datetime",
                record
                    .iter()
                    .map(|rec| chrono_tz::Tz::UTC.from_utc_datetime(&rec.to.naive_utc()))
                    .collect::<Vec<_>>(),
            )
            .column(
                "tunnel_bytes_gw_rx",
                record
                    .iter()
                    .map(|rec| rec.tunnel_bytes_gw_rx)
                    .collect::<Vec<_>>(),
            )
            .column(
                "tunnel_bytes_gw_tx",
                record
                    .iter()
                    .map(|rec| rec.tunnel_bytes_gw_tx)
                    .collect::<Vec<_>>(),
            );
        let mut client = self.pool.get_handle().await?;
        client.insert("traffic_counters", block).await?;
        Ok(())
    }
}
