use crate::service::Service;
use exogress_common::entities::SmolStr;
use exogress_server_common::dns_rules;
use std::convert::TryInto;
use tokio::io::AsyncReadExt;

#[derive(Debug, Serialize, Deserialize)]
pub struct Region {
    name: SmolStr,
    lat: f32,
    lon: f32,
    status: dns_rules::LocationStatus,
}

impl Service {
    pub async fn get_regions(&self) -> anyhow::Result<Vec<Region>> {
        let mut file = tokio::fs::File::open(&self.dns_rules_path).await?;
        let mut v = Vec::new();
        file.read_to_end(&mut v).await?;
        let rules = serde_yaml::from_slice::<exogress_server_common::dns_rules::Main>(&v)?;
        Ok(rules
            .locations
            .iter()
            .map(|loc| Region {
                name: loc.name.clone(),
                lat: loc.lat.try_into().unwrap(),
                lon: loc.lon.try_into().unwrap(),
                status: loc.status.clone(),
            })
            .collect())
    }
}
