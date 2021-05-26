use crate::mongodb::{Account, Project};
use anyhow::bail;
use bson::oid::ObjectId;
use exogress_common::{
    access_tokens::{validate_jwt_token, Claims},
    entities::{AccessKeyId, AccountName, AccountUniqueId, ProjectName, SmolStr, Ulid},
};
use exogress_server_common::dns_rules;
use futures::future::join3;
use serde_json::Value;
use std::{convert::TryInto, path::PathBuf};
use tokio::io::AsyncReadExt;
use typed_builder::TypedBuilder;

#[derive(Debug, Serialize, Deserialize)]
pub struct Region {
    name: SmolStr,
    lat: f32,
    lon: f32,
    status: dns_rules::LocationStatus,
}

#[derive(TypedBuilder, Clone)]
pub struct Service {
    redis: crate::redis_client::RedisClient,
    elasticsearch: crate::elasticsearch::ElasticsearchClient,
    mongodb: crate::mongodb::MongoDbClient,
    dns_rules_path: PathBuf,
}

impl Service {
    pub(crate) async fn health(&self) -> bool {
        let (elastic, mongo, redis) = join3(
            self.elasticsearch.health(),
            self.mongodb.health(),
            self.redis.health(),
        )
        .await;

        elastic && mongo && redis
    }
}

impl Service {
    pub(crate) async fn find_account_by_bearer_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<Account>> {
        let insecure_decoded = jsonwebtoken::dangerous_insecure_decode::<Claims>(token)?;
        let access_key_id: AccessKeyId = insecure_decoded.claims.iss.parse()?;

        if let Some(access_token_info) = self
            .mongodb
            .get_info_by_access_key_id(access_key_id)
            .await?
        {
            match validate_jwt_token(
                &access_token_info.secret_access_public_key,
                &access_key_id,
                token,
            ) {
                Ok(_) => {
                    info!("validation pass");
                    return Ok(Some(access_token_info.account));
                }
                Err(e) => {
                    warn!("error validation JWT: {}", e);
                }
            }
        }

        Ok(None)
    }

    pub(crate) async fn find_request_by_request_id(
        &self,
        account_unique_id: &AccountUniqueId,
        request_id: &Ulid,
    ) -> anyhow::Result<Option<Value>> {
        let mut res = self
            .elasticsearch
            .find_request_by_request_id(account_unique_id, request_id)
            .await?;

        error!("res = {:?}", res);

        if let Some(array) = res["hits"].take()["hits"].take().as_array_mut() {
            if let Some(mut first) = array.pop() {
                Ok(Some(first["_source"].take()))
            } else {
                Ok(None)
            }
        } else {
            bail!("hits is not an array")
        }
    }

    pub async fn find_user_by_session_id(
        &mut self,
        session_id: &str,
    ) -> anyhow::Result<Option<bson::oid::ObjectId>> {
        let maybe_uid = self.redis.get_uid_from_session_id(session_id).await?;
        if let Some(uid) = maybe_uid {
            Ok(self.mongodb.get_user_id(uid.as_ref()).await?)
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn find_account(
        &self,
        user_id: ObjectId,
        account_name: &AccountName,
    ) -> anyhow::Result<Option<Account>> {
        self.mongodb
            .get_account_by_user_id_and_account_name(&user_id, &account_name)
            .await
    }

    pub async fn find_project(
        &self,
        account: &Account,
        project_name: &ProjectName,
    ) -> anyhow::Result<Option<Project>> {
        self.mongodb
            .get_project_by_account_id_and_project_name(&account._id, project_name)
            .await
    }

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
