use crate::mongodb::{Account, Project};
use bson::oid::ObjectId;
use exogress_common::entities::{AccountName, ProjectName};
use std::path::PathBuf;
use typed_builder::TypedBuilder;

pub mod auth;
pub mod cache;
pub mod gw_invalidations;
pub mod health;
pub mod regions;
pub mod requests;

#[derive(TypedBuilder, Clone)]
pub struct Service {
    redis_sessions: crate::redis_sessions_client::RedisSessionsClient,
    redis_assistant: crate::redis_assistant_client::RedisAssistantClient,
    elasticsearch: crate::elasticsearch::ElasticsearchClient,
    mongodb: crate::mongodb::MongoDbClient,
    dns_rules_path: PathBuf,
}

impl Service {
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
}
