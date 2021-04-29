use bson::oid::ObjectId;
use exogress_common::entities::{AccessKeyId, AccountName, AccountUniqueId, ProjectName};
use std::time::Duration;

#[derive(Clone)]
pub struct MongoDbClient {
    db: mongodb::Database,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    pub _id: bson::oid::ObjectId,
    pub name: AccountName,
    pub unique_id: AccountUniqueId,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Project {
    pub _id: bson::oid::ObjectId,
    pub name: AccountName,
    pub unique_id: AccountUniqueId,
}

#[derive(Serialize, Deserialize, Debug)]
struct AccessToken {
    pub _id: bson::oid::ObjectId,
    pub account_id: bson::oid::ObjectId,
    pub secret_access_public_key: String,
}

#[derive(Debug)]
pub struct AccessTokenInfo {
    pub account: Account,
    pub secret_access_public_key: String,
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

    pub async fn get_user_id(&self, uid: &str) -> anyhow::Result<Option<ObjectId>> {
        let users = self.db.collection::<bson::Document>("users");

        if let Some(user) = users
            .find_one(
                bson::doc! {
                    "auth0_uid": uid
                },
                None,
            )
            .await?
        {
            Ok(Some(user.get_object_id("_id").unwrap().clone()))
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn get_info_by_access_key_id(
        &self,
        access_key_id: AccessKeyId,
    ) -> anyhow::Result<Option<AccessTokenInfo>> {
        let access_tokens = self.db.collection::<AccessToken>("access_tokens");
        let accounts = self.db.collection::<Account>("accounts");

        if let Some(access_token) = access_tokens
            .find_one(
                bson::doc! {
                    "access_key_id": access_key_id.to_string()
                },
                None,
            )
            .await?
        {
            if let Some(account) = accounts
                .find_one(
                    bson::doc! {
                        "_id": access_token.account_id
                    },
                    None,
                )
                .await?
            {
                let resp = AccessTokenInfo {
                    account,
                    secret_access_public_key: access_token.secret_access_public_key,
                };
                Ok(Some(resp))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub async fn get_account_by_user_id_and_account_name(
        &self,
        user_id: &bson::oid::ObjectId,
        account_name: &AccountName,
    ) -> anyhow::Result<Option<Account>> {
        let account_memberships = self.db.collection::<bson::Document>("account_memberships");
        let accounts = self.db.collection::<Account>("accounts");

        if let Some(account) = accounts
            .find_one(
                bson::doc! {
                    "name": account_name.as_str()
                },
                None,
            )
            .await?
        {
            if account_memberships
                .find_one(
                    bson::doc! {
                        "account_id": &account._id,
                        "user_id": user_id
                    },
                    None,
                )
                .await?
                .is_some()
            {
                // account belongs to the user
                return Ok(Some(account));
            }
        }

        Ok(None)
    }

    pub async fn get_project_by_account_id_and_project_name(
        &self,
        account_id: &ObjectId,
        project_name: &ProjectName,
    ) -> anyhow::Result<Option<Project>> {
        let projects = self.db.collection::<Project>("projects");

        if let Some(project) = projects
            .find_one(
                bson::doc! {
                    "account_id": account_id,
                    "name": project_name.as_str()
                },
                None,
            )
            .await?
        {
            Ok(Some(project))
        } else {
            Ok(None)
        }
    }
}
