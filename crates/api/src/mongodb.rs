use anyhow::bail;
use bson::oid::ObjectId;
use exogress_common::entities::{
    AccessKeyId, AccountName, AccountUniqueId, ConfigName, HandlerName, InvalidationGroupName,
    MountPointName, ProjectName,
};
use futures::StreamExt;
use std::time::Duration;

#[derive(Clone)]
pub struct MongoDbClient {
    db: mongodb::Database,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BaseUrl {
    pub domain_id: bson::oid::ObjectId,
    pub mount_point_id: bson::oid::ObjectId,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Domain {
    pub _id: bson::oid::ObjectId,
    pub fqdn: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MountPoint {
    pub _id: bson::oid::ObjectId,
    pub project_id: bson::oid::ObjectId,
    pub name: MountPointName,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Invalidation {
    pub _id: bson::oid::ObjectId,
    pub expired_at: u64,
    pub mount_point_id: bson::oid::ObjectId,
    pub name: InvalidationGroupName,
    pub config_name: Option<ConfigName>,
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

    pub async fn get_mount_point_by_mount_point_name_and_account_id_and_project_name(
        &self,
        account_id: &ObjectId,
        project_name: &ProjectName,
        mount_point_name: &MountPointName,
    ) -> anyhow::Result<Option<MountPoint>> {
        let maybe_project = self
            .get_project_by_account_id_and_project_name(account_id, project_name)
            .await?;

        if let Some(project) = maybe_project {
            let mount_points = self.db.collection::<MountPoint>("mount_points");

            if let Some(mount_point) = mount_points
                .find_one(
                    bson::doc! {
                        "project_id": project._id,
                        "name": mount_point_name.as_str()
                    },
                    None,
                )
                .await?
            {
                return Ok(Some(mount_point));
            }
        };

        Ok(None)
    }

    pub async fn get_invalidation(
        &self,
        mount_point: &MountPoint,
        handler_name: &HandlerName,
        config_name: &Option<ConfigName>,
        invalidation_name: &InvalidationGroupName,
    ) -> anyhow::Result<Option<Invalidation>> {
        let invalidations = self.db.collection::<Invalidation>("invalidations");

        if let Some(invalidation) = invalidations
            .find_one(
                bson::doc! {
                    "mount_point_id": mount_point._id,
                    "handler_name": handler_name.as_str(),
                    "config_name": if let Some(cn) = config_name {
                        bson::Bson::String(cn.to_string())
                    } else {
                        bson::Bson::Null
                    },
                    "name": invalidation_name.as_str(),
                },
                None,
            )
            .await?
        {
            return Ok(Some(invalidation));
        }

        Ok(None)
    }

    pub async fn get_domains(&self, mount_point: &MountPoint) -> anyhow::Result<Vec<Domain>> {
        let domains_collection = self.db.collection::<Domain>("domains");

        let mut domains = domains_collection
            .find(
                bson::doc! {
                    "mount_point_id": mount_point._id,
                },
                None,
            )
            .await?;

        let mut res = vec![];

        while let Some(domain) = domains.next().await {
            res.push(domain?);
        }

        Ok(res)
    }

    pub async fn invalidate_group(&self, invalidation: &Invalidation) -> anyhow::Result<()> {
        let invalidations = self.db.collection::<Invalidation>("invalidations");

        if invalidations
            .find_one_and_update(
                bson::doc! {
                    "_id": invalidation._id,
                },
                bson::doc! {
                    "$set": {
                        "expired_at": chrono::Utc::now().timestamp(),
                    }
                },
                None,
            )
            .await?
            .is_none()
        {
            bail!("invalidation failed to update: not found");
        }

        Ok(())
    }
}
