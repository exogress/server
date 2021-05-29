use super::Service;
use crate::mongodb::Account;
use exogress_common::{
    access_tokens::{validate_jwt_token, Claims},
    entities::AccessKeyId,
};
use mongodb::bson;

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

    pub async fn find_user_by_session_id(
        &mut self,
        session_id: &str,
    ) -> anyhow::Result<Option<bson::oid::ObjectId>> {
        let maybe_uid = self
            .redis_sessions
            .get_uid_from_session_id(session_id)
            .await?;
        if let Some(uid) = maybe_uid {
            Ok(self.mongodb.get_user_id(uid.as_ref()).await?)
        } else {
            Ok(None)
        }
    }
}
