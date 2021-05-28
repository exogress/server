use crate::service::Service;
use anyhow::bail;
use exogress_common::entities::{AccountUniqueId, RequestId};
use serde_json::Value;

impl Service {
    pub(crate) async fn find_request_by_request_id(
        &self,
        account_unique_id: &AccountUniqueId,
        request_id: &RequestId,
    ) -> anyhow::Result<Option<Value>> {
        let mut res = self
            .elasticsearch
            .find_request_by_request_id(account_unique_id, request_id.as_ref())
            .await?;

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
}
