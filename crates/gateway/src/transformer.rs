use crate::public_hyper_client::MeteredHttpConnector;
use core::mem;
use exogress_common::entities::{
    AccountUniqueId, HandlerName, MountPointName, ProjectName, ProjectUniqueId,
};
use exogress_server_common::transformer::{
    ProcessRequest, ProcessResponse, ProcessedFormatResult, ProcessedFormatSucceeded,
    ProcessingReady,
};
use futures::TryStreamExt;
use http::{header::CONTENT_LENGTH, HeaderValue, Method, Request, Response, StatusCode};
use hyper::{header::CONTENT_TYPE, Body};
use std::{
    convert::{TryFrom, TryInto},
    sync::Arc,
};
use tame_oauth::gcp::ServiceAccountAccess;
use url::Url;

#[derive(Clone)]
pub struct TransformerClient {
    account_unique_id: AccountUniqueId,
    base_url: Url,
    client: hyper::Client<MeteredHttpConnector, hyper::Body>,
    gcs_credentials: Arc<ServiceAccountAccess>,
    gcs_token_storage: Arc<tokio::sync::Mutex<Option<tame_oauth::Token>>>,
    maybe_identity: Option<Vec<u8>>,
}

impl TransformerClient {
    pub fn new(
        account_unique_id: AccountUniqueId,
        base_url: Url,
        gcs_credentials_file: String,
        client: hyper::Client<MeteredHttpConnector, hyper::Body>,
        maybe_identity: Option<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        let gcs_service_account = tame_oauth::gcp::ServiceAccountInfo::deserialize(
            std::fs::read_to_string(gcs_credentials_file)?.as_str(),
        )?;
        let gcs_service_account_access =
            tame_oauth::gcp::ServiceAccountAccess::new(gcs_service_account)?;

        Ok(TransformerClient {
            account_unique_id,
            base_url,
            client,
            gcs_credentials: Arc::new(gcs_service_account_access),
            gcs_token_storage: Arc::new(Default::default()),
            maybe_identity,
        })
    }

    pub async fn request_content(
        &self,
        content_hash: &str,
        content_type: &mime::Mime,
        handler_name: &HandlerName,
        project_name: &ProjectName,
        project_unique_id: &ProjectUniqueId,
        mount_point_name: &MountPointName,
        requested_url: &http::uri::Uri,
    ) -> anyhow::Result<ProcessResponse> {
        let mut url = self.base_url.clone();

        url.path_segments_mut()
            .unwrap()
            .push("int_api")
            .push("v1")
            .push("transformations")
            .push("content");

        let body = ProcessRequest {
            content_type: content_type.essence_str().to_string(),
            content_hash: content_hash.to_string(),
            account_unique_id: self.account_unique_id,
            url: requested_url.to_string(),
            mount_point_name: mount_point_name.clone(),
            project_name: project_name.clone(),
            handler_name: handler_name.clone(),
            project_unique_id: project_unique_id.clone(),
        };

        let json = serde_json::to_string(&body).unwrap();

        let req = hyper::Request::builder()
            .method(Method::POST)
            .uri(url.to_string())
            .body(Body::from(json))
            .unwrap();

        let resp = self.client.request(req).await?;

        if resp.status().is_success() {
            let body = resp
                .into_body()
                .try_fold(Vec::new(), |mut acc, chunk| async move {
                    acc.extend_from_slice(chunk.as_ref());
                    Ok(acc)
                })
                .await?;
            let ready = serde_json::from_slice::<ProcessResponse>(&body)?;
            Ok(ready)
        } else {
            bail!("error code: {}", resp.status());
        }
    }

    pub async fn upload(&self, upload_id: &str, len: usize, body: Body) -> anyhow::Result<()> {
        let content_type = "application/x-www-form-urlencoded".to_string();

        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .unwrap()
            .push("int_api")
            .push("v1")
            .push("transformations")
            .push("uploads")
            .push(upload_id);

        let builder = hyper::Request::builder()
            .method(Method::POST)
            .uri(url.to_string())
            .header(CONTENT_TYPE, content_type)
            .header(CONTENT_LENGTH, HeaderValue::from(len));

        error!("send upload request");

        let req = builder.body(body)?;
        let resp = self.client.request(req).await?;

        error!("request sent res = {:?}", resp);

        if resp.status().is_success() {
            Ok(())
        } else {
            bail!("error uploading content. status code: {}", resp.status());
        }
    }

    pub async fn download_best_processed(
        &self,
        succeeded: ProcessedFormatSucceeded,
        content_type: &str,
        content_hash: &str,
    ) -> anyhow::Result<Option<(hyper::Body, String)>> {
        error!("Best matched content from transformer: {:?}", succeeded);

        let r = self
            .download_format(content_hash, &succeeded, &content_type)
            .await?;

        Ok(r.map(move |r| (r, succeeded.encryption_header)))
    }

    pub async fn find_best_conversion(
        &self,
        ready: &ProcessingReady,
        accept: &typed_headers::Accept,
    ) -> Option<(ProcessedFormatSucceeded, String)> {
        ready
            .formats
            .iter()
            .filter_map(|processed| {
                if let ProcessedFormatResult::Succeeded(suceeded) = &processed.result {
                    Some((suceeded, &processed.content_type))
                } else {
                    None
                }
            })
            .filter(|(processed, _)| processed.compression_ratio > 1.0)
            .filter(|(_succeeded, content_type)| {
                // we do strict match on specific transformed types
                accept
                    .0
                    .iter()
                    .any(|accept| accept.item.essence_str() == content_type.as_str())
            })
            .next()
            .map(|(s, c)| (s.clone(), c.clone()))
    }

    async fn download_format(
        &self,
        content_hash: &str,
        succeeded_conversion: &ProcessedFormatSucceeded,
        content_type: &str,
    ) -> anyhow::Result<Option<hyper::Body>> {
        let token_or_req = self
            .gcs_credentials
            .get_token(&[tame_gcs::Scopes::ReadOnly])?;

        let current_token = self.gcs_token_storage.lock().await.clone();
        let token = match current_token {
            Some(token) if !token.has_expired() => token,
            _ => {
                let new_token = match token_or_req {
                    tame_oauth::gcp::TokenOrRequest::Token(token) => token,
                    tame_oauth::gcp::TokenOrRequest::Request {
                        request,
                        scope_hash,
                        ..
                    } => {
                        let (parts, body) = request.into_parts();
                        let read_body = Body::from(body);
                        let auth_req = http::Request::from_parts(parts, read_body);

                        let mut auth_res = self.client.request(auth_req).await?;

                        let resp_bytes = mem::replace(auth_res.body_mut(), Body::empty())
                            .try_fold(Vec::new(), |mut data, chunk| async move {
                                data.extend_from_slice(&chunk);
                                Ok(data)
                            })
                            .await?;

                        let mut converted_res = Response::new(resp_bytes);

                        *converted_res.headers_mut() = auth_res.headers().clone();
                        *converted_res.status_mut() = auth_res.status();

                        self.gcs_credentials
                            .parse_token_response(scope_hash, converted_res)?
                    }
                };

                *self.gcs_token_storage.lock().await = Some(new_token.clone());

                new_token
            }
        };

        let bucket = succeeded_conversion
            .buckets
            .get(0)
            .ok_or_else(|| anyhow!("empty buckets list"))?;

        let bucket_name = tame_gcs::BucketName::try_from(bucket.name.as_str().to_string())?;
        let path = format!(
            "{}/processed/{}/{}",
            self.account_unique_id, content_hash, content_type
        );

        let object_name = tame_gcs::ObjectName::try_from(path)?;
        let download_req_empty =
            tame_gcs::objects::Object::download(&(&bucket_name, &object_name), None)?;

        let mut req = Request::new(Body::empty());
        *req.headers_mut() = download_req_empty.headers().clone();
        req.headers_mut()
            .insert(http::header::AUTHORIZATION, token.try_into().unwrap());
        *req.uri_mut() = download_req_empty.uri().clone();
        *req.method_mut() = download_req_empty.method().clone();

        let response = self.client.request(req).await?;

        if response.status().is_success() {
            Ok(Some(response.into_body()))
        } else if response.status() == StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            let status = response.status();
            let entire_body = response
                .into_body()
                .try_fold(Vec::new(), |mut data, chunk| async move {
                    data.extend_from_slice(&chunk);
                    Ok(data)
                })
                .await
                .map_err(anyhow::Error::from)
                .and_then(|v| String::from_utf8(v).map_err(anyhow::Error::from));
            bail!(
                "failed to download transformed content. status: {:?}, body: {:?}",
                status,
                entire_body
            );
        }
    }
}
