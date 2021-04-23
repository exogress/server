use crate::http_serve::{
    helpers::{clone_response_through_tempfile, ClonedResponse},
    identifier::RequestProcessingIdentifier,
    RequestsProcessor, ResolvedHandler,
};
use byte_unit::Byte;
use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashSet;
use etag::EntityTag;
use exogress_common::entities::AccountUniqueId;
use exogress_server_common::crypto;
use futures::{future::Either, Future, TryStreamExt};
use hashbrown::HashSet;
use http::{
    header::{
        HeaderName, ACCEPT, ACCEPT_ENCODING, CONTENT_LENGTH, ETAG, IF_MODIFIED_SINCE,
        IF_NONE_MATCH, LAST_MODIFIED, VARY,
    },
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode,
};
use hyper::Body;
use ledb::Primary;
use pin_utils::pin_mut;
use sha2::Digest;
use sodiumoxide::crypto::secretstream::{xchacha20poly1305, Header};
use std::{
    collections::BTreeSet,
    convert::TryInto,
    io,
    io::Cursor,
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time::sleep;
use typed_headers::HeaderMapExt;

#[derive(Clone)]
pub struct Cache {
    ledb: Arc<parking_lot::RwLock<ledb::Storage>>,
    cache_files_dir: Arc<PathBuf>,
    in_flights: Arc<DashSet<(AccountUniqueId, String)>>,
    space_used: Arc<AtomicU32>,
    max_allowed_size: Byte,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Meta {
    #[serde(with = "http_serde::header_map")]
    headers: http::HeaderMap,
    #[serde(with = "http_serde::status_code")]
    status: http::StatusCode,
}

#[derive(Debug, Clone, Copy)]
pub struct HandlerChecksum(u64);

impl From<u64> for HandlerChecksum {
    fn from(num: u64) -> Self {
        HandlerChecksum(num)
    }
}

impl HandlerChecksum {
    pub fn into_inner(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ledb::Document)]
pub struct CacheItem {
    #[document(primary)]
    id: Option<Primary>,
    #[document(index)]
    account_unique_id: AccountUniqueId,
    #[document(index)]
    request_hash: String,
    #[document(index)]
    vary: String,
    #[document(index)]
    vary_hash: String,
    body_encryption_header: String,
    meta_encryption_header: String,
    original_file_size: u32,
    file_size: u64,
    #[document(index)]
    expires_at: u32,
    #[document(index)]
    last_used_at: u64,
    meta: String,
    etag: Option<String>,
    is_weak_etag: Option<bool>,
    last_modified: Option<u32>,
    used_times: u32,
    content_hash: String,
}

impl Cache {
    pub async fn new(cache_dir: PathBuf, max_size: Byte) -> Result<Cache, anyhow::Error> {
        let cache_dir = tokio::fs::canonicalize(&cache_dir).await?;

        info!(
            "use cache-dir: {:?} with max size: {}",
            cache_dir,
            max_size.get_appropriate_unit(true)
        );

        let mut ledb_db_path = cache_dir.clone();
        ledb_db_path.push("db");

        tokio::fs::create_dir_all(&ledb_db_path).await?;
        info!("ledb path: {:?}", ledb_db_path);

        let mut cache_files_dir = cache_dir.clone();
        cache_files_dir.push("files");

        tokio::fs::create_dir_all(&cache_files_dir).await?;

        info!("Use ledb at {}", ledb_db_path.as_os_str().to_str().unwrap());

        let ledb = ledb::Storage::new(&ledb_db_path, ledb::Options::default())
            .map_err(|e| anyhow!("{}", e))?;

        let files_collection = ledb.collection("files").unwrap();

        ledb::query!(index for files_collection
            id int,
            account_unique_id str,
            request_hash str,
            vary str,
            vary_hash str,
            expires_at int,
            last_used_at int,
        )
        .map_err(|e| anyhow!("{}", e))?;

        let bytes_used = ledb::query!(
            find CacheItem in files_collection
        )
        .map_err(|e| anyhow!("{}", e))?
        .try_fold(0, |acc, r| r.map(|item| acc + item.original_file_size))
        .map_err(|e| anyhow!("{}", e))?;

        let space_used = Arc::new(AtomicU32::from(bytes_used));

        let cache = Cache {
            ledb: Arc::new(parking_lot::RwLock::new(ledb)),
            cache_files_dir: Arc::new(cache_files_dir),
            in_flights: Arc::new(Default::default()),
            space_used,
            max_allowed_size: max_size,
        };

        tokio::spawn({
            shadow_clone!(cache);

            async move {
                loop {
                    match cache.delete_some_expired(10).await {
                        Ok(num_deleted) if num_deleted >= 10 => continue,
                        Err(e) => {
                            error!("error deleting expired items: {}", e);
                        }
                        _ => {}
                    }
                    sleep(Duration::from_secs(5)).await;
                }
            }
        });

        Ok(cache)
    }

    /// Path to the file
    fn storage_path(
        &self,
        account_unique_id: &AccountUniqueId,
        file_name: &str,
        vary: &str,
    ) -> PathBuf {
        let mut path = (*self.cache_files_dir).clone();
        path.push(account_unique_id.to_string());
        let first = file_name[..2].to_string();
        let second = file_name[2..4].to_string();
        let last = file_name[4..].to_string();
        path.push(first);
        path.push(second);
        path.push(format!("{}-{}", last, vary));
        path
    }

    async fn delete_evicted_files(&self, evicted_files: Vec<CacheItem>) -> anyhow::Result<()> {
        for evicted in evicted_files {
            info!("evict file {:?} from cache", evicted);
            {
                let ledb = self.ledb.write();
                let files_collection = ledb.collection("files").unwrap();

                ledb::query!(
                    remove from files_collection
                    where
                        account_unique_id == evicted.account_unique_id.to_string() &&
                        request_hash == evicted.request_hash.as_str() &&
                        vary == evicted.vary.as_str() &&
                        vary_hash == evicted.vary_hash.as_str()
                )
                .map_err(|e| anyhow!("{}", e))?;

                self.space_used
                    .fetch_sub(evicted.original_file_size, Ordering::Relaxed);
            }

            let mut storage_path = self.storage_path(
                &evicted.account_unique_id,
                evicted.request_hash.as_str(),
                evicted.vary.as_str(),
            );

            let _r = tokio::fs::remove_file(&storage_path).await;
            // Use remove_dir here, so that the command will fail if there are some files in the dir left
            storage_path.pop();
            let _ = tokio::fs::remove_dir(&storage_path).await;
            storage_path.pop();
            let _ = tokio::fs::remove_dir(&storage_path).await;
            storage_path.pop();
            let _ = tokio::fs::remove_dir(&storage_path).await;
        }

        Ok(())
    }

    async fn delete_some_expired(&self, limit: usize) -> anyhow::Result<usize> {
        let now = Utc::now().timestamp();

        let evicted_files: Vec<_> = {
            let ledb = self.ledb.read();
            let files_collection = ledb.collection("files").unwrap();

            ledb::query!(
                find CacheItem in files_collection where expires_at < now
            )
            .map_err(|e| anyhow!("{}", e))?
            .take(limit)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("{}", e))?
        };

        let num_evicted_files = evicted_files.len();

        if num_evicted_files > 0 {
            info!("evicted expired files globally = {:?}", evicted_files);

            self.delete_evicted_files(evicted_files).await?;
        }

        Ok(num_evicted_files)
    }

    async fn delete_some_expired_from_account(
        &self,
        account_unique_id: &AccountUniqueId,
        limit: usize,
    ) -> anyhow::Result<usize> {
        let now = Utc::now().timestamp();

        let evicted_files: Vec<_> = {
            let ledb = self.ledb.read();
            let files_collection = ledb.collection("files").unwrap();

            ledb::query!(
                find CacheItem in files_collection where expires_at < now && account_unique_id == account_unique_id.to_string()
            )
                .map_err(|e| anyhow!("{}", e))?
                .take(limit)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("{}", e))?
        };

        let num_evicted_files = evicted_files.len();

        if num_evicted_files > 0 {
            self.delete_evicted_files(evicted_files).await?;
        }

        Ok(num_evicted_files)
    }

    /// Delete files which were accessed the longest time ago
    async fn delete_most_unused(
        &self,
        account_unique_id: &AccountUniqueId,
    ) -> anyhow::Result<usize> {
        let evicted_files: Vec<_> = {
            let ledb = self.ledb.read();

            let files_collection = ledb.collection("files").unwrap();

            ledb::query!(
                find CacheItem in files_collection
                where account_unique_id == account_unique_id.to_string()
                order by last_used_at
            )
            .map_err(|e| anyhow!("{}", e))?
            .take(1)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("{}", e))?
        };

        let num_evicted_files = evicted_files.len();

        if num_evicted_files > 0 {
            self.delete_evicted_files(evicted_files).await?;
        }

        Ok(num_evicted_files)
    }

    async fn get_account_used(&self, account_unique_id: &AccountUniqueId) -> anyhow::Result<Byte> {
        let space_used = {
            let ledb = self.ledb.read();
            let files_collection = ledb.collection("files").unwrap();

            ledb::query!(
                find CacheItem in files_collection where account_unique_id == account_unique_id.to_string()
            )
                .map_err(|e| anyhow!("{}", e))?
                .try_fold(0, |acc, r| {
                    r.map(|item| {
                        acc + item.original_file_size
                    })
                })
                .map_err(|e| anyhow!("{}", e))?
        };

        let bytes_used = Byte::from_bytes(space_used.into());

        Ok(bytes_used)
    }

    fn get_overall_used(&self) -> Byte {
        let space_used = self.space_used.load(Ordering::Relaxed);
        crate::statistics::EDGE_CACHE_SIZE.set(space_used as f64);
        Byte::from_bytes(space_used.into())
    }

    fn vary_hash(vary_headers_ordered_list: &BTreeSet<String>, req_headers: &HeaderMap) -> String {
        let mut hashsum = sha2::Sha224::default();

        for vary_by_header_name in vary_headers_ordered_list {
            let header_value = req_headers
                // TODO: make sure we can remove to_lowercase!
                .get(vary_by_header_name.to_lowercase())
                .map(|h| h.to_str().unwrap())
                .unwrap_or_default();
            hashsum.update(header_value);
        }

        bs58::encode(hashsum.finalize()).into_string()
    }

    async fn add_file_without_checks(
        &self,
        account_unique_id: &AccountUniqueId,
        req_headers: &HeaderMap,
        res_headers: &mut HeaderMap,
        status: StatusCode,
        body_encryption_header: Header,
        content_hash: String,
        valid_till: DateTime<Utc>,
        original_file_size: u32,
        temp_file_path: PathBuf,
        file_name: &str,
        xchacha20poly1305_secret_key: &xchacha20poly1305::Key,
    ) -> anyhow::Result<()> {
        let file_size = tokio::fs::metadata(&temp_file_path).await?.len();

        let mut vary_header_names_set = res_headers
            .get(VARY)
            .map(|s| {
                s.to_str()
                    .unwrap()
                    .split(", ")
                    .map(|s| HeaderName::from_str(s).unwrap())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        vary_header_names_set.insert(ACCEPT_ENCODING);
        vary_header_names_set.insert(ACCEPT);

        let vary_headers_ordered_list: BTreeSet<_> = vary_header_names_set
            .into_iter()
            .map(|h| h.to_string())
            .collect();

        let vary_json = serde_json::to_string(&vary_headers_ordered_list).unwrap();
        let vary_hash = Self::vary_hash(&vary_headers_ordered_list, req_headers);

        if !res_headers.contains_key(CONTENT_LENGTH) {
            res_headers.insert(CONTENT_LENGTH, HeaderValue::from(original_file_size));
        }

        if !res_headers.contains_key(LAST_MODIFIED) {
            res_headers.insert(LAST_MODIFIED, Utc::now().to_rfc2822().parse().unwrap());
        }

        if !res_headers.contains_key(ETAG) {
            res_headers.insert(
                ETAG,
                EntityTag::from_hash(content_hash.as_ref())
                    .to_string()
                    .parse()
                    .unwrap(),
            );
        }

        let meta = Meta {
            headers: res_headers.clone(),
            status: status.clone(),
        };

        let meta_json = serde_json::to_vec(&meta).expect("Serialization should never fail");

        let meta_json_stream = futures::stream::once(async { Ok::<_, io::Error>(meta_json) });

        pin_mut!(meta_json_stream);

        let (encrypted_stream, meta_encryption_header) =
            crypto::encrypt_stream(meta_json_stream, xchacha20poly1305_secret_key)?;

        let encrypted_meta_json = encrypted_stream
            .try_fold(Vec::new(), |mut acc, (item, _)| {
                acc.extend_from_slice(&item);
                futures::future::ok(acc)
            })
            .await?;

        let etag: Option<EntityTag> = res_headers
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        let last_modified = res_headers.get(LAST_MODIFIED).and_then(|date| {
            Some(
                DateTime::parse_from_rfc2822(date.to_str().ok()?)
                    .ok()?
                    .timestamp(),
            )
        });

        {
            let ledb = self.ledb.write();
            let files_collection = ledb.collection("files").unwrap();

            let used_size_by_existing_documents = ledb::query!(
                find CacheItem in files_collection
                where
                    request_hash == file_name &&
                    account_unique_id == account_unique_id.to_string() &&
                    vary == vary_json.as_str() &&
                    vary_hash == vary_hash.as_str()
            )
            .map_err(|e| anyhow!("{}", e))?
            .try_fold(0, |acc, r| r.map(|item| acc + item.original_file_size))
            .map_err(|e| anyhow!("{}", e))?;

            ledb::query!(
                remove from files_collection
                where
                    request_hash == file_name &&
                    account_unique_id == account_unique_id.to_string() &&
                    vary == vary_json.as_str() &&
                    vary_hash == vary_hash.as_str()
            )
            .map_err(|e| anyhow!("{}", e))?;

            if used_size_by_existing_documents > 0 {
                self.space_used
                    .fetch_sub(used_size_by_existing_documents, Ordering::Relaxed);
            }

            files_collection
                .insert(&CacheItem {
                    id: None,
                    account_unique_id: account_unique_id.clone(),
                    request_hash: file_name.to_string(),
                    vary: vary_json,
                    vary_hash: vary_hash.to_string(),
                    body_encryption_header: base64::encode(body_encryption_header.as_ref()),
                    meta_encryption_header: base64::encode(meta_encryption_header.as_ref()),
                    original_file_size,
                    file_size,
                    expires_at: valid_till.timestamp().try_into().unwrap(),
                    last_used_at: Utc::now().timestamp().try_into().unwrap(),
                    meta: base64::encode(encrypted_meta_json),
                    etag: etag.as_ref().map(|e| e.tag().to_string()),
                    is_weak_etag: etag.as_ref().map(|e| e.weak),
                    last_modified: last_modified.map(|lm| lm.try_into().unwrap()),
                    used_times: 0,
                    content_hash,
                })
                .map_err(|e| anyhow!("{}", e))?;

            self.space_used
                .fetch_add(original_file_size, Ordering::Relaxed);
        }

        let storage_path = self.storage_path(account_unique_id, file_name, vary_hash.as_ref());
        let mut parent_dir = storage_path.clone();
        parent_dir.pop();

        tokio::fs::create_dir_all(&parent_dir).await?;

        tokio::fs::copy(temp_file_path, storage_path).await?;

        crate::statistics::EDGE_CACHE_REQUESTS_SAVED_BYTES.inc_by(original_file_size.into());

        Ok(())
    }

    async fn mark_lru_used(&self, file_id: Primary) -> anyhow::Result<()> {
        let ledb = self.ledb.write();
        let files_collection = ledb.collection("files").unwrap();

        ledb::query!(
            update in files_collection
            modify used_times += 1, last_used_at = Utc::now().timestamp()
            where id == i64::from(file_id)
        )
        .map_err(|e| anyhow!("{}", e))?;

        Ok(())
    }

    pub fn is_enough_space(&self) -> bool {
        self.get_overall_used() < self.max_allowed_size
    }

    pub async fn save_content_from_temp_file(
        &self,
        processing_identifier: RequestProcessingIdentifier,
        account_unique_id: &AccountUniqueId,
        req_headers: &HeaderMap,
        res_headers: &mut HeaderMap,
        status: StatusCode,
        original_file_size: u32,
        encryption_header: Header,
        content_hash: String,
        max_account_cache_size: Byte,
        valid_till: DateTime<Utc>,
        xchacha20poly1305_secret_key: &xchacha20poly1305::Key,
        temp_file_path: PathBuf,
    ) -> anyhow::Result<()> {
        let file_name = processing_identifier.to_string();

        let key = (account_unique_id.clone(), file_name.clone());

        if self.in_flights.insert(key.clone()) {
            let r = async move {
                let mut account_used = self.get_account_used(account_unique_id).await?;

                loop {
                    if account_used <= max_account_cache_size {
                        break;
                    }

                    let num_deleted = self
                        .delete_some_expired_from_account(account_unique_id, 10)
                        .await?;

                    if num_deleted == 0 {
                        break;
                    }

                    account_used = self.get_account_used(account_unique_id).await?;
                }

                loop {
                    if account_used <= max_account_cache_size {
                        break;
                    }

                    let num_deleted = self.delete_most_unused(account_unique_id).await?;

                    if num_deleted == 0 {
                        return Err(anyhow!("could not free-up space"));
                    }

                    account_used = self.get_account_used(account_unique_id).await?;
                }

                error!("Will add without checks!");

                self.add_file_without_checks(
                    account_unique_id,
                    req_headers,
                    res_headers,
                    status,
                    encryption_header,
                    content_hash,
                    valid_till,
                    original_file_size,
                    temp_file_path,
                    file_name.as_str(),
                    xchacha20poly1305_secret_key,
                )
                .await?;

                Ok(())
            }
            .await;

            self.in_flights.remove(&key);

            r
        } else {
            error!("Will not save since another saving is in progress");
            Ok(())
        }
    }

    pub async fn serve_from_cache(
        &self,
        requests_processor: &RequestsProcessor,
        handler: &ResolvedHandler,
        processing_identifier: &RequestProcessingIdentifier,
        req: &Request<Body>,
    ) -> anyhow::Result<Option<CacheResponse>> {
        if handler.resolved_variant.is_cache_enabled() != Some(true) {
            return Ok(None);
        }

        if req.method() != &Method::GET && req.method() != &Method::HEAD {
            return Ok(None);
        }

        let account_unique_id = &requests_processor.account_unique_id;
        let xchacha20poly1305_secret_key = &requests_processor.xchacha20poly1305_secret_key;
        let request_headers = req.headers();

        let file_name = processing_identifier.to_string();

        let maybe_variation = {
            let ledb = self.ledb.read();
            let files_collection = ledb.collection("files").unwrap();

            ledb::query!(
                find CacheItem in files_collection
                where request_hash == file_name.as_str() && account_unique_id == account_unique_id.to_string()
            )
                .map_err(|e| anyhow!("{}", e))?
                .filter(|row_result| {
                    if let Ok(row) = row_result.as_ref().map_err(|e| anyhow!("{}", e)) {
                        let vary_json = &row.vary;
                        let stored_vary_hash = &row.vary_hash;

                        let vary_headers_ordered_list: BTreeSet<String> =
                            if let Ok(r) = serde_json::from_str(&vary_json) {
                                r
                            } else {
                                return false;
                            };

                        let vary_hash = Self::vary_hash(&vary_headers_ordered_list, request_headers);

                        if stored_vary_hash != &vary_hash {
                            // vary hash doesn't match
                            return false;
                        };

                        true
                    } else {
                        // return true to later fail the whole function
                        true
                    }
                })
                .next()
        };

        if let Some(variation_result) = maybe_variation {
            let variation: CacheItem = variation_result.map_err(|e| anyhow!("{}", e))?;

            // at this point we are sure that vary header match

            let id = variation
                .id
                .ok_or_else(|| anyhow!("no id field in retrieved document"))?;
            let original_file_size = variation.original_file_size;
            let etag = variation.etag;
            let is_weak_etag = variation.is_weak_etag;
            let last_modified = variation.last_modified;

            let expires_at = Utc.timestamp(variation.expires_at.into(), 0);
            let body_encryption_header = sodiumoxide::crypto::secretstream::Header::from_slice(
                &base64::decode(variation.body_encryption_header)?,
            )
            .ok_or_else(|| anyhow!("failed to read encryption header"))?;
            let meta_encryption_header = sodiumoxide::crypto::secretstream::Header::from_slice(
                &base64::decode(variation.meta_encryption_header)?,
            )
            .ok_or_else(|| anyhow!("failed to read encryption header"))?;

            let dec_stream = crypto::decrypt_reader(
                Cursor::new(base64::decode(variation.meta)?),
                &xchacha20poly1305_secret_key,
                &meta_encryption_header,
            )?;

            let decrypted = dec_stream
                .try_fold(Vec::new(), |mut acc, item| {
                    acc.extend_from_slice(item.as_ref());
                    futures::future::ok(acc)
                })
                .await?;

            let meta = serde_json::from_slice::<Meta>(decrypted.as_ref())?;

            let maybe_stored_etag = match (is_weak_etag, etag) {
                (Some(true), Some(tag)) => Some(EntityTag::weak(&tag)),
                (Some(false), Some(tag)) => Some(EntityTag::strong(&tag)),
                _ => None,
            };
            let maybe_stored_last_modified = last_modified.map(|lm| Utc.timestamp(lm.into(), 0));

            let now = Utc::now();
            if expires_at < now {
                return Ok(None);
            }

            self.mark_lru_used(id).await?;

            error!("request_headers = {:?}", request_headers);

            let req_if_none_match: Vec<EntityTag> = request_headers
                .get_all(IF_NONE_MATCH)
                .iter()
                .filter_map(|v| v.to_str().ok().and_then(|r| r.parse().ok()))
                .collect();

            error!("req_if_none_match = {:?}", req_if_none_match);

            let req_last_modified = request_headers
                .get(IF_MODIFIED_SINCE)
                .and_then(|date| Some(DateTime::parse_from_rfc2822(date.to_str().ok()?).ok()?));

            let mut conditional_response_matches = false;
            if !req_if_none_match.is_empty() {
                if let Some(stored_etag) = maybe_stored_etag {
                    if req_if_none_match
                        .iter()
                        .any(|provided_etag| stored_etag.weak_eq(provided_etag))
                    {
                        conditional_response_matches = true;
                    }
                }
            } else {
                if let (Some(stored_cached_last_modified), Some(if_modified_since)) =
                    (maybe_stored_last_modified, req_last_modified)
                {
                    // If user provided if-modified-since header, which is equal or in the future
                    // compared to our cache - respond with not-modified
                    if if_modified_since >= stored_cached_last_modified {
                        info!("if-modified-since matches the cached version - send not-modified");
                        conditional_response_matches = true;
                    }
                }
            }

            let storage_path = self.storage_path(
                account_unique_id,
                file_name.as_ref(),
                variation.vary_hash.as_str(),
            );

            let reader = tokio::fs::File::open(&storage_path).await?;

            let body = hyper::Body::wrap_stream(crypto::decrypt_reader(
                reader,
                xchacha20poly1305_secret_key,
                &body_encryption_header,
            )?);

            let mut resp = Response::new(body);
            *resp.status_mut() = meta.status;
            *resp.headers_mut() = meta.headers;

            if conditional_response_matches {
                let mut conditional_resp = Response::new(hyper::Body::empty());
                *conditional_resp.status_mut() = StatusCode::NOT_MODIFIED;

                crate::statistics::EDGE_CACHE_HIT
                    .with_label_values(&["not_modified"])
                    .inc();

                return Ok(Some(CacheResponse {
                    conditional: Some(conditional_resp),
                    full: resp,
                    full_content_hash: variation.content_hash,
                    full_content_len: original_file_size as usize,
                }));
            }

            crate::statistics::EDGE_CACHE_REQUESTS_SERVED_BYTES.inc_by(original_file_size.into());
            crate::statistics::EDGE_CACHE_HIT
                .with_label_values(&["full"])
                .inc();

            if original_file_size > 0 {
                resp.headers_mut()
                    .typed_insert::<typed_headers::ContentLength>(&typed_headers::ContentLength(
                        original_file_size.into(),
                    ));
            }
            Ok(Some(CacheResponse {
                conditional: None,
                full: resp,
                full_content_hash: variation.content_hash,
                full_content_len: original_file_size as usize,
            }))
        } else {
            crate::statistics::EDGE_CACHE_MISS.inc();

            Ok(None)
        }
    }
}

pub struct CacheResponse {
    conditional: Option<Response<hyper::Body>>,
    full: Response<hyper::Body>,
    full_content_hash: String,
    full_content_len: usize,
}

impl CacheResponse {
    pub fn into_for_user(self) -> Response<Body> {
        self.conditional.unwrap_or(self.full)
    }

    pub async fn split_for_user_and_maybe_cloned(
        self,
    ) -> anyhow::Result<(
        Response<Body>,
        impl Future<Output = Option<ClonedResponse>> + Send,
    )> {
        if let Some(conditional) = self.conditional {
            Ok((
                conditional,
                Either::Left(futures::future::ready(Some(ClonedResponse {
                    content_length: self.full_content_len,
                    content_hash: self.full_content_hash,
                    response: self.full,
                }))),
            ))
        } else {
            info!("The response from cache is full. Clone it thorugh the temp file");
            let mut full = self.full;

            let cloned_future = clone_response_through_tempfile(&mut full).await?;

            Ok((full, Either::Right(cloned_future)))
        }
    }

    pub fn is_full_response_success(&self) -> bool {
        self.full.status().is_success()
    }

    pub fn has_conditional(&self) -> bool {
        self.conditional.is_some()
    }

    pub fn as_full_resp(&self) -> &Response<hyper::Body> {
        &self.full
    }
}
