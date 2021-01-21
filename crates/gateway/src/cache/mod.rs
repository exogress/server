use byte_unit::Byte;
use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashSet;
use etag::EntityTag;
use exogress_common::entities::{AccountUniqueId, HandlerName, MountPointName, ProjectName};
use futures::{StreamExt, TryStreamExt};
use hashbrown::HashSet;
use http::header::{HeaderName, ACCEPT, ACCEPT_ENCODING, ETAG, IF_NONE_MATCH, LAST_MODIFIED, VARY};
use http::{HeaderMap, Response, StatusCode};
use sha2::Digest;
use sodiumoxide::crypto::secretstream::{xchacha20poly1305, Header};
use sqlx::sqlite::{SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio_util::codec::LengthDelimitedCodec;
use typed_headers::HeaderMapExt;

#[derive(Clone)]
pub struct Cache {
    sqlite: SqlitePool,
    cache_files_dir: Arc<PathBuf>,
    in_flights: Arc<DashSet<(AccountUniqueId, String)>>,
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

impl Cache {
    pub async fn new(cache_dir: PathBuf) -> Result<Cache, anyhow::Error> {
        let cache_dir = tokio::fs::canonicalize(&cache_dir).await?;

        info!("use cache-dir: {:?}", cache_dir);

        let mut sqlite_db_path = cache_dir.clone();
        sqlite_db_path.push("db");
        tokio::fs::create_dir_all(&sqlite_db_path)
            .await
            .expect("Error initializing cache DB");
        sqlite_db_path.push("cache.db3");
        info!("sqlite path: {:?}", sqlite_db_path);

        let mut cache_files_dir = cache_dir.clone();
        cache_files_dir.push("files");

        tokio::fs::create_dir_all(&cache_files_dir)
            .await
            .expect("Error initializing cache files directory");

        info!(
            "Use sqlite at {}",
            sqlite_db_path.as_os_str().to_str().unwrap()
        );

        if let Err(e) = tokio::fs::metadata(&sqlite_db_path).await {
            if let io::ErrorKind::NotFound = e.kind() {
                info!("sqlite db not exist. Creating empty file");
                tokio::fs::File::create(&sqlite_db_path).await?;
            }
        }

        let sqlite = SqlitePoolOptions::new()
            .max_connections(64)
            .connect(sqlite_db_path.to_str().unwrap())
            .await?;

        info!("Cache sqlite DB successfully opened");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS  files (
                  id                       INTEGER PRIMARY KEY,
                  account_unique_id        TEXT NOT NULL,
                  request_hash             TEXT NOT NULL,
                  vary                     TEXT NOT NULL,
                  vary_hash                TEXT NOT NULL,
                  body_encryption_header   TEXT NOT NULL,
                  meta_encryption_header   TEXT NOT NULL,
                  original_file_size       INT4 NOT NULL,
                  file_size                INT4 NOT NULL,
                  expires_at               INT4 NOT NULL,
                  last_used_at             INT4 NOT NULL,
                  meta                     TEXT NOT NULL,
                  etag                     TEXT,
                  is_weak_etag             BOOL,
                  last_modified            INT8,
                  used_times               INT4 NOT NULL
            )",
        )
        .execute(&sqlite)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS account_files ON files(account_unique_id, request_hash);",
        )
        .execute(&sqlite)
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS account_files_variations ON files(account_unique_id, request_hash, vary, vary_hash);",
        )
            .execute(&sqlite)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS expired_files ON files(expires_at);")
            .execute(&sqlite)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS expired_files_in_account ON files(account_unique_id, expires_at);")
            .execute(&sqlite)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS expired_files ON files(account_unique_id, last_used_at);",
        )
        .execute(&sqlite)
        .await?;

        let cache = Cache {
            sqlite,
            cache_files_dir: Arc::new(cache_files_dir),
            in_flights: Arc::new(Default::default()),
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

    /// The request_hash used to store the data in blob storage
    fn sha_request_hash(
        &self,
        project_name: &ProjectName,
        mount_point_name: &MountPointName,
        handler_name: &HandlerName,
        handler_checksum: &HandlerChecksum,
        method: &http::Method,
        path_and_query: &str,
    ) -> String {
        let mut content_sha2 = sha2::Sha512::default();
        content_sha2.update(project_name.as_str());
        content_sha2.update(mount_point_name.as_str());
        content_sha2.update(handler_name.as_str());
        content_sha2.update(&handler_checksum.0.to_be_bytes());
        content_sha2.update(method.as_str());
        content_sha2.update(path_and_query);
        bs58::encode(content_sha2.finalize()).into_string()
    }

    async fn delete_evicted_files(
        &self,
        evicted_files: Vec<(String, String, AccountUniqueId)>,
    ) -> anyhow::Result<()> {
        for (evicted_file, vary, account_unique_id) in evicted_files {
            info!("evict file {} from cache", evicted_file);

            sqlx::query("DELETE FROM files WHERE account_unique_id = ? AND request_hash = ?")
                .bind(account_unique_id.to_string().as_str())
                .bind(evicted_file.as_str())
                .execute(&self.sqlite)
                .await?;

            let mut storage_path =
                self.storage_path(&account_unique_id, evicted_file.as_str(), vary.as_str());

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

    async fn delete_some_expired(&self, limit: isize) -> anyhow::Result<usize> {
        let now = Utc::now().timestamp();

        let evicted_files: Vec<(String, String, AccountUniqueId)> = sqlx::query(
            "SELECT account_unique_id, request_hash, vary_hash
                 FROM files 
                 WHERE expires_at < ?1 
                 LIMIT ?2;",
        )
        .bind(now)
        .bind(limit as i64)
        .fetch(&self.sqlite)
        .err_into::<anyhow::Error>()
        .and_then(|row: SqliteRow| async move {
            let account_unique_id: String = row.try_get("account_unique_id")?;
            let request_hash: String = row.try_get("request_hash")?;
            let vary_hash: String = row.try_get("vary_hash")?;
            Ok::<_, anyhow::Error>((request_hash, vary_hash, account_unique_id.parse()?))
        })
        .try_collect()
        .await?;

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
        limit: isize,
    ) -> anyhow::Result<usize> {
        let now = Utc::now().timestamp();

        let evicted_files: Vec<(String, String, AccountUniqueId)> = sqlx::query(
            "SELECT request_hash, vary_hash
                  FROM files 
                  WHERE expires_at < ? AND account_unique_id = ?
                  LIMIT ?",
        )
        .bind(now)
        .bind(account_unique_id.to_string().as_str())
        .bind(limit as i64)
        .fetch(&self.sqlite)
        .and_then(|row: SqliteRow| async move {
            let request_hash: String = row.try_get("request_hash")?;
            let vary_hash: String = row.try_get("vary_hash")?;
            Ok((request_hash, vary_hash, account_unique_id.clone()))
        })
        .try_collect()
        .await?;

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
        let evicted_files: Vec<(String, String, AccountUniqueId)> = sqlx::query(
            "SELECT request_hash, vary_hash
                 FROM files 
                 WHERE account_unique_id = ?
                 ORDER BY last_used_at
                 LIMIT 1;",
        )
        .bind(account_unique_id.to_string().as_str())
        .fetch(&self.sqlite)
        .and_then(|row: SqliteRow| async move {
            let request_hash: String = row.try_get("request_hash")?;
            let vary_hash: String = row.try_get("vary_hash")?;
            Ok((request_hash, vary_hash, account_unique_id.clone()))
        })
        .try_collect()
        .await?;

        let num_evicted_files = evicted_files.len();

        if num_evicted_files > 0 {
            self.delete_evicted_files(evicted_files).await?;
        }

        Ok(num_evicted_files)
    }

    async fn get_account_used(&self, account_unique_id: &AccountUniqueId) -> anyhow::Result<Byte> {
        let maybe_row = sqlx::query(
            "SELECT sum(original_file_size) as space_used
                    FROM files
                    WHERE account_unique_id = ?1
                    GROUP BY account_unique_id
                    LIMIT 1",
        )
        .bind(account_unique_id.to_string())
        .fetch_optional(&self.sqlite)
        .await?;

        let space_used = match maybe_row {
            None => 0,
            Some(row) => {
                let space_used: u32 = row.try_get("space_used")?;
                space_used
            }
        };

        let bytes_used = Byte::from_bytes(space_used.into());
        info!(
            "account space used = {}",
            bytes_used.get_appropriate_unit(true)
        );

        Ok(bytes_used)
    }

    fn vary_hash(vary_headers_ordered_list: &Vec<String>, req_headers: &HeaderMap) -> String {
        let mut content_sha = sha2::Sha224::default();

        for vary_by_header_name in vary_headers_ordered_list {
            let header_value = req_headers
                .get(vary_by_header_name)
                .map(|h| h.to_str().unwrap())
                .unwrap_or_default();
            content_sha.update(header_value);
        }

        bs58::encode(content_sha.finalize()).into_string()
    }

    async fn add_file_without_checks(
        &self,
        account_unique_id: &AccountUniqueId,
        req_headers: &HeaderMap,
        res_headers: &HeaderMap,
        status: StatusCode,
        body_encryption_header: Header,
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

        let mut vary_headers_ordered_list: Vec<_> = vary_header_names_set
            .into_iter()
            .map(|h| h.to_string())
            .collect();
        vary_headers_ordered_list.sort();

        let vary_json = serde_json::to_string(&vary_headers_ordered_list).unwrap();
        let vary_hash = Self::vary_hash(&vary_headers_ordered_list, req_headers);

        info!("vary_json = {} hash = {}", vary_json, vary_hash);

        let meta = Meta {
            headers: res_headers.clone(),
            status: status.clone(),
        };

        let meta_json = serde_json::to_vec(&meta).expect("Serialization should never fail");

        let (mut enc_stream, meta_encryption_header) =
            sodiumoxide::crypto::secretstream::Stream::init_push(xchacha20poly1305_secret_key)
                .map_err(|_| anyhow!("could not init encryption"))?;

        let encrypted_meta_json = enc_stream
            .push(
                meta_json.as_ref(),
                None,
                sodiumoxide::crypto::secretstream::Tag::Message,
            )
            .unwrap();

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

        sqlx::query(
            "INSERT INTO files (
                      account_unique_id,
                      request_hash,
                      file_size,
                      original_file_size,
                      expires_at,
                      last_used_at,
                      meta,
                      used_times,
                      body_encryption_header,
                      meta_encryption_header,
                      etag,
                      is_weak_etag,
                      last_modified,
                      vary,
                      vary_hash
                ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                    ON CONFLICT(account_unique_id, request_hash, vary, vary_hash) DO 
                        UPDATE SET 
                            file_size=?3,
                            original_file_size=?4,
                            expires_at=?5,
                            last_used_at=?6,
                            meta=?7,
                            used_times=0,
                            body_encryption_header=?8,
                            meta_encryption_header=?9,
                            etag=?10,
                            is_weak_etag=?11,
                            last_modified=?12;",
        )
        .bind(account_unique_id.to_string())
        .bind(file_name)
        .bind(file_size as u32)
        .bind(original_file_size)
        .bind(valid_till.timestamp())
        .bind(Utc::now().timestamp())
        .bind(base64::encode(encrypted_meta_json))
        .bind(0)
        .bind(base64::encode(body_encryption_header.as_ref()))
        .bind(base64::encode(meta_encryption_header.as_ref()))
        .bind(etag.as_ref().map(|e| e.tag().to_string()))
        .bind(etag.as_ref().map(|e| e.weak))
        .bind(last_modified)
        .bind(vary_json)
        .bind(&vary_hash)
        .execute(&self.sqlite)
        .await?;

        let storage_path = self.storage_path(account_unique_id, file_name, vary_hash.as_ref());
        let mut parent_dir = storage_path.clone();
        parent_dir.pop();

        tokio::fs::create_dir_all(&parent_dir).await?;

        tokio::fs::copy(temp_file_path, storage_path).await?;

        crate::statistics::CACHE_SAVED.inc_by(original_file_size.into());

        Ok(())
    }

    async fn mark_lru_used(&self, file_id: i64) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE files 
                 SET used_times=used_times+1, last_used_at=?1
                 WHERE id = ?2",
        )
        .bind(Utc::now().timestamp())
        .bind(file_id)
        .execute(&self.sqlite)
        .await?;

        Ok(())
    }

    pub async fn save_content(
        &self,
        account_unique_id: &AccountUniqueId,
        project_name: &ProjectName,
        mount_point_name: &MountPointName,
        handler_name: &HandlerName,
        handler_checksum: &HandlerChecksum,
        method: &http::Method,
        req_headers: &HeaderMap,
        res_headers: &HeaderMap,
        status: StatusCode,
        path_and_query: &str,
        original_file_size: u32,
        encryption_header: Header,
        max_account_cache_size: Byte,
        valid_till: DateTime<Utc>,
        xchacha20poly1305_secret_key: &xchacha20poly1305::Key,
        temp_file_path: PathBuf,
    ) -> anyhow::Result<()> {
        // TODO: ensure GET/HEAD and success resp
        let file_name = self.sha_request_hash(
            project_name,
            mount_point_name,
            handler_name,
            handler_checksum,
            method,
            path_and_query,
        );

        let key = (account_unique_id.clone(), file_name.clone());

        if self.in_flights.insert(key.clone()) {
            let r = async move {
                let mut account_used = self.get_account_used(account_unique_id).await?;

                loop {
                    if account_used < max_account_cache_size {
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
                    if account_used < max_account_cache_size {
                        break;
                    }

                    let num_deleted = self.delete_most_unused(account_unique_id).await?;

                    if num_deleted == 0 {
                        return Err(anyhow!("could not free-up space"));
                    }

                    account_used = self.get_account_used(account_unique_id).await?;
                }

                self.add_file_without_checks(
                    account_unique_id,
                    req_headers,
                    res_headers,
                    status,
                    encryption_header,
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
            Ok(())
        }
    }

    pub async fn serve_from_cache(
        &self,
        account_unique_id: &AccountUniqueId,
        project_name: &ProjectName,
        mount_point_name: &MountPointName,
        handler_name: &HandlerName,
        handler_checksum: &HandlerChecksum,
        request_headers: &HeaderMap,
        method: &http::Method,
        path_and_query: &str,
        xchacha20poly1305_secret_key: &xchacha20poly1305::Key,
    ) -> anyhow::Result<Option<Response<hyper::Body>>> {
        let file_name = self.sha_request_hash(
            project_name,
            mount_point_name,
            handler_name,
            handler_checksum,
            method,
            path_and_query,
        );

        let mut variations = sqlx::query(
            "SELECT
                    id,
                    expires_at,
                    meta,
                    original_file_size,
                    body_encryption_header,
                    meta_encryption_header,
                    etag,
                    is_weak_etag,
                    last_modified,
                    vary,
                    vary_hash
                FROM files 
                WHERE request_hash = ? AND account_unique_id = ?",
        )
        .bind(file_name.as_str())
        .bind(account_unique_id.to_string())
        .fetch_all(&self.sqlite)
        .await?
        .into_iter();

        while let Some(row) = variations.next() {
            let vary_json = row.try_get::<String, _>("vary")?;
            let stored_vary_hash = row.try_get::<String, _>("vary_hash")?;

            let vary_headers_ordered_list: Vec<String> =
                if let Ok(r) = serde_json::from_str(&vary_json) {
                    r
                } else {
                    continue;
                };

            let vary_hash = Self::vary_hash(&vary_headers_ordered_list, request_headers);

            if stored_vary_hash != vary_hash {
                // vary hash doesn't match
                continue;
            }

            // at this point we are sure that vary header math
            info!("found matched vary header");

            let id = row.try_get::<i64, _>("id")?;
            let original_file_size = row.try_get::<u32, _>("original_file_size")?;
            let etag = row.try_get::<Option<String>, _>("etag")?;
            let is_weak_etag = row.try_get::<Option<bool>, _>("is_weak_etag")?;
            let last_modified = row.try_get::<Option<i64>, _>("last_modified")?;

            let expires_at = Utc.timestamp(row.try_get("expires_at")?, 0);
            let body_encryption_header = sodiumoxide::crypto::secretstream::Header::from_slice(
                &base64::decode(row.try_get::<String, _>("body_encryption_header")?)?,
            )
            .ok_or_else(|| anyhow!("failed to read encryption header"))?;
            let meta_encryption_header = sodiumoxide::crypto::secretstream::Header::from_slice(
                &base64::decode(row.try_get::<String, _>("meta_encryption_header")?)?,
            )
            .ok_or_else(|| anyhow!("failed to read encryption header"))?;

            let mut dec_stream = sodiumoxide::crypto::secretstream::Stream::init_pull(
                &meta_encryption_header,
                &xchacha20poly1305_secret_key,
            )
            .map_err(|_| anyhow!("could not init decryption"))?;

            let decrypted = dec_stream
                .pull(
                    base64::decode(row.try_get::<String, _>("meta")?)?.as_ref(),
                    None,
                )
                .map_err(|_| anyhow!("could not decrypt meta data"))?
                .0;

            let meta = serde_json::from_slice::<Meta>(decrypted.as_ref())?;

            let maybe_stored_etag = match (is_weak_etag, etag) {
                (Some(true), Some(tag)) => Some(EntityTag::weak(&tag)),
                (Some(false), Some(tag)) => Some(EntityTag::strong(&tag)),
                _ => None,
            };
            let maybe_stored_last_modified = last_modified.map(|lm| Utc.timestamp(lm, 0));

            let now = Utc::now();
            if expires_at < now {
                return Ok(None);
            }

            self.mark_lru_used(id).await?;

            let req_if_none_match: Vec<EntityTag> = request_headers
                .get_all(IF_NONE_MATCH)
                .iter()
                .filter_map(|v| v.to_str().ok().and_then(|r| r.parse().ok()))
                .collect();

            let req_last_modified = request_headers
                .get(LAST_MODIFIED)
                .and_then(|date| Some(DateTime::parse_from_rfc2822(date.to_str().ok()?).ok()?));

            let mut conditional_response_matches = false;
            if let Some(stored_etag) = maybe_stored_etag {
                if req_if_none_match
                    .iter()
                    .filter(|&provided_etag| stored_etag.weak_eq(provided_etag))
                    .next()
                    .is_some()
                {
                    info!("etag matches the cached version - send non-modified");
                    conditional_response_matches = true;
                }
            }
            if let (Some(stored_last_modified), Some(provided_last_modified)) =
                (maybe_stored_last_modified, req_last_modified)
            {
                if stored_last_modified < provided_last_modified {
                    info!("last-modified matches the cached version - send non-modified");
                    conditional_response_matches = true;
                }
            }

            if conditional_response_matches {
                let mut resp = Response::new(hyper::Body::empty());
                *resp.status_mut() = StatusCode::NOT_MODIFIED;
                return Ok(Some(resp));
            }

            let storage_path =
                self.storage_path(account_unique_id, file_name.as_ref(), vary_hash.as_str());

            let mut dec_stream = sodiumoxide::crypto::secretstream::Stream::init_pull(
                &body_encryption_header,
                xchacha20poly1305_secret_key,
            )
            .map_err(|_| anyhow!("could not init decryption"))?;

            let reader = tokio::fs::File::open(&storage_path).await?;

            let framed_reader = LengthDelimitedCodec::builder().new_read(reader);

            let body = framed_reader
                .map_ok(move |encrypted_frame| {
                    Ok::<Vec<u8>, io::Error>(
                        dec_stream
                            .pull(&encrypted_frame, None)
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::Other,
                                    "failed to decoded encrypted frame",
                                )
                            })?
                            .0,
                    )
                })
                .take_while(|r| {
                    if let Err(e) = r {
                        error!("Could not decode encrypted frame from storage: {}", e);
                    }
                    futures::future::ready(r.is_ok())
                })
                .map(|r| r.unwrap());

            let mut resp = Response::new(hyper::Body::wrap_stream(body));
            *resp.status_mut() = meta.status;
            *resp.headers_mut() = meta.headers;

            crate::statistics::CACHE_SERVED.inc_by(original_file_size.into());

            if original_file_size > 0 {
                resp.headers_mut()
                    .typed_insert::<typed_headers::ContentLength>(&typed_headers::ContentLength(
                        original_file_size.into(),
                    ));
            }
            return Ok(Some(resp));
        }

        Ok(None)
    }
}
