use byte_unit::Byte;
use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashSet;
use exogress_common::entities::{AccountUniqueId, HandlerName, MountPointName, ProjectName};
use futures::{StreamExt, TryStreamExt};
use http::{HeaderMap, Response, StatusCode};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use sha2::Digest;
use sodiumoxide::crypto::secretstream::{xchacha20poly1305, Header};
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
    sqlite: Arc<tokio::sync::Mutex<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>>,
    cache_files_dir: Arc<PathBuf>,
    in_flights: Arc<DashSet<(AccountUniqueId, String)>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Meta {
    #[serde(with = "http_serde::header_map")]
    headers: http::HeaderMap,
    #[serde(with = "http_serde::status_code")]
    status: http::StatusCode,

    encryption_header: String,
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

        let mut sqlite_db_path = cache_dir.clone();
        sqlite_db_path.push("db");
        tokio::fs::create_dir_all(&sqlite_db_path)
            .await
            .expect("Error initializing cache DB");
        sqlite_db_path.push("cache.db3");

        let mut cache_files_dir = cache_dir.clone();
        cache_files_dir.push("files");

        tokio::fs::create_dir_all(&cache_files_dir)
            .await
            .expect("Error initializing cache files directory");

        info!(
            "Use sqlite at {}",
            sqlite_db_path.as_os_str().to_str().unwrap()
        );

        let manager = SqliteConnectionManager::file(sqlite_db_path);
        // FIXME: use builder
        let pool = r2d2::Pool::new(manager)?;
        let sqlite = pool.get()?;

        info!("Cache sqlite DB successfully opened");

        // + 1. find all expired
        // + 2. find all expired in account
        // + 3. find the least used file in account
        // + 4. update last used time of file by account + filename

        sqlite.execute(
            "CREATE TABLE IF NOT EXISTS  files (
                  id                  INTEGER PRIMARY KEY,
                  account_unique_id   TEXT NOT NULL,
                  filename            TEXT NOT NULL,
                  original_file_size  INT4 NOT NULL,
                  file_size           INT4 NOT NULL,
                  expires_at          INT4 NOT NULL,
                  last_used_at        INT4 NOT NULL,
                  meta                TEXT NOT NULL,
                  used_times          INT4 NOT NULL
            )",
            params![],
        )?;

        sqlite.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS account_files ON files(account_unique_id, filename);",
            params![],
        )?;
        sqlite.execute(
            "CREATE INDEX IF NOT EXISTS expired_files ON files(expires_at);",
            params![],
        )?;
        sqlite.execute(
            "CREATE INDEX IF NOT EXISTS expired_files_in_account ON files(account_unique_id, expires_at);",
            params![],
        )?;
        sqlite.execute(
            "CREATE INDEX IF NOT EXISTS  expired_files ON files(account_unique_id, last_used_at);",
            params![],
        )?;

        let cache = Cache {
            sqlite: Arc::new(tokio::sync::Mutex::new(pool)),
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
    fn storage_path(&self, account_unique_id: &AccountUniqueId, file_name: &str) -> PathBuf {
        let mut path = (*self.cache_files_dir).clone();
        path.push(account_unique_id.to_string());
        let first = file_name[..2].to_string();
        let second = file_name[2..4].to_string();
        let last = file_name[4..].to_string();
        path.push(first);
        path.push(second);
        path.push(last);
        path
    }

    /// The filename used to store the data in blob storage
    fn sha_filename(
        &self,
        project_name: &ProjectName,
        mount_point_name: &MountPointName,
        handler_name: &HandlerName,
        handler_checksum: &HandlerChecksum,
        accept: &typed_headers::Accept,
        accept_encoding: &typed_headers::AcceptEncoding,
        method: &http::Method,
        path_and_query: &str,
    ) -> String {
        let mut content_sha2 = sha2::Sha512::default();
        content_sha2.update(project_name.as_str());
        content_sha2.update(mount_point_name.as_str());
        content_sha2.update(handler_name.as_str());
        content_sha2.update(&handler_checksum.0.to_be_bytes());
        for qi in &accept.0 {
            content_sha2.update(&qi.quality.as_u16().to_be_bytes());
            content_sha2.update(qi.item.as_ref());
        }
        for qi in &accept_encoding.0 {
            content_sha2.update(&qi.quality.as_u16().to_be_bytes());
            content_sha2.update(qi.item.as_str());
        }
        content_sha2.update(method.as_str());
        content_sha2.update(path_and_query);
        bs58::encode(content_sha2.finalize()).into_string()
    }

    async fn delete_evicted_files(
        &self,
        evicted_files: Vec<(String, AccountUniqueId)>,
    ) -> anyhow::Result<()> {
        for (evicted_file, account_unique_id) in evicted_files {
            info!("evict file {} from cache", evicted_file);

            {
                let locked_sqlite_pool = self.sqlite.clone().lock_owned().await;
                shadow_clone!(evicted_file);

                let _res = tokio::task::spawn_blocking(move || {
                    Ok::<_, anyhow::Error>(locked_sqlite_pool.get()?.execute(
                        "DELETE FROM files WHERE account_unique_id = ?1 AND filename = ?2;",
                        params![account_unique_id.to_string(), evicted_file],
                    )?)
                })
                .await??;
            }

            let mut storage_path = self.storage_path(&account_unique_id, evicted_file.as_str());

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

        let evicted_files: Vec<(String, AccountUniqueId)> = {
            let locked_sqlite_pool = self.sqlite.clone().lock_owned().await;

            tokio::task::spawn_blocking(move || {
                let conn = locked_sqlite_pool.get()?;
                let mut stmt = conn.prepare(
                    "SELECT account_unique_id, filename 
                    FROM files 
                    WHERE expires_at < ?1 
                    LIMIT ?2;",
                )?;

                let res = stmt
                    .query_map(params![now, limit], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .into_iter()
                    .map(|r| {
                        let (account_unique_id, filename) = r?;
                        Ok::<_, anyhow::Error>((
                            filename,
                            AccountUniqueId::from_str(&account_unique_id)?,
                        ))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Ok::<_, anyhow::Error>(res)
            })
            .await??
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
        limit: isize,
    ) -> anyhow::Result<usize> {
        let now = Utc::now().timestamp();

        let evicted_files: Vec<(String, AccountUniqueId)> = {
            let locked_sqlite_pool = self.sqlite.clone().lock_owned().await;
            shadow_clone!(account_unique_id);

            tokio::task::spawn_blocking(move || {
                let conn = locked_sqlite_pool.get()?;
                let mut stmt = conn.prepare(
                    "SELECT filename 
                    FROM files 
                    WHERE expires_at < ?1 AND account_unique_id = ?2
                    LIMIT ?3;",
                )?;

                let res = stmt
                    .query_map(params![now, account_unique_id.to_string(), limit], |row| {
                        row.get::<_, String>(0)
                    })?
                    .into_iter()
                    .map(|r| {
                        let filename = r?;
                        Ok::<_, anyhow::Error>((filename, account_unique_id.clone()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Ok::<_, anyhow::Error>(res)
            })
            .await??
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
        let evicted_files: Vec<(String, AccountUniqueId)> = {
            let locked_sqlite_pool = self.sqlite.clone().lock_owned().await;
            shadow_clone!(account_unique_id);

            tokio::task::spawn_blocking(move || {
                let conn = locked_sqlite_pool.get()?;
                let mut stmt = conn.prepare(
                    "SELECT filename 
                    FROM files 
                    WHERE account_unique_id = ?1
                    ORDER BY last_used_at
                    LIMIT 1;",
                )?;

                let res = stmt
                    .query_map(params![account_unique_id.to_string()], |row| {
                        Ok(row.get::<_, String>(0)?)
                    })?
                    .into_iter()
                    .map(|r| {
                        let filename = r?;
                        Ok::<_, anyhow::Error>((filename, account_unique_id.clone()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Ok::<_, anyhow::Error>(res)
            })
            .await??
        };

        let num_evicted_files = evicted_files.len();

        if num_evicted_files > 0 {
            self.delete_evicted_files(evicted_files).await?;
        }

        Ok(num_evicted_files)
    }

    async fn get_account_used(&self, account_unique_id: &AccountUniqueId) -> anyhow::Result<Byte> {
        let space_used = {
            let locked_sqlite_pool = self.sqlite.clone().lock_owned().await;
            shadow_clone!(account_unique_id);

            tokio::task::spawn_blocking(move || {
                let conn = locked_sqlite_pool.get()?;
                let mut stmt = conn.prepare(
                    "SELECT sum(original_file_size) as space_used
                    FROM files
                    WHERE account_unique_id = ?1
                    GROUP BY account_unique_id
                    LIMIT 1;",
                )?;

                let res = stmt
                    .query_row(params![account_unique_id.to_string()], |row| {
                        Ok(row.get::<_, u32>(0)?)
                    })
                    .optional()?;

                Ok::<_, anyhow::Error>(res)
            })
            .await??
            .unwrap_or(0u32)
        };

        info!("account space used = {:?}", space_used);

        Ok(Byte::from_bytes(space_used.into()))
    }

    async fn add_file_without_checks(
        &self,
        account_unique_id: &AccountUniqueId,
        headers: &HeaderMap,
        status: StatusCode,
        encryption_header: Header,
        valid_till: DateTime<Utc>,
        original_file_size: u32,
        temp_file_path: PathBuf,
        file_name: &str,
    ) -> anyhow::Result<()> {
        let storage_path = self.storage_path(account_unique_id, file_name);

        let file_size = tokio::fs::metadata(&temp_file_path).await?.len();

        let meta = Meta {
            headers: headers.clone(),
            status: status.clone(),
            encryption_header: hex::encode(encryption_header.as_ref()),
        };

        let meta_json =
            serde_json::to_string_pretty(&meta).expect("Serialization should never fail");

        {
            let locked_sqlite_pool = self.sqlite.clone().lock_owned().await;

            tokio::task::spawn_blocking({
                shadow_clone!(account_unique_id);
                let file_name = file_name.to_string();

                move || {
                    Ok::<_, anyhow::Error>(
                        locked_sqlite_pool.get()?.execute(
                            "INSERT INTO files (
                                      account_unique_id,
                                      filename,
                                      file_size,
                                      original_file_size,
                                      expires_at,
                                      last_used_at,
                                      meta,
                                      used_times
                                ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                                    ON CONFLICT(account_unique_id, filename) DO 
                                        UPDATE SET 
                                            file_size=?3,
                                            original_file_size=?4,
                                            expires_at=?5,
                                            last_used_at=?6,
                                            meta=?7,
                                            used_times=?8;"
                                .into(),
                            params![
                                account_unique_id.to_string(),
                                file_name,
                                file_size as u32,
                                original_file_size,
                                valid_till.timestamp(),
                                Utc::now().timestamp(),
                                meta_json,
                                0
                            ],
                        )?,
                    )
                }
            })
            .await??;
        }

        let mut parent_dir = storage_path.clone();
        parent_dir.pop();

        tokio::fs::create_dir_all(&parent_dir).await?;

        tokio::fs::copy(temp_file_path, storage_path).await?;

        Ok(())
    }

    async fn mark_lru_used(
        &self,
        account_unique_id: &AccountUniqueId,
        file_name: &str,
    ) -> anyhow::Result<()> {
        {
            let locked_sqlite = self.sqlite.clone().lock_owned().await;

            tokio::task::spawn_blocking({
                shadow_clone!(account_unique_id);
                let file_name = file_name.to_string();

                move || {
                    Ok::<_, anyhow::Error>(locked_sqlite.get()?.execute(
                        "UPDATE files 
                             SET used_times=used_times+1, last_used_at=?3 
                             WHERE account_unique_id = ?1 AND filename = ?2;",
                        params![
                            account_unique_id.to_string(),
                            file_name,
                            Utc::now().timestamp()
                        ],
                    )?)
                }
            })
            .await??;
        }

        Ok(())
    }

    pub async fn save_content(
        &self,
        account_unique_id: &AccountUniqueId,
        project_name: &ProjectName,
        mount_point_name: &MountPointName,
        handler_name: &HandlerName,
        handler_checksum: &HandlerChecksum,
        accept: &typed_headers::Accept,
        accept_encoding: &typed_headers::AcceptEncoding,
        method: &http::Method,
        headers: &HeaderMap,
        status: StatusCode,
        path_and_query: &str,
        original_file_size: u32,
        encryption_header: Header,
        max_account_cache_size: Byte,
        valid_till: DateTime<Utc>,
        temp_file_path: PathBuf,
    ) -> anyhow::Result<()> {
        // TODO: ensure GET/HEAD and success resp
        let file_name = self.sha_filename(
            project_name,
            mount_point_name,
            handler_name,
            handler_checksum,
            accept,
            accept_encoding,
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
                    headers,
                    status,
                    encryption_header,
                    valid_till,
                    original_file_size,
                    temp_file_path,
                    file_name.as_str(),
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

    pub async fn read_from_cache(
        &self,
        account_unique_id: &AccountUniqueId,
        project_name: &ProjectName,
        mount_point_name: &MountPointName,
        handler_name: &HandlerName,
        handler_checksum: &HandlerChecksum,
        accept: &typed_headers::Accept,
        accept_encoding: &typed_headers::AcceptEncoding,
        method: &http::Method,
        path_and_query: &str,
        xchacha20poly1305_secret_key: &xchacha20poly1305::Key,
    ) -> anyhow::Result<Option<Response<hyper::Body>>> {
        let file_name = self.sha_filename(
            project_name,
            mount_point_name,
            handler_name,
            handler_checksum,
            accept,
            accept_encoding,
            method,
            path_and_query,
        );

        let (expires_at, meta, original_file_size) = {
            let locked_sqlite_pool = self.sqlite.clone().lock_owned().await;
            shadow_clone!(account_unique_id);
            shadow_clone!(file_name);

            tokio::task::spawn_blocking(move || {
                let conn = locked_sqlite_pool.get()?;
                let mut stmt = conn.prepare(
                    "SELECT expires_at, meta, original_file_size
                    FROM files 
                    WHERE filename = ?1 AND account_unique_id = ?2;",
                )?;

                let (ts, meta_json, original_file_size) = stmt
                    .query_row(params![file_name, account_unique_id.to_string()], |row| {
                        Ok((row.get(0)?, row.get::<_, String>(1)?, row.get::<_, u32>(2)?))
                    })?;

                let expires_at = Utc.timestamp(ts, 0);
                let meta = serde_json::from_str::<Meta>(meta_json.as_str())?;

                Ok::<_, anyhow::Error>((expires_at, meta, original_file_size))
            })
            .await??
        };

        let now = Utc::now();
        if expires_at < now {
            return Ok(None);
        }

        self.mark_lru_used(account_unique_id, file_name.as_str())
            .await?;

        let storage_path = self.storage_path(account_unique_id, file_name.as_ref());

        let header = sodiumoxide::crypto::secretstream::Header::from_slice(&hex::decode(
            &meta.encryption_header,
        )?)
        .ok_or_else(|| anyhow!("failed to read encryption header"))?;

        let mut dec_stream = sodiumoxide::crypto::secretstream::Stream::init_pull(
            &header,
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
        if original_file_size > 0 {
            resp.headers_mut()
                .typed_insert::<typed_headers::ContentLength>(&typed_headers::ContentLength(
                    original_file_size.into(),
                ));
        }
        Ok(Some(resp))
    }
}
