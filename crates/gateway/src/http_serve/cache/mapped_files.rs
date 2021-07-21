use crate::http_serve::cache::dir::storage_path;
use exogress_common::entities::AccountUniqueId;
use exogress_server_common::crypto;
use futures::StreamExt;
use lru_time_cache::LruCache;
use memadvise::Advice;
use memmap2::Mmap;
use pin_utils::pin_mut;
use sodiumoxide::crypto::secretstream::xchacha20poly1305;
use std::{fs::File, path::PathBuf, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, task::spawn_blocking};

pub struct MmapInner {
    mmap: Mmap,
    _file: File,
}

#[derive(Clone)]
pub struct SharedMmapInner(Arc<MmapInner>);

impl AsRef<[u8]> for SharedMmapInner {
    fn as_ref(&self) -> &[u8] {
        let inner: &MmapInner = self.0.as_ref();
        inner.mmap.as_ref()
    }
}

impl SharedMmapInner {
    pub fn into_hyper_body(self) -> hyper::Body {
        let mut v = Vec::with_capacity(self.0.mmap.as_ref().len());
        v.extend_from_slice(self.as_ref());
        hyper::Body::from(v)
    }
}

#[derive(Clone)]
pub struct MappedFiles {
    storage: Arc<tokio::sync::Mutex<LruCache<(AccountUniqueId, String, String), SharedMmapInner>>>,
    cache_files_dir: Arc<PathBuf>,
}

const TTL: Duration = Duration::from_secs(30);

impl MappedFiles {
    pub fn new(dir: &Arc<PathBuf>) -> Self {
        MappedFiles {
            storage: Arc::new(tokio::sync::Mutex::new(LruCache::with_expiry_duration(TTL))),
            cache_files_dir: dir.clone(),
        }
    }

    pub async fn open(
        &self,
        account_unique_id: &AccountUniqueId,
        request_hash: &str,
        vary: &str,
        xchacha20poly1305_secret_key: &xchacha20poly1305::Key,
        body_encryption_header: &sodiumoxide::crypto::secretstream::Header,
    ) -> anyhow::Result<SharedMmapInner> {
        let storage = self.storage.clone();
        let mut locked = storage.lock_owned().await;

        match locked.entry((
            *account_unique_id,
            request_hash.to_string(),
            vary.to_string(),
        )) {
            lru_time_cache::Entry::Occupied(e) => Ok(e.into_mut().clone()),
            lru_time_cache::Entry::Vacant(v) => {
                let storage_path =
                    storage_path(&self.cache_files_dir, account_unique_id, request_hash, vary);

                let mut decrypted_tempfile =
                    tokio::fs::File::from_std(spawn_blocking(|| tempfile::tempfile()).await??);

                let encrypted_source = tokio::fs::File::open(storage_path).await?;

                let stream = crypto::decrypt_reader(
                    encrypted_source,
                    xchacha20poly1305_secret_key,
                    &body_encryption_header,
                )?;

                pin_mut!(stream);

                while let Some(chunk) = stream.next().await {
                    decrypted_tempfile.write_all(&chunk?).await?;
                }

                let std_file = decrypted_tempfile.into_std().await;

                let mmap = unsafe { Mmap::map(&std_file) }?;

                memadvise::advise(mmap.as_ptr() as *mut (), mmap.len(), Advice::WillNeed)
                    .map_err(|_e| anyhow!("madvise error"))?;

                let mapped = Arc::new(MmapInner {
                    mmap,
                    _file: std_file,
                });

                let shared = SharedMmapInner(mapped);

                v.insert(shared.clone());

                Ok(shared)
            }
        }
    }
}
