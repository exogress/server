use crate::http_serve::cache::dir::storage_path;
use exogress_common::entities::AccountUniqueId;
use lru_time_cache::LruCache;
use memadvise::Advice;
use memmap::Mmap;
use std::{fs::File, io, path::PathBuf, sync::Arc, time::Duration};

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

#[derive(Clone)]
pub struct MappedFiles {
    storage: Arc<parking_lot::Mutex<LruCache<(AccountUniqueId, String, String), SharedMmapInner>>>,
    cache_files_dir: Arc<PathBuf>,
}

const TTL: Duration = Duration::from_secs(30);

impl MappedFiles {
    pub fn new(dir: &Arc<PathBuf>) -> Self {
        MappedFiles {
            storage: Arc::new(parking_lot::Mutex::new(LruCache::with_expiry_duration(TTL))),
            cache_files_dir: dir.clone(),
        }
    }

    pub fn open(
        &self,
        account_unique_id: &AccountUniqueId,
        request_hash: &str,
        vary: &str,
    ) -> Result<SharedMmapInner, io::Error> {
        match self.storage.lock().entry((
            *account_unique_id,
            request_hash.to_string(),
            vary.to_string(),
        )) {
            lru_time_cache::Entry::Occupied(e) => Ok(e.into_mut().clone()),
            lru_time_cache::Entry::Vacant(v) => {
                let storage_path =
                    storage_path(&self.cache_files_dir, account_unique_id, request_hash, vary);

                let file = std::fs::File::open(storage_path)?;

                let mmap = unsafe { Mmap::map(&file) }?;

                memadvise::advise(mmap.as_ptr() as *mut (), mmap.len(), Advice::WillNeed)
                    .map_err(|_e| io::Error::new(io::ErrorKind::Other, format!("madvise error")))?;

                let mapped = Arc::new(MmapInner { mmap, _file: file });

                let shared = SharedMmapInner(mapped);

                v.insert(shared.clone());

                Ok(shared)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mapping() {
        let tempdir = tempfile::tempdir().unwrap();

        let account_unique_id = AccountUniqueId::new();

        let request_hash = "12345678901234567890";
        let vary = "asdfghjklzxcvbnmqwertyuiop";

        let path = storage_path(
            &Arc::new(tempdir.path().to_owned()),
            &account_unique_id,
            request_hash,
            vary,
        );

        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();

        let content = vec![1u8, 2, 3, 4, 5, 6, 7];

        std::fs::write(path, &content).unwrap();

        let files = MappedFiles::new(&Arc::new(tempdir.path().to_owned()));

        let mapped = files.open(&account_unique_id, request_hash, vary).unwrap();

        assert_eq!(&content[..], mapped.as_ref());
    }
}
