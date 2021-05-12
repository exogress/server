use exogress_common::entities::AccountUniqueId;
use std::{path::PathBuf, sync::Arc};

/// Path to the file
pub fn storage_path(
    cache_files_dir: &Arc<PathBuf>,
    account_unique_id: &AccountUniqueId,
    file_name: &str,
    vary: &str,
) -> PathBuf {
    let mut path = cache_files_dir.as_ref().to_owned();
    path.push(account_unique_id.to_string());
    let first = file_name[..2].to_string();
    let second = file_name[2..4].to_string();
    let last = file_name[4..].to_string();
    path.push(first);
    path.push(second);
    path.push(format!("{}-{}", last, vary));
    path
}
