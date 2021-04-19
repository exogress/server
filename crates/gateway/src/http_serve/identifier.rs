use crate::http_serve::cache::HandlerChecksum;
use exogress_common::entities::{HandlerName, MountPointName, ProjectName};
use sha2::Digest;
use smol_str::SmolStr;

pub struct RequestProcessingIdentifier {
    inner: SmolStr,
}

impl RequestProcessingIdentifier {
    pub fn new(
        project_name: &ProjectName,
        mount_point_name: &MountPointName,
        handler_name: &HandlerName,
        handler_checksum: &HandlerChecksum,
        method: &http::Method,
        path_and_query: &str,
    ) -> Self {
        let mut hashsum = sha2::Sha512::default();
        hashsum.update(project_name.as_str());
        hashsum.update(mount_point_name.as_str());
        hashsum.update(handler_name.as_str());
        hashsum.update(&handler_checksum.into_inner().to_be_bytes());
        hashsum.update(method.as_str());
        hashsum.update(path_and_query);
        RequestProcessingIdentifier {
            inner: bs58::encode(hashsum.finalize()).into_string().into(),
        }
    }
}

impl<R> AsRef<R> for RequestProcessingIdentifier
where
    SmolStr: AsRef<R>,
{
    fn as_ref(&self) -> &R {
        self.inner.as_ref()
    }
}

impl ToString for RequestProcessingIdentifier {
    fn to_string(&self) -> String {
        self.inner.clone().into()
    }
}
