use std::net::SocketAddr;

#[derive(Debug, Deserialize, Serialize)]
pub struct SourceInfo {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}
