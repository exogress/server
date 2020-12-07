use std::net::SocketAddr;

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
pub struct SourceInfo {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}
