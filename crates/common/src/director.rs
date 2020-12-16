use std::net::SocketAddr;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SourceInfo {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub alpn_domain: Option<String>,
}
