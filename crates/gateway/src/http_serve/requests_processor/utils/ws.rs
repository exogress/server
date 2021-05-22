pub fn sec_websocket_accept(key: &str) -> String {
    let s = format!("{}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);

    let mut m = sha1::Sha1::new();
    m.update(s.as_ref());
    base64::encode(m.digest().bytes().as_ref())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sec_websocket() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        assert_eq!(sec_websocket_accept(key), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    }
}
