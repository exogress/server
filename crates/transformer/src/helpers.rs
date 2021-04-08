use bytes::Buf;
use futures::{Stream, StreamExt};

pub(crate) fn to_vec_body<E: std::error::Error>(
    body_stream: impl Stream<Item = Result<impl Buf, E>> + Send + Sync + 'static,
) -> impl Stream<Item = Result<impl AsRef<[u8]>, E>> + Send + Sync + 'static {
    body_stream.map(|buf| buf.map(|mut b| b.copy_to_bytes(b.remaining())))
}
