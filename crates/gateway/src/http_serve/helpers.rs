use crate::http_serve::tempfile_stream::save_stream;
use bytes::Bytes;
use exogress_server_common::ContentHash;
use futures::{Future, Stream, TryStreamExt};
use http::{header::CONTENT_LENGTH, HeaderValue, Response};
use hyper::Body;
use std::mem;
use tokio::io::AsyncReadExt as _;

pub fn chunks(
    content: impl tokio::io::AsyncRead + Send + Unpin + 'static,
    max_chunk_size: usize,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send {
    futures::stream::try_unfold(content, move |mut reader| async move {
        let mut chunk = vec![0; max_chunk_size];
        let len = reader.read(&mut chunk).await?;
        if len == 0 {
            Ok(None)
        } else {
            chunk.truncate(len);
            Ok(Some((chunk.into(), reader)))
        }
    })
}

pub struct ClonedResponse {
    pub content_length: usize,
    pub content_hash: String,
    pub response: Response<Body>,
}

pub fn clone_response_through_tempfile(
    res: &mut Response<Body>,
) -> anyhow::Result<impl Future<Output = Option<ClonedResponse>> + Send> {
    let body = mem::replace(res.body_mut(), Body::empty())
        .into_stream()
        .map_err(|e| anyhow!("{}", e));
    let (out_stream, saved_content) = save_stream::<ContentHash, _, _>(body)?;

    let original_headers = res.headers().clone();
    let original_status = res.status();

    let mut cloned_response = Response::new(Body::empty());
    *cloned_response.headers_mut() = original_headers;
    *cloned_response.status_mut() = original_status;

    let create_response = async move {
        if let Some((reader, content_hash, content_length)) = saved_content.await {
            *cloned_response.body_mut() = Body::wrap_stream(chunks(reader, 16536));

            cloned_response
                .headers_mut()
                .insert(CONTENT_LENGTH, HeaderValue::from(content_length));
            Some(ClonedResponse {
                content_length,
                content_hash,
                response: cloned_response,
            })
        } else {
            None
        }
    };

    *res.body_mut() = Body::wrap_stream(out_stream);

    Ok(create_response)
}
