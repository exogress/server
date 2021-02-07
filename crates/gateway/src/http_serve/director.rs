use exogress_server_common::director::SourceInfo;
use std::{io, net::SocketAddr, pin::Pin, task::Context};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    macros::support::Poll,
};

/// Director connection
#[derive(Debug)]
pub struct Connection<I: AsyncRead + AsyncWrite + Unpin> {
    io: I,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
}

impl<I> Connection<I>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(io: I, source_info: SourceInfo) -> Self {
        Connection {
            io,
            local_addr: Some(source_info.local_addr),
            remote_addr: Some(source_info.remote_addr),
        }
    }
}

impl<I> AsyncRead for Connection<I>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<I> AsyncWrite for Connection<I>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
