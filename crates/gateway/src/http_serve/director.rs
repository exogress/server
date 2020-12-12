use bytes::{Buf, BufMut};
use exogress_server_common::director::SourceInfo;
use std::io;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Context;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::macros::support::Poll;

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
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
        self.io.prepare_uninitialized_buffer(buf)
    }

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }

    fn poll_read_buf<B: BufMut>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>>
    where
        Self: Sized,
    {
        Pin::new(&mut self.io).poll_read_buf(cx, buf)
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

    fn poll_write_buf<B: Buf>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>>
    where
        Self: Sized,
    {
        Pin::new(&mut self.io).poll_write_buf(cx, buf)
    }
}
