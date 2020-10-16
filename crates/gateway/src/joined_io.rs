use bytes::{Buf, BufMut};
use nom::lib::std::mem::MaybeUninit;
use std::io;
use std::pin::Pin;
use std::task::Context;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::macros::support::Poll;

#[derive(Debug)]
pub struct JoinedIo<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    read: R,
    write: W,
}

impl<R, W> JoinedIo<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(read: R, write: W) -> Self {
        JoinedIo { read, write }
    }
}

impl<R, W> AsyncRead for JoinedIo<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
        self.read.prepare_uninitialized_buffer(buf)
    }

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }

    fn poll_read_buf<B: BufMut>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>>
    where
        Self: Sized,
    {
        Pin::new(&mut self.read).poll_read_buf(cx, buf)
    }
}

impl<R, W> AsyncWrite for JoinedIo<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }

    fn poll_write_buf<B: Buf>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>>
    where
        Self: Sized,
    {
        Pin::new(&mut self.write).poll_write_buf(cx, buf)
    }
}
