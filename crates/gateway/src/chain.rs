use bytes::Buf;
use futures::ready;
use pin_utils::{unsafe_pinned, unsafe_unpinned};
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite};

pub struct Chain<T, U> {
    first: T,
    second: U,
    done_first: bool,
}

impl<T, U> Unpin for Chain<T, U>
where
    T: Unpin,
    U: Unpin,
{
}

pub(super) fn chain<T, U>(first: T, second: U) -> Chain<T, U>
where
    T: AsyncRead,
    U: AsyncRead,
{
    Chain {
        first,
        second,
        done_first: false,
    }
}

impl<T, U> Chain<T, U>
where
    T: AsyncRead,
    U: AsyncRead,
{
    unsafe_pinned!(first: T);
    unsafe_pinned!(second: U);
    unsafe_unpinned!(done_first: bool);
}

impl<T, U> fmt::Debug for Chain<T, U>
where
    T: fmt::Debug,
    U: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chain")
            .field("t", &self.first)
            .field("u", &self.second)
            .finish()
    }
}

impl<T, U> AsyncRead for Chain<T, U>
where
    T: AsyncRead,
    U: AsyncRead,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.done_first {
            match ready!(self.as_mut().first().poll_read(cx, buf)?) {
                0 if !buf.is_empty() => *self.as_mut().done_first() = true,
                n => return Poll::Ready(Ok(n)),
            }
        }
        self.second().poll_read(cx, buf)
    }
}

impl<T, U> AsyncBufRead for Chain<T, U>
where
    T: AsyncBufRead,
    U: AsyncBufRead,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let Self {
            first,
            second,
            done_first,
        } = unsafe { self.get_unchecked_mut() };
        let first = unsafe { Pin::new_unchecked(first) };
        let second = unsafe { Pin::new_unchecked(second) };

        if !*done_first {
            match ready!(first.poll_fill_buf(cx)?) {
                buf if buf.is_empty() => {
                    *done_first = true;
                }
                buf => return Poll::Ready(Ok(buf)),
            }
        }
        second.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        if !self.done_first {
            self.first().consume(amt)
        } else {
            self.second().consume(amt)
        }
    }
}

impl<T, U> AsyncWrite for Chain<T, U>
where
    U: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().second) }.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().second) }.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().second) }.poll_shutdown(cx)
    }

    fn poll_write_buf<B: Buf>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>>
    where
        Self: Sized,
    {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().second) }.poll_write_buf(cx, buf)
    }
}
