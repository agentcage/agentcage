//! Byte-stream plumbing shared by every protocol layer.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

/// Any duplex byte stream the proxy reads and writes: a TCP socket, a TLS
/// session on top of one, either with already-read bytes replayed first.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// A boxed [`Io`], so connection handling is not generic over the stream.
pub(crate) type BoxIo = Box<dyn Io>;

/// A stream with bytes that were already read from it (while peeking at
/// the protocol) put back in front.
pub(crate) struct Prefixed<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> Prefixed<S> {
    pub(crate) fn new(prefix: Bytes, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A stream plus the bytes read from it but not consumed yet.
pub(crate) struct Buffered {
    pub(crate) io: BoxIo,
    pub(crate) buf: BytesMut,
}

impl Buffered {
    pub(crate) fn new(io: BoxIo) -> Self {
        Self {
            io,
            buf: BytesMut::with_capacity(8 * 1024),
        }
    }

    /// Read more into the buffer; `Ok(0)` at end of stream.
    pub(crate) async fn fill(&mut self) -> io::Result<usize> {
        if self.buf.capacity() - self.buf.len() < 4096 {
            self.buf.reserve(16 * 1024);
        }
        self.io.read_buf(&mut self.buf).await
    }

    pub(crate) async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.io.write_all(data).await?;
        self.io.flush().await
    }

    /// The stream with the unconsumed bytes replayed first.
    pub(crate) fn into_io(self) -> BoxIo {
        if self.buf.is_empty() {
            self.io
        } else {
            Box::new(Prefixed::new(self.buf.freeze(), self.io))
        }
    }

    /// The stream and the unconsumed bytes, separately.
    pub(crate) fn into_parts(self) -> (BoxIo, Vec<u8>) {
        (self.io, self.buf.to_vec())
    }
}
