//! Resource limits for an HTTP listener: how long a connection may take to
//! send a request's headers, how long it may sit idle, how many connections
//! are served at once, and how long a handler waits for a request body.
//!
//! `axum::serve` sets none of these. Its connection builder has no timer, so
//! hyper's own header-read timeout never runs, and it accepts connections
//! without bound. [`BoundedListener`] wraps the bound `TcpListener` and adds
//! them at the I/O layer, with no change to routing:
//!
//! - **Connection cap.** At most [`ListenerLimits::max_connections`] are
//!   served at once. Past that, `accept` waits for one to close; the kernel's
//!   backlog holds the rest.
//! - **Header read.** Once a request's first byte arrives, its header block
//!   must be complete within [`ListenerLimits::header_read_timeout`]. The
//!   deadline is fixed when the request starts: a client that keeps sending
//!   a byte at a time does not extend it.
//! - **Idle.** A kept-alive connection with no request in progress is closed
//!   after [`ListenerLimits::idle_timeout`], and so is one whose response
//!   the peer stops reading for that long.
//!
//! A request body is read by the handler, after any admission check, with
//! [`read_body`]: bounded in size and in time
//! ([`ListenerLimits::body_read_timeout`]).
//!
//! These are a backstop for a service reachable directly. A deployment is
//! still expected to put a reverse proxy in front, with its own limits.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::serve::{Listener, ListenerExt, TapIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};

/// Time allowed from a request's first byte to the end of its header block.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Time a connection may wait for its next request, or stall reading a
/// response, before it is closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Time a handler waits for a whole request body.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Connections served at once.
pub const MAX_CONNECTIONS: usize = 256;

/// The limits a [`BoundedListener`] applies.
#[derive(Debug, Clone, Copy)]
pub struct ListenerLimits {
    pub header_read_timeout: Duration,
    pub idle_timeout: Duration,
    pub body_read_timeout: Duration,
    pub max_connections: usize,
}

impl Default for ListenerLimits {
    fn default() -> Self {
        Self {
            header_read_timeout: HEADER_READ_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
            body_read_timeout: BODY_READ_TIMEOUT,
            max_connections: MAX_CONNECTIONS,
        }
    }
}

/// A `TcpListener` that applies [`ListenerLimits`] to every connection.
pub struct BoundedListener {
    inner: TcpListener,
    limits: ListenerLimits,
    slots: Arc<Semaphore>,
}

impl BoundedListener {
    pub fn new(inner: TcpListener, limits: ListenerLimits) -> Self {
        Self {
            inner,
            limits,
            slots: Arc::new(Semaphore::new(limits.max_connections.max(1))),
        }
    }

    /// This listener in the form `axum::serve` takes with
    /// `into_make_service_with_connect_info::<SocketAddr>()`: axum provides
    /// `ConnectInfo<SocketAddr>` for a tapped listener, so the per-address
    /// limiters still see each connection's peer.
    pub fn into_serve(self) -> TapIo<Self, fn(&mut BoundedIo)> {
        self.tap_io(|_| {})
    }
}

/// Serve `listener` under the default [`ListenerLimits`].
pub fn bounded(listener: TcpListener) -> TapIo<BoundedListener, fn(&mut BoundedIo)> {
    BoundedListener::new(listener, ListenerLimits::default()).into_serve()
}

impl Listener for BoundedListener {
    type Io = BoundedIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // Wait for a free slot before taking the next connection off the
        // backlog. The semaphore is never closed, so this cannot fail.
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .expect("the connection semaphore is never closed");
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => {
                    return (BoundedIo::new(stream, self.limits, permit), addr);
                }
                Err(e) => handle_accept_error(e).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// As axum's own `TcpListener` does: a connection-level error is the peer's
/// and is skipped; anything else (out of file descriptors) is logged and
/// retried after a pause.
async fn handle_accept_error(e: io::Error) {
    if matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }
    tracing::error!(error = %e, "accept failed; retrying in 1s");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// Where a connection is in its request cycle, as far as its bytes show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the next request; closed at the idle deadline.
    Idle,
    /// A request has started; its header block must end by the deadline.
    Header,
    /// The header block is complete. The handler bounds the body.
    Request,
    /// The connection speaks HTTP/2, whose frames carry no header block
    /// this can see; only the idle deadline applies, on every read.
    Http2,
}

/// Finds the end of a request's header block: an empty line, `\r\n` or
/// `\n`, after at least one byte that is not a line break (leading empty
/// lines do not end a header block).
#[derive(Debug, Default, Clone, Copy)]
struct HeaderEnd {
    /// 0 = in a line, 1 = after `\n`, 2 = after `\n\r`.
    eol: u8,
    content: bool,
}

impl HeaderEnd {
    /// Feed bytes; whether the header block ended within them.
    fn feed(&mut self, bytes: &[u8]) -> bool {
        for &b in bytes {
            match (self.eol, b) {
                (1 | 2, b'\n') if self.content => return true,
                (_, b'\n') => self.eol = 1,
                (1, b'\r') => self.eol = 2,
                (_, b'\r') => self.eol = 0,
                _ => {
                    self.eol = 0;
                    self.content = true;
                }
            }
        }
        false
    }
}

/// The HTTP/2 connection preface's first bytes.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0";

/// A connection served under [`ListenerLimits`]. Holds its slot of the
/// connection cap until dropped.
pub struct BoundedIo {
    inner: TcpStream,
    limits: ListenerLimits,
    phase: Phase,
    /// The deadline the current read phase is held to.
    read_deadline: Option<Instant>,
    read_timer: Pin<Box<Sleep>>,
    /// Armed while a write is blocked on the peer.
    write_deadline: Option<Instant>,
    write_timer: Pin<Box<Sleep>>,
    header_end: HeaderEnd,
    /// Bytes of the connection seen so far, up to the HTTP/2 preface's length.
    sniffed: Vec<u8>,
    /// The task waiting on a pending read, woken when a write moves the read
    /// deadline so that it arms the new one.
    reader: Option<std::task::Waker>,
    _slot: OwnedSemaphorePermit,
}

impl BoundedIo {
    fn new(inner: TcpStream, limits: ListenerLimits, slot: OwnedSemaphorePermit) -> Self {
        let now = Instant::now();
        Self {
            inner,
            limits,
            // A new connection has not sent anything yet: it gets the header
            // deadline from the start, so connecting and saying nothing is
            // not a way to hold a slot for the idle timeout.
            phase: Phase::Header,
            read_deadline: Some(now + limits.header_read_timeout),
            read_timer: Box::pin(tokio::time::sleep_until(now + limits.header_read_timeout)),
            write_deadline: None,
            write_timer: Box::pin(tokio::time::sleep_until(now)),
            header_end: HeaderEnd::default(),
            sniffed: Vec::with_capacity(H2_PREFACE.len()),
            reader: None,
            _slot: slot,
        }
    }

    fn enter_idle(&mut self) {
        self.phase = Phase::Idle;
        self.set_read_deadline(Instant::now() + self.limits.idle_timeout);
    }

    /// Move the read deadline, waking a pending read so it is armed.
    fn set_read_deadline(&mut self, deadline: Instant) {
        self.read_deadline = Some(deadline);
        if let Some(reader) = self.reader.take() {
            reader.wake();
        }
    }

    fn start_request(&mut self) {
        self.phase = Phase::Header;
        self.read_deadline = Some(Instant::now() + self.limits.header_read_timeout);
        self.header_end = HeaderEnd::default();
    }

    /// Account for bytes read.
    fn observe(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.sniffed.len() < H2_PREFACE.len() {
            let take = (H2_PREFACE.len() - self.sniffed.len()).min(bytes.len());
            self.sniffed.extend_from_slice(&bytes[..take]);
            if !H2_PREFACE.starts_with(&self.sniffed) {
                // Not HTTP/2: stop sniffing.
                self.sniffed = H2_PREFACE.to_vec();
                self.sniffed[0] = 0;
            } else if self.sniffed.len() == H2_PREFACE.len() {
                self.phase = Phase::Http2;
            }
        }
        match self.phase {
            Phase::Http2 => {
                self.read_deadline = Some(Instant::now() + self.limits.idle_timeout);
            }
            Phase::Request => {}
            Phase::Idle => {
                self.start_request();
                self.scan(bytes);
            }
            Phase::Header => self.scan(bytes),
        }
    }

    /// Look for the end of the header block.
    fn scan(&mut self, bytes: &[u8]) {
        if self.header_end.feed(bytes) {
            self.phase = Phase::Request;
            self.read_deadline = None;
        }
    }

    /// Account for bytes written: a response going out ends the request, and
    /// the connection is idle until the next one starts.
    fn wrote(&mut self, n: usize) {
        self.write_deadline = None;
        if n == 0 {
            return;
        }
        match self.phase {
            Phase::Request | Phase::Idle => self.enter_idle(),
            Phase::Http2 => {
                self.set_read_deadline(Instant::now() + self.limits.idle_timeout);
            }
            Phase::Header => {}
        }
    }
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{what} timed out"))
}

/// Poll `timer` towards `deadline`; ready once it has passed.
fn poll_deadline(timer: &mut Pin<Box<Sleep>>, deadline: Instant, cx: &mut Context<'_>) -> bool {
    if timer.deadline() != deadline {
        timer.as_mut().reset(deadline);
    }
    timer.as_mut().poll(cx).is_ready()
}

impl AsyncRead for BoundedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled()[before..].to_vec();
                this.observe(&filled);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.reader = Some(cx.waker().clone());
                if let Some(deadline) = this.read_deadline
                    && poll_deadline(&mut this.read_timer, deadline, cx)
                {
                    let what = match this.phase {
                        Phase::Header => "reading the request headers",
                        _ => "the idle connection",
                    };
                    return Poll::Ready(Err(timed_out(what)));
                }
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for BoundedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.wrote(n);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                let deadline = *this
                    .write_deadline
                    .get_or_insert_with(|| Instant::now() + this.limits.idle_timeout);
                if poll_deadline(&mut this.write_timer, deadline, cx) {
                    return Poll::Ready(Err(timed_out("writing the response")));
                }
                Poll::Pending
            }
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(n)) => {
                this.wrote(n);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                let deadline = *this
                    .write_deadline
                    .get_or_insert_with(|| Instant::now() + this.limits.idle_timeout);
                if poll_deadline(&mut this.write_timer, deadline, cx) {
                    return Poll::Ready(Err(timed_out("writing the response")));
                }
                Poll::Pending
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Why [`read_body`] did not return a body.
#[derive(Debug)]
pub enum BodyReadError {
    /// The body is larger than the limit (`413`).
    TooLarge { limit: usize },
    /// The body did not arrive within the timeout (`408`).
    TimedOut,
    /// The connection failed while the body was read (`400`).
    Failed,
}

impl IntoResponse for BodyReadError {
    fn into_response(self) -> Response {
        let (status, error, message) = match self {
            BodyReadError::TooLarge { limit } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                format!("the request body is larger than {limit} bytes"),
            ),
            BodyReadError::TimedOut => (
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "the request body did not arrive in time".to_string(),
            ),
            BodyReadError::Failed => (
                StatusCode::BAD_REQUEST,
                "malformed_request",
                "the request body could not be read".to_string(),
            ),
        };
        (
            status,
            [(axum::http::header::CONNECTION, "close")],
            axum::Json(serde_json::json!({ "error": error, "message": message })),
        )
            .into_response()
    }
}

/// Read a whole request body, at most `limit` bytes, within `timeout`.
///
/// Call it after the request has been admitted, so a refused request never
/// has its body read. A body that declares a length over `limit` is refused
/// before anything is read.
pub async fn read_body(
    mut body: Body,
    limit: usize,
    timeout: Duration,
) -> Result<Bytes, BodyReadError> {
    use axum::body::HttpBody;
    if body.size_hint().lower() > limit as u64 {
        return Err(BodyReadError::TooLarge { limit });
    }
    let read = async {
        let mut out = Vec::new();
        while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
        {
            let frame = frame.map_err(|_| BodyReadError::Failed)?;
            if let Ok(data) = frame.into_data() {
                if out.len() + data.len() > limit {
                    return Err(BodyReadError::TooLarge { limit });
                }
                out.extend_from_slice(&data);
            }
        }
        Ok(Bytes::from(out))
    };
    tokio::time::timeout(timeout, read)
        .await
        .unwrap_or(Err(BodyReadError::TimedOut))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn short() -> ListenerLimits {
        ListenerLimits {
            header_read_timeout: Duration::from_millis(300),
            idle_timeout: Duration::from_millis(300),
            body_read_timeout: Duration::from_millis(300),
            max_connections: 2,
        }
    }

    async fn serve(limits: ListenerLimits) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/", get(|| async { "ok" }));
        tokio::spawn(async move {
            axum::serve(
                BoundedListener::new(listener, limits).into_serve(),
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        addr
    }

    /// Read until the peer closes or `within` passes; whether it closed.
    async fn closed_within(stream: &mut TcpStream, within: Duration) -> bool {
        let mut buf = [0u8; 1024];
        let deadline = Instant::now() + within;
        loop {
            match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
                Err(_) => return false,
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => {}
            }
        }
    }

    async fn get_ok(stream: &mut TcpStream) -> String {
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[tokio::test]
    async fn a_request_whose_headers_never_finish_is_closed() {
        let addr = serve(short()).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();
        assert!(closed_within(&mut stream, Duration::from_secs(3)).await);
    }

    /// Sending a byte at a time does not move the header deadline.
    #[tokio::test]
    async fn headers_sent_a_byte_at_a_time_are_held_to_one_deadline() {
        let addr = serve(short()).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let started = Instant::now();
        let mut closed = false;
        for b in
            b"GET / HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".iter()
        {
            if stream.write_all(&[*b]).await.is_err() {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            if started.elapsed() > Duration::from_secs(3) {
                break;
            }
        }
        assert!(closed || closed_within(&mut stream, Duration::from_millis(500)).await);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "closed by the header deadline"
        );
    }

    #[tokio::test]
    async fn a_connection_that_sends_nothing_is_closed() {
        let addr = serve(short()).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        assert!(closed_within(&mut stream, Duration::from_secs(3)).await);
    }

    #[tokio::test]
    async fn an_idle_kept_alive_connection_is_closed() {
        let addr = serve(short()).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        assert!(get_ok(&mut stream).await.starts_with("HTTP/1.1 200"));
        // A second request on the same connection is served...
        assert!(get_ok(&mut stream).await.starts_with("HTTP/1.1 200"));
        // ...and then, with nothing more sent, it is closed.
        assert!(closed_within(&mut stream, Duration::from_secs(3)).await);
    }

    #[tokio::test]
    async fn connections_past_the_cap_wait_for_a_free_slot() {
        let limits = ListenerLimits {
            header_read_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(30),
            max_connections: 1,
            ..short()
        };
        let addr = serve(limits).await;
        let mut first = TcpStream::connect(addr).await.unwrap();
        assert!(get_ok(&mut first).await.starts_with("HTTP/1.1 200"));

        let mut second = TcpStream::connect(addr).await.unwrap();
        second
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        assert!(
            tokio::time::timeout(Duration::from_millis(400), second.read(&mut buf))
                .await
                .is_err(),
            "the second connection is not served while the first holds the only slot"
        );
        drop(first);
        let n = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buf))
            .await
            .expect("served once the slot is free")
            .unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn the_end_of_a_header_block_is_found() {
        let ends = |chunks: &[&[u8]]| {
            let mut h = HeaderEnd::default();
            chunks.iter().any(|c| h.feed(c))
        };
        assert!(ends(&[b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"]));
        assert!(ends(&[b"GET / HTTP/1.1\nHost: x\n\n"]));
        assert!(ends(&[b"GET / HTTP/1.1\r\nHost: x\r", b"\n\r", b"\n"]));
        assert!(!ends(&[b"GET / HTTP/1.1\r\nHost: x\r\n"]));
        // Leading empty lines do not end a header block.
        assert!(!ends(&[b"\r\n\r\n\n\n"]));
    }

    /// A body that stops arriving is given up on at the timeout, with a
    /// `408`, over a real connection.
    #[tokio::test]
    async fn a_body_that_stops_arriving_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/",
            axum::routing::post(|body: Body| async move {
                match read_body(body, 1024, Duration::from_millis(200)).await {
                    Ok(_) => StatusCode::OK.into_response(),
                    Err(e) => e.into_response(),
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(
                BoundedListener::new(listener, ListenerLimits::default()).into_serve(),
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc")
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("answered at the body timeout")
            .unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 408"),
            "{}",
            String::from_utf8_lossy(&buf[..n])
        );
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_refused() {
        let err = read_body(Body::from(vec![0u8; 2048]), 1024, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(
            matches!(err, BodyReadError::TooLarge { limit: 1024 }),
            "{err:?}"
        );
        let ok = read_body(Body::from(vec![0u8; 1024]), 1024, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(ok.len(), 1024);
    }
}
