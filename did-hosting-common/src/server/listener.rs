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
//! - **Per-address cap.** At most
//!   [`ListenerLimits::max_connections_per_address`] of them come from one
//!   source: one IPv4 address, or one IPv6 /64 (the block a single host is
//!   usually given). A connection past that is closed as soon as it is
//!   accepted, so one source cannot take every slot of the connection cap.
//!   Trusted proxies ([`BoundedListener::with_trusted_proxies`]) are exempt:
//!   every client behind one shares its address.
//! - **Header read.** Once a request's first byte arrives, its header block
//!   must be complete within [`ListenerLimits::header_read_timeout`]. The
//!   deadline is fixed when the request starts: a client that keeps sending
//!   a byte at a time does not extend it.
//! - **Idle.** A kept-alive connection with no request in progress is closed
//!   after [`ListenerLimits::idle_timeout`], and so is one whose response
//!   the peer stops reading for that long.
//! - **HTTP/2.** A connection that opens with the HTTP/2 preface is held to
//!   the header deadline, renewed only when the service writes to it (a
//!   SETTINGS or PING acknowledgement, a response). Bytes from the peer alone
//!   never extend it, and it never gets the longer idle timeout. (axum is
//!   built without its `http2` feature here, so hyper refuses the preface at
//!   once; this only keeps the bound if that feature is ever turned on.)
//!
//! A request body is read by the handler, after any admission check, with
//! [`read_body`]: bounded in size and in time
//! ([`ListenerLimits::body_read_timeout`]).
//!
//! These are a backstop for a service reachable directly. A deployment is
//! still expected to put a reverse proxy in front, with its own limits.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::serve::{Listener, ListenerExt, TapIo};
use ipnetwork::IpNetwork;
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

/// Connections served at once from one IPv4 address or one IPv6 /64.
pub const MAX_CONNECTIONS_PER_ADDRESS: usize = 32;

/// The limits a [`BoundedListener`] applies.
#[derive(Debug, Clone, Copy)]
pub struct ListenerLimits {
    pub header_read_timeout: Duration,
    pub idle_timeout: Duration,
    pub body_read_timeout: Duration,
    pub max_connections: usize,
    pub max_connections_per_address: usize,
}

impl Default for ListenerLimits {
    fn default() -> Self {
        Self {
            header_read_timeout: HEADER_READ_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
            body_read_timeout: BODY_READ_TIMEOUT,
            max_connections: MAX_CONNECTIONS,
            max_connections_per_address: MAX_CONNECTIONS_PER_ADDRESS,
        }
    }
}

/// A `TcpListener` that applies [`ListenerLimits`] to every connection.
pub struct BoundedListener {
    inner: TcpListener,
    limits: ListenerLimits,
    slots: Arc<Semaphore>,
    per_address: Arc<PerAddress>,
    /// Sources exempt from the per-address cap.
    trusted_proxies: Vec<IpNetwork>,
}

impl BoundedListener {
    pub fn new(inner: TcpListener, limits: ListenerLimits) -> Self {
        Self {
            inner,
            limits,
            slots: Arc::new(Semaphore::new(limits.max_connections.max(1))),
            per_address: Arc::new(PerAddress {
                limit: limits.max_connections_per_address.max(1),
                open: Mutex::new(HashMap::new()),
            }),
            trusted_proxies: Vec::new(),
        }
    }

    /// Exempt `trusted_proxies` (the service's `server.trusted_proxies`)
    /// from the per-address cap: every client behind a proxy reaches this
    /// listener from the proxy's address. They still count towards the
    /// connection cap.
    pub fn with_trusted_proxies(mut self, trusted_proxies: &[IpNetwork]) -> Self {
        self.trusted_proxies = trusted_proxies.to_vec();
        self
    }

    /// Admit a connection from `ip` under the per-address cap.
    fn admit(&self, ip: IpAddr) -> Admission {
        let ip = unmapped(ip);
        if self.trusted_proxies.iter().any(|net| net.contains(ip)) {
            return Admission::Exempt;
        }
        match self.per_address.take(AddressKey::of(ip)) {
            Some(slot) => Admission::Counted(slot),
            None => Admission::Refused,
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

/// Serve `listener` under the default [`ListenerLimits`], exempting
/// `trusted_proxies` from the per-address cap.
pub fn bounded(
    listener: TcpListener,
    trusted_proxies: &[IpNetwork],
) -> TapIo<BoundedListener, fn(&mut BoundedIo)> {
    BoundedListener::new(listener, ListenerLimits::default())
        .with_trusted_proxies(trusted_proxies)
        .into_serve()
}

/// An IPv4-mapped IPv6 address as the IPv4 address it carries.
fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// The source a connection is counted against: an IPv4 address, or the /64
/// an IPv6 address is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AddressKey {
    V4(Ipv4Addr),
    V6(u64),
}

impl AddressKey {
    fn of(ip: IpAddr) -> Self {
        match unmapped(ip) {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => Self::V6((u128::from(v6) >> 64) as u64),
        }
    }
}

/// Open connections per source. An entry exists only while a connection
/// from that source is open, so the map holds at most `max_connections`
/// entries.
#[derive(Debug)]
struct PerAddress {
    limit: usize,
    open: Mutex<HashMap<AddressKey, usize>>,
}

impl PerAddress {
    fn take(self: &Arc<Self>, key: AddressKey) -> Option<AddressSlot> {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let count = open.entry(key).or_insert(0);
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        Some(AddressSlot {
            table: Arc::clone(self),
            key,
        })
    }
}

/// One connection's place in its source's count, released on drop.
#[derive(Debug)]
struct AddressSlot {
    table: Arc<PerAddress>,
    key: AddressKey,
}

impl Drop for AddressSlot {
    fn drop(&mut self) {
        let mut open = self
            .table
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Entry::Occupied(mut count) = open.entry(self.key) {
            *count.get_mut() -= 1;
            if *count.get() == 0 {
                count.remove();
            }
        }
    }
}

/// The per-address decision for an accepted connection.
enum Admission {
    /// From a trusted proxy: not counted.
    Exempt,
    Counted(AddressSlot),
    /// Its source already has the most connections it may.
    Refused,
}

impl Listener for BoundedListener {
    type Io = BoundedIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // Wait for a free slot before taking the next connection off the
        // backlog. Nothing closes the semaphore; if something ever did, no
        // slot could be issued again, so stop accepting (graceful shutdown
        // still ends the serve loop) rather than panic.
        let Ok(permit) = self.slots.clone().acquire_owned().await else {
            tracing::error!("the connection limit was closed; accepting no more connections");
            return std::future::pending().await;
        };
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => {
                    let address = match self.admit(addr.ip()) {
                        Admission::Exempt => None,
                        Admission::Counted(slot) => Some(slot),
                        Admission::Refused => {
                            // Close it at once and keep the slot for the
                            // next connection.
                            tracing::debug!(
                                peer = %addr.ip(),
                                "connection refused: its address has the most connections it may"
                            );
                            drop(stream);
                            continue;
                        }
                    };
                    return (BoundedIo::new(stream, self.limits, permit, address), addr);
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
    /// The connection opened with the HTTP/2 preface, whose frames carry
    /// no header block this can see. It is held to the header deadline,
    /// renewed only when the service writes; the peer's bytes alone never
    /// extend it.
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
    /// The task that last polled a read, woken whenever the read deadline
    /// moves so that its next `poll_read` arms the new one. Kept, not taken,
    /// so a move made between two reads still reaches it.
    reader: Option<Waker>,
    _slot: OwnedSemaphorePermit,
    _address: Option<AddressSlot>,
}

impl BoundedIo {
    fn new(
        inner: TcpStream,
        limits: ListenerLimits,
        slot: OwnedSemaphorePermit,
        address: Option<AddressSlot>,
    ) -> Self {
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
            _address: address,
        }
    }

    fn enter_idle(&mut self) {
        self.phase = Phase::Idle;
        self.set_read_deadline(Instant::now() + self.limits.idle_timeout);
    }

    /// Move the read deadline and wake the reading task, so that its next
    /// `poll_read` (which re-arms the timer whenever the deadline differs)
    /// is held to the new one. A wake with no read pending is spurious and
    /// harmless.
    fn set_read_deadline(&mut self, deadline: Instant) {
        self.read_deadline = Some(deadline);
        if let Some(reader) = &self.reader {
            reader.wake_by_ref();
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
                // The preface opens the connection, so the header deadline
                // set when it was accepted still applies. It is not moved.
                self.phase = Phase::Http2;
            }
        }
        match self.phase {
            // Reads never extend an HTTP/2 connection's deadline.
            Phase::Http2 | Phase::Request => {}
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
            // Beyond its own opening SETTINGS, the service writes on an
            // HTTP/2 connection only in answer to frames it accepted, so a
            // write renews the deadline: by the header timeout, the same as
            // every connection's first request, never the idle timeout.
            Phase::Http2 => {
                self.set_read_deadline(Instant::now() + self.limits.header_read_timeout);
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
        // Record the reading task on every poll, whatever the outcome, so a
        // deadline moved by a write wakes it even if no read is pending at
        // that moment.
        match &this.reader {
            Some(reader) if reader.will_wake(cx.waker()) => {}
            _ => this.reader = Some(cx.waker().clone()),
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled()[before..].to_vec();
                this.observe(&filled);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                if let Some(deadline) = this.read_deadline
                    && poll_deadline(&mut this.read_timer, deadline, cx)
                {
                    let what = match this.phase {
                        Phase::Header => "reading the request headers",
                        Phase::Http2 => "the HTTP/2 connection",
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
#[path = "listener_tests.rs"]
mod tests;
