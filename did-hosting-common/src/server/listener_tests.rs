//! Tests for [`super`].

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
        max_connections_per_address: 2,
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
    for b in b"GET / HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".iter() {
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

async fn serve_listener(listener: BoundedListener) -> SocketAddr {
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/", get(|| async { "ok" }));
    tokio::spawn(async move {
        axum::serve(
            listener.into_serve(),
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

fn per_address_limits() -> ListenerLimits {
    ListenerLimits {
        header_read_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(30),
        max_connections: 8,
        max_connections_per_address: 2,
        ..short()
    }
}

/// One address cannot hold more than its share of the connection cap:
/// past it, a connection is closed at once, and the slots it would
/// have taken stay free.
#[tokio::test]
async fn connections_past_the_per_address_cap_are_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = serve_listener(BoundedListener::new(listener, per_address_limits())).await;
    let mut first = TcpStream::connect(addr).await.unwrap();
    let mut second = TcpStream::connect(addr).await.unwrap();
    assert!(get_ok(&mut first).await.starts_with("HTTP/1.1 200"));
    assert!(get_ok(&mut second).await.starts_with("HTTP/1.1 200"));

    let mut third = TcpStream::connect(addr).await.unwrap();
    assert!(
        closed_within(&mut third, Duration::from_secs(3)).await,
        "a third connection from the address is closed"
    );

    // Closing one frees its place for the address.
    drop(first);
    let mut fourth = None;
    for _ in 0..50 {
        let mut s = TcpStream::connect(addr).await.unwrap();
        if s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .is_ok()
        {
            let mut buf = [0u8; 256];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(500), s.read(&mut buf)).await
                && n > 0
            {
                assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
                fourth = Some(s);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(fourth.is_some(), "served once the address has a place free");
}

/// A trusted proxy carries many clients' connections, so it is held to
/// the connection cap only.
#[tokio::test]
async fn a_trusted_proxy_is_not_held_to_the_per_address_cap() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bounded = BoundedListener::new(listener, per_address_limits())
        .with_trusted_proxies(&["127.0.0.0/8".parse().unwrap()]);
    let addr = serve_listener(bounded).await;
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut s = TcpStream::connect(addr).await.unwrap();
        assert!(get_ok(&mut s).await.starts_with("HTTP/1.1 200"));
        held.push(s);
    }
}

#[test]
fn ipv6_addresses_are_counted_by_their_64() {
    let key = |s: &str| AddressKey::of(s.parse().unwrap());
    assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff::9"));
    assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
    // An IPv4-mapped address counts as the IPv4 address it carries.
    assert_eq!(key("::ffff:192.0.2.7"), key("192.0.2.7"));
    assert_ne!(key("192.0.2.7"), key("192.0.2.8"));

    let table = Arc::new(PerAddress {
        limit: 2,
        open: Mutex::new(HashMap::new()),
    });
    let a = table.take(key("2001:db8::1")).unwrap();
    let _b = table.take(key("2001:db8::2")).unwrap();
    assert!(table.take(key("2001:db8::3")).is_none(), "the /64 is full");
    assert!(table.take(key("2001:db8:0:1::1")).is_some(), "another /64");
    drop(a);
    assert!(table.take(key("2001:db8::3")).is_some(), "a place freed");
}

/// A connected `BoundedIo` and the peer's end.
async fn pair(limits: ListenerLimits) -> (BoundedIo, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
    (BoundedIo::new(server, limits, permit, None), client)
}

#[derive(Default)]
struct CountWakes(std::sync::atomic::AtomicUsize);

impl std::task::Wake for CountWakes {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A deadline moved by a write while no read is pending (the last read
/// completed) still wakes the reading task, so its next poll arms it.
#[tokio::test]
async fn a_deadline_moved_between_reads_wakes_the_reader() {
    let (mut io, mut client) = pair(short()).await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    // Let the request arrive, so the first poll completes the read and
    // no read is left pending.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let wakes = Arc::new(CountWakes::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    let mut storage = [0u8; 256];
    loop {
        let mut buf = ReadBuf::new(&mut storage);
        match Pin::new(&mut io).poll_read(&mut cx, &mut buf) {
            Poll::Ready(Ok(())) if !buf.filled().is_empty() => break,
            Poll::Ready(r) => panic!("read ended: {r:?}"),
            Poll::Pending => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }
    assert_eq!(io.phase, Phase::Request);

    // The response goes out: the connection is idle, and its read
    // deadline moves while no read is pending.
    let before = wakes.0.load(std::sync::atomic::Ordering::SeqCst);
    io.wrote(10);
    assert_eq!(io.phase, Phase::Idle);
    assert!(
        wakes.0.load(std::sync::atomic::Ordering::SeqCst) > before,
        "the reading task is woken"
    );

    // Its next poll is held to the new deadline.
    let deadline = io.read_deadline.unwrap();
    let mut buf = ReadBuf::new(&mut storage);
    assert!(Pin::new(&mut io).poll_read(&mut cx, &mut buf).is_pending());
    assert_eq!(io.read_timer.deadline(), deadline);
}

/// The HTTP/2 preface does not earn the idle timeout, and the peer's
/// bytes never extend the deadline; only a write by the service renews
/// it, by the header timeout.
#[tokio::test]
async fn the_http2_preface_does_not_extend_the_deadline() {
    let limits = ListenerLimits {
        header_read_timeout: Duration::from_millis(300),
        idle_timeout: Duration::from_secs(60),
        ..short()
    };
    let (mut io, _client) = pair(limits).await;
    let accepted = io.read_deadline.unwrap();
    io.observe(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    assert_eq!(io.phase, Phase::Http2);
    assert_eq!(
        io.read_deadline,
        Some(accepted),
        "the preface moves nothing"
    );

    tokio::time::sleep(Duration::from_millis(20)).await;
    io.observe(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    io.observe(b"x");
    assert_eq!(io.read_deadline, Some(accepted), "nor do later bytes");

    io.wrote(9);
    let renewed = io.read_deadline.unwrap();
    assert!(renewed > accepted);
    assert!(renewed <= Instant::now() + limits.header_read_timeout);
}

/// A trickle after the preface is closed at the header deadline, not
/// kept for the idle timeout.
#[tokio::test]
async fn a_trickle_after_the_http2_preface_is_closed() {
    let limits = ListenerLimits {
        header_read_timeout: Duration::from_millis(300),
        idle_timeout: Duration::from_secs(30),
        ..short()
    };
    let addr = serve(limits).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let started = Instant::now();
    let _ = stream.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await;
    let mut closed = false;
    while started.elapsed() < Duration::from_secs(5) {
        if stream.write_all(b"\0").await.is_err() {
            closed = true;
            break;
        }
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(100), stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                closed = true;
                break;
            }
            _ => {}
        }
    }
    assert!(closed, "closed well before the idle timeout");
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// A closed connection limit stops `accept` without a panic.
#[tokio::test]
async fn a_closed_connection_limit_stops_accepting_without_a_panic() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut bounded = BoundedListener::new(listener, short());
    bounded.slots.close();
    let _client = TcpStream::connect(addr).await.unwrap();
    let accepted = tokio::time::timeout(Duration::from_millis(300), bounded.accept()).await;
    assert!(accepted.is_err(), "no connection is accepted");
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
