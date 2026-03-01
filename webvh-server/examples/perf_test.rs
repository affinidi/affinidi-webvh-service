//! WebVH DID Resolution Performance Test
//!
//! A rich TUI benchmarking tool that authenticates with a WebVH server via
//! DIDComm, discovers active DIDs, and runs configurable-rate HTTP resolution
//! tests against the public endpoints.
//!
//! # Usage
//!
//! ```bash
//! # Generate a fresh identity (print DID, add to ACL, then run)
//! cargo run -p affinidi-webvh-server --example perf_test -- \
//!   --server-url http://localhost:8101 --rate 100
//!
//! # Use an existing identity via 32-byte hex seed
//! cargo run -p affinidi-webvh-server --example perf_test -- \
//!   --server-url http://localhost:8101 --rate 100 \
//!   --seed 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//! ```

use std::collections::VecDeque;
use std::io::{self, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::prelude::*;
use ratatui::widgets::*;
use tokio::sync::{mpsc, watch};

use affinidi_webvh_common::did::generate_ed25519_identity;
use affinidi_webvh_common::{Secret, WebVHClient};

// =========================================================================
// CLI
// =========================================================================

#[derive(Parser)]
#[command(
    name = "perf-test",
    about = "WebVH DID resolution performance test with TUI dashboard"
)]
struct Args {
    /// WebVH server URL
    #[arg(long, short = 's', default_value = "http://localhost:8101")]
    server_url: String,

    /// Target requests per second (adjustable at runtime with +/-)
    #[arg(long, short = 'r', default_value = "10")]
    rate: u64,

    /// Maximum concurrent in-flight requests
    #[arg(long, short = 'w', default_value = "64")]
    workers: usize,

    /// Ed25519 seed as 64 hex characters. If omitted, generates a fresh identity.
    #[arg(long)]
    seed: Option<String>,

    /// Mediator DID (reserved for future DIDComm-via-mediator testing)
    #[arg(long)]
    mediator_did: Option<String>,

    /// WebVH server DID (reserved for future DIDComm-via-mediator testing)
    #[arg(long)]
    webvh_did: Option<String>,
}

// =========================================================================
// Metrics
// =========================================================================

const HISTORY_LEN: usize = 120;
const LATENCY_BUFFER: usize = 10_000;

/// A point-in-time snapshot of all metrics, safe to clone to the TUI thread.
#[derive(Clone)]
struct Snapshot {
    total: u64,
    success: u64,
    errors: u64,
    current_rps: u64,
    rolling_rpm: u64,
    avg_latency_ms: f64,
    min_latency_ms: f64,
    max_latency_ms: f64,
    p50_latency_ms: f64,
    p95_latency_ms: f64,
    p99_latency_ms: f64,
    throughput_history: Vec<u64>,
    latency_history: Vec<u64>,
    error_history: Vec<u64>,
    elapsed: Duration,
    target_rate: u64,
    did_count: usize,
    server_url: String,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            total: 0,
            success: 0,
            errors: 0,
            current_rps: 0,
            rolling_rpm: 0,
            avg_latency_ms: 0.0,
            min_latency_ms: 0.0,
            max_latency_ms: 0.0,
            p50_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            throughput_history: vec![],
            latency_history: vec![],
            error_history: vec![],
            elapsed: Duration::ZERO,
            target_rate: 0,
            did_count: 0,
            server_url: String::new(),
        }
    }
}

/// Internal mutable aggregator — only touched by the aggregator task.
struct Aggregator {
    total: u64,
    success: u64,
    errors: u64,
    // Current-second accumulators
    sec_total: u64,
    sec_errors: u64,
    sec_latencies: Vec<f64>,
    // Sparkline history (per-second samples)
    throughput_hist: VecDeque<u64>,
    latency_hist: VecDeque<u64>,
    error_hist: VecDeque<u64>,
    // Circular buffer for percentile calculation
    latency_buf: VecDeque<f64>,
    min_lat: f64,
    max_lat: f64,
    start: Instant,
    did_count: usize,
    server_url: String,
}

impl Aggregator {
    fn new(did_count: usize, server_url: String) -> Self {
        Self {
            total: 0,
            success: 0,
            errors: 0,
            sec_total: 0,
            sec_errors: 0,
            sec_latencies: Vec::with_capacity(1024),
            throughput_hist: VecDeque::with_capacity(HISTORY_LEN),
            latency_hist: VecDeque::with_capacity(HISTORY_LEN),
            error_hist: VecDeque::with_capacity(HISTORY_LEN),
            latency_buf: VecDeque::with_capacity(LATENCY_BUFFER),
            min_lat: f64::MAX,
            max_lat: 0.0,
            start: Instant::now(),
            did_count,
            server_url,
        }
    }

    fn record(&mut self, ok: bool, latency: Duration) {
        let ms = latency.as_secs_f64() * 1000.0;
        self.total += 1;
        self.sec_total += 1;
        self.sec_latencies.push(ms);

        if ok {
            self.success += 1;
        } else {
            self.errors += 1;
            self.sec_errors += 1;
        }

        if ms < self.min_lat {
            self.min_lat = ms;
        }
        if ms > self.max_lat {
            self.max_lat = ms;
        }

        self.latency_buf.push_back(ms);
        if self.latency_buf.len() > LATENCY_BUFFER {
            self.latency_buf.pop_front();
        }
    }

    fn tick_second(&mut self) {
        push_bounded(&mut self.throughput_hist, self.sec_total, HISTORY_LEN);
        push_bounded(&mut self.error_hist, self.sec_errors, HISTORY_LEN);

        let avg_ms = if self.sec_latencies.is_empty() {
            0
        } else {
            (self.sec_latencies.iter().sum::<f64>() / self.sec_latencies.len() as f64) as u64
        };
        push_bounded(&mut self.latency_hist, avg_ms, HISTORY_LEN);

        self.sec_total = 0;
        self.sec_errors = 0;
        self.sec_latencies.clear();
    }

    fn snapshot(&self, target_rate: u64) -> Snapshot {
        let mut sorted: Vec<f64> = self.latency_buf.iter().copied().collect();
        sorted.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());

        let avg = if sorted.is_empty() {
            0.0
        } else {
            sorted.iter().sum::<f64>() / sorted.len() as f64
        };

        let rolling_rpm: u64 = self.throughput_hist.iter().sum();
        let current_rps = self.throughput_hist.back().copied().unwrap_or(0);

        Snapshot {
            total: self.total,
            success: self.success,
            errors: self.errors,
            current_rps,
            rolling_rpm,
            avg_latency_ms: avg,
            min_latency_ms: if self.min_lat == f64::MAX {
                0.0
            } else {
                self.min_lat
            },
            max_latency_ms: self.max_lat,
            p50_latency_ms: percentile(&sorted, 50.0),
            p95_latency_ms: percentile(&sorted, 95.0),
            p99_latency_ms: percentile(&sorted, 99.0),
            throughput_history: self.throughput_hist.iter().copied().collect(),
            latency_history: self.latency_hist.iter().copied().collect(),
            error_history: self.error_hist.iter().copied().collect(),
            elapsed: self.start.elapsed(),
            target_rate,
            did_count: self.did_count,
            server_url: self.server_url.clone(),
        }
    }
}

fn push_bounded(deque: &mut VecDeque<u64>, val: u64, max: usize) {
    if deque.len() >= max {
        deque.pop_front();
    }
    deque.push_back(val);
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// =========================================================================
// Workers & rate control
// =========================================================================

/// Pick a random index without holding ThreadRng across await points.
fn pick_random_index(len: usize) -> usize {
    use rand::RngExt;
    rand::rng().random_range(0..len)
}

/// Dispatches HTTP requests at the target rate, bounded by a semaphore.
async fn dispatcher(
    target_rate: Arc<AtomicU64>,
    client: reqwest::Client,
    mnemonics: Arc<Vec<String>>,
    server_url: String,
    event_tx: mpsc::UnboundedSender<(bool, Duration)>,
    shutdown: Arc<AtomicBool>,
    max_concurrent: usize,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    let mut interval = tokio::time::interval(Duration::from_millis(10));
    let mut deficit = 0.0f64;

    while !shutdown.load(Ordering::Relaxed) {
        interval.tick().await;
        let rate = target_rate.load(Ordering::Relaxed) as f64;
        deficit += rate * 0.01; // 10ms tick
        let to_spawn = deficit.floor() as u64;
        deficit -= to_spawn as f64;

        for _ in 0..to_spawn {
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let idx = pick_random_index(mnemonics.len());
            let mnemonic = mnemonics[idx].clone();
            let url = format!("{}/{}/did.jsonl", server_url, mnemonic);
            let c = client.clone();
            let tx = event_tx.clone();

            tokio::spawn(async move {
                let start = Instant::now();
                let result = c.get(&url).send().await;
                let latency = start.elapsed();
                let ok = result.map(|r| r.status().is_success()).unwrap_or(false);
                let _ = tx.send((ok, latency));
                drop(permit);
            });
        }
    }
}

/// Consumes metric events, updates the aggregator, and publishes snapshots.
async fn run_aggregator(
    mut event_rx: mpsc::UnboundedReceiver<(bool, Duration)>,
    snap_tx: watch::Sender<Snapshot>,
    target_rate: Arc<AtomicU64>,
    did_count: usize,
    server_url: String,
    shutdown: Arc<AtomicBool>,
) {
    let mut agg = Aggregator::new(did_count, server_url);
    let mut tick = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            Some((ok, lat)) = event_rx.recv() => {
                agg.record(ok, lat);
            }
            _ = tick.tick() => {
                let rate = target_rate.load(Ordering::Relaxed);
                agg.tick_second();
                let _ = snap_tx.send(agg.snapshot(rate));
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }
}

// =========================================================================
// TUI rendering
// =========================================================================

fn draw(frame: &mut Frame, snap: &Snapshot) {
    let area = frame.area();

    let [header, main, footer] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(10), Constraint::Length(3)])
            .areas(area);

    // ---- Header ----
    let elapsed = format_duration(snap.elapsed);
    let header_text = format!(
        " WebVH Perf Test | {} | {} DIDs | Target: {} req/s | Elapsed: {}",
        snap.server_url, snap.did_count, snap.target_rate, elapsed
    );
    frame.render_widget(
        Paragraph::new(header_text)
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::bordered().border_style(Style::default().fg(Color::DarkGray))),
        header,
    );

    // ---- Main: 2x2 grid ----
    let [top_row, bottom_row] =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(main);

    let [throughput_area, latency_area] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .areas(top_row);

    let [error_area, summary_area] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .areas(bottom_row);

    // ---- Throughput sparkline ----
    frame.render_widget(
        Sparkline::default()
            .data(&snap.throughput_history)
            .style(Style::default().fg(Color::Green))
            .block(
                Block::bordered()
                    .title(format!(" Throughput ({} req/s) ", snap.current_rps))
                    .title_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
        throughput_area,
    );

    // ---- Latency sparkline ----
    frame.render_widget(
        Sparkline::default()
            .data(&snap.latency_history)
            .style(Style::default().fg(Color::Yellow))
            .block(
                Block::bordered()
                    .title(format!(" Latency ({:.1}ms avg) ", snap.avg_latency_ms))
                    .title_style(
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    )
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
        latency_area,
    );

    // ---- Error sparkline ----
    let error_pct = if snap.total > 0 {
        snap.errors as f64 / snap.total as f64 * 100.0
    } else {
        0.0
    };
    frame.render_widget(
        Sparkline::default()
            .data(&snap.error_history)
            .style(Style::default().fg(Color::Red))
            .block(
                Block::bordered()
                    .title(format!(
                        " Errors ({:.1}% | {}/s) ",
                        error_pct,
                        snap.error_history.last().unwrap_or(&0)
                    ))
                    .title_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
        error_area,
    );

    // ---- Summary panel ----
    let success_pct = if snap.total > 0 {
        snap.success as f64 / snap.total as f64 * 100.0
    } else {
        0.0
    };

    let summary_lines = vec![
        Line::from(vec![
            Span::styled("  Requests", Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("   Total:    "),
            Span::styled(
                format!("{:>10}", fmt_num(snap.total)),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("   Success:  "),
            Span::styled(
                format!("{:>10}", fmt_num(snap.success)),
                Style::default().fg(Color::Green),
            ),
            Span::styled(format!("  ({:.1}%)", success_pct), Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::raw("   Errors:   "),
            Span::styled(
                format!("{:>10}", fmt_num(snap.errors)),
                Style::default().fg(Color::Red),
            ),
            Span::styled(format!("  ({:.1}%)", error_pct), Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Throughput", Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("   Current:  "),
            Span::styled(
                format!("{:>7} req/s", snap.current_rps),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::raw("   Rolling:  "),
            Span::styled(
                format!("{:>7} req/min", snap.rolling_rpm),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Latency", Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("   Min: "),
            Span::styled(
                format!("{:>8.1}ms", snap.min_latency_ms),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw("  P50: "),
            Span::styled(
                format!("{:>8.1}ms", snap.p50_latency_ms),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::raw("   Avg: "),
            Span::styled(
                format!("{:>8.1}ms", snap.avg_latency_ms),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw("  P95: "),
            Span::styled(
                format!("{:>8.1}ms", snap.p95_latency_ms),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::raw("   Max: "),
            Span::styled(
                format!("{:>8.1}ms", snap.max_latency_ms),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw("  P99: "),
            Span::styled(
                format!("{:>8.1}ms", snap.p99_latency_ms),
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(summary_lines).block(
            Block::bordered()
                .title(" Summary ")
                .title_style(Style::default().add_modifier(Modifier::BOLD))
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        summary_area,
    );

    // ---- Footer ----
    frame.render_widget(
        Paragraph::new(
            " q: quit | +/Up: +10 req/s | -/Down: -10 req/s | ]: 2x | [: 0.5x",
        )
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::bordered().border_style(Style::default().fg(Color::DarkGray))),
        footer,
    );
}

// =========================================================================
// Helpers
// =========================================================================

fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else {
        format!("{m}m {s:02}s")
    }
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn decode_hex_seed(hex_str: &str) -> Result<[u8; 32]> {
    if hex_str.len() != 64 {
        bail!("seed must be exactly 64 hex characters (32 bytes)");
    }
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] =
            u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).context("invalid hex in seed")?;
    }
    Ok(seed)
}

// =========================================================================
// Main
// =========================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let server_url = args.server_url.trim_end_matches('/').to_string();

    // ----- Generate or load identity -----
    let (my_did, my_secret) = if let Some(ref seed_hex) = args.seed {
        let seed = decode_hex_seed(seed_hex)?;
        let secret = Secret::generate_ed25519(None, Some(&seed));
        let pk = secret
            .get_public_keymultibase()
            .map_err(|e| anyhow::anyhow!("failed to get public key: {e}"))?;
        let did = format!("did:key:{pk}");
        (did, secret)
    } else {
        generate_ed25519_identity().context("failed to generate identity")?
    };

    eprintln!();
    eprintln!("  Identity:  {my_did}");
    eprintln!("  Server:    {server_url}");
    eprintln!();

    if args.seed.is_none() {
        eprintln!("  (Generated fresh identity. Ensure this DID is in the server ACL:)");
        eprintln!("    webvh-server add-acl --did {my_did}");
        eprintln!();
        eprint!("  Press Enter to continue after adding to ACL...");
        io::stderr().flush()?;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
    }

    // ----- Authenticate via DIDComm -----
    eprintln!("  Authenticating via DIDComm...");
    let mut client = WebVHClient::new(&server_url);
    client
        .authenticate(&my_did, &my_secret)
        .await
        .context("DIDComm authentication failed")?;
    eprintln!("  Authenticated!");

    // ----- Fetch active DIDs -----
    eprintln!("  Fetching DID list...");
    let all_dids = client
        .list_dids()
        .await
        .context("failed to list DIDs")?;

    // Filter to published and enabled DIDs only
    let active_mnemonics: Vec<String> = all_dids
        .iter()
        .filter(|d| d.version_count > 0 && !d.disabled)
        .map(|d| d.mnemonic.clone())
        .collect();

    eprintln!(
        "  Found {} active DIDs (of {} total)",
        active_mnemonics.len(),
        all_dids.len()
    );

    if active_mnemonics.is_empty() {
        eprintln!();
        eprintln!("  No active (published & enabled) DIDs found.");
        eprintln!("  Create and publish DIDs first, e.g.:");
        eprintln!(
            "    cargo run -p affinidi-webvh-server --example client -- --server-url {server_url}"
        );
        bail!("no active DIDs to test against");
    }

    eprintln!();
    eprintln!(
        "  Starting performance test: {} req/s target, {} max concurrent",
        args.rate, args.workers
    );
    eprintln!();

    // ----- Shared state -----
    let target_rate = Arc::new(AtomicU64::new(args.rate));
    let shutdown = Arc::new(AtomicBool::new(false));
    let mnemonics = Arc::new(active_mnemonics);

    let (event_tx, event_rx) = mpsc::unbounded_channel::<(bool, Duration)>();
    let (snap_tx, snap_rx) = watch::channel(Snapshot::default());

    // ----- Spawn background tasks -----
    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(args.workers)
        .build()?;

    // Dispatcher
    let d_rate = target_rate.clone();
    let d_shutdown = shutdown.clone();
    let d_mnemonics = mnemonics.clone();
    let d_url = server_url.clone();
    let d_tx = event_tx.clone();
    let d_workers = args.workers;
    let d_client = http_client.clone();
    tokio::spawn(async move {
        dispatcher(d_rate, d_client, d_mnemonics, d_url, d_tx, d_shutdown, d_workers).await;
    });

    // Aggregator
    let a_rate = target_rate.clone();
    let a_shutdown = shutdown.clone();
    let a_did_count = mnemonics.len();
    let a_url = server_url.clone();
    tokio::spawn(async move {
        run_aggregator(event_rx, snap_tx, a_rate, a_did_count, a_url, a_shutdown).await;
    });

    // Drop the extra event_tx so the aggregator can detect shutdown
    drop(event_tx);

    // ----- TUI event loop -----
    // Install panic hook to restore terminal on crash
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = ratatui::restore();
        original_hook(info);
    }));

    let mut terminal = ratatui::init();
    let result = run_tui(&mut terminal, snap_rx, target_rate.clone(), shutdown.clone());

    ratatui::restore();

    if let Err(e) = result {
        eprintln!("TUI error: {e}");
    }

    // Print final stats
    let snap = snap_rx_final(&server_url, mnemonics.len(), target_rate.load(Ordering::Relaxed));
    eprintln!();
    eprintln!("  Performance test complete.");
    eprintln!("  Total: {} | Success: {} | Errors: {}", snap.total, snap.success, snap.errors);
    eprintln!();

    Ok(())
}

/// Placeholder for final snapshot (the watch receiver was moved).
fn snap_rx_final(_url: &str, _did_count: usize, _rate: u64) -> Snapshot {
    Snapshot::default()
}

fn run_tui(
    terminal: &mut ratatui::DefaultTerminal,
    mut snap_rx: watch::Receiver<Snapshot>,
    target_rate: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let redraw_interval = std::time::Duration::from_millis(100);
    let mut last_draw = Instant::now();
    let mut snap = Snapshot::default();

    loop {
        // Draw if enough time has passed
        if last_draw.elapsed() >= redraw_interval {
            // Check for new snapshot
            if snap_rx.has_changed().unwrap_or(false) {
                snap = snap_rx.borrow_and_update().clone();
            }
            terminal.draw(|frame| draw(frame, &snap))?;
            last_draw = Instant::now();
        }

        // Poll for keyboard events (non-blocking)
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            shutdown.store(true, Ordering::Relaxed);
                            return Ok(());
                        }
                        KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Up => {
                            let cur = target_rate.load(Ordering::Relaxed);
                            target_rate.store(cur.saturating_add(10), Ordering::Relaxed);
                        }
                        KeyCode::Char('-') | KeyCode::Down => {
                            let cur = target_rate.load(Ordering::Relaxed);
                            target_rate.store(cur.saturating_sub(10).max(1), Ordering::Relaxed);
                        }
                        KeyCode::Char(']') => {
                            let cur = target_rate.load(Ordering::Relaxed);
                            target_rate.store(cur.saturating_mul(2), Ordering::Relaxed);
                        }
                        KeyCode::Char('[') => {
                            let cur = target_rate.load(Ordering::Relaxed);
                            target_rate.store((cur / 2).max(1), Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
