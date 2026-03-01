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
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::prelude::*;
use ratatui::widgets::*;
use tokio::sync::watch;

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

    /// Number of random WebVH DIDs to create on startup for testing.
    /// Each DID gets a server-generated random mnemonic.
    #[arg(long, default_value = "0")]
    create_dids: usize,

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
const Y_AXIS_WIDTH: u16 = 5;
const WARMUP_SECS: f64 = 3.0;
const WARMUP_TICKS: u8 = 30; // 3s × 10 ticks/s

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
    warming_up: bool,
    warmup_secs_left: u8,
    inbound_bps: u64,
    peak_inbound_bps: u64,
    outbound_bps: u64,
    peak_outbound_bps: u64,
    active_workers: u64,
    peak_workers: u64,
    max_workers: usize,
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
            warming_up: false,
            warmup_secs_left: 0,
            inbound_bps: 0,
            peak_inbound_bps: 0,
            outbound_bps: 0,
            peak_outbound_bps: 0,
            active_workers: 0,
            peak_workers: 0,
            max_workers: 0,
        }
    }
}

/// Lock-free metrics shared between worker tasks and the aggregator.
///
/// Counts are updated atomically by each worker; latencies are pushed
/// into a `Mutex<Vec>` that the aggregator swaps out every 100 ms.
/// This avoids per-request channel overhead and scales to any TPS.
struct SharedMetrics {
    total: AtomicU64,
    success: AtomicU64,
    errors: AtomicU64,
    bytes_inbound: AtomicU64,
    bytes_outbound: AtomicU64,
    active_workers: AtomicU64,
    latencies: Mutex<Vec<f64>>,
}

impl SharedMetrics {
    fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            success: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            bytes_inbound: AtomicU64::new(0),
            bytes_outbound: AtomicU64::new(0),
            active_workers: AtomicU64::new(0),
            latencies: Mutex::new(Vec::with_capacity(4096)),
        }
    }
}

/// Internal mutable aggregator — only touched by the aggregator task.
struct Aggregator {
    total: u64,
    success: u64,
    errors: u64,
    // Cumulative values at the start of the current second (for deltas)
    sec_start_total: u64,
    sec_start_errors: u64,
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
    // Warmup
    warmup_remaining: u8,
    baseline_total: u64,
    baseline_success: u64,
    baseline_errors: u64,
    baseline_bytes_in: u64,
    baseline_bytes_out: u64,
    // Network bandwidth tracking
    total_bytes_in: u64,
    total_bytes_out: u64,
    sec_start_bytes_in: u64,
    sec_start_bytes_out: u64,
    inbound_bps: u64,
    peak_inbound_bps: u64,
    outbound_bps: u64,
    peak_outbound_bps: u64,
    peak_workers: u64,
    max_workers: usize,
}

impl Aggregator {
    fn new(did_count: usize, server_url: String, max_workers: usize) -> Self {
        Self {
            total: 0,
            success: 0,
            errors: 0,
            sec_start_total: 0,
            sec_start_errors: 0,
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
            warmup_remaining: WARMUP_TICKS,
            baseline_total: 0,
            baseline_success: 0,
            baseline_errors: 0,
            baseline_bytes_in: 0,
            baseline_bytes_out: 0,
            total_bytes_in: 0,
            total_bytes_out: 0,
            sec_start_bytes_in: 0,
            sec_start_bytes_out: 0,
            inbound_bps: 0,
            peak_inbound_bps: 0,
            outbound_bps: 0,
            peak_outbound_bps: 0,
            peak_workers: 0,
            max_workers,
        }
    }

    /// Absorb a batch of metrics from the shared atomic counters.
    fn update(&mut self, raw_total: u64, raw_success: u64, raw_errors: u64, raw_bytes_in: u64, raw_bytes_out: u64, active_workers: u64, latencies: &[f64]) {
        if active_workers > self.peak_workers {
            self.peak_workers = active_workers;
        }
        self.total = raw_total - self.baseline_total;
        self.success = raw_success - self.baseline_success;
        self.errors = raw_errors - self.baseline_errors;
        self.total_bytes_in = raw_bytes_in - self.baseline_bytes_in;
        self.total_bytes_out = raw_bytes_out - self.baseline_bytes_out;

        for &ms in latencies {
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
        self.sec_latencies.extend_from_slice(latencies);
    }

    fn tick_second(&mut self) {
        let sec_total = self.total - self.sec_start_total;
        let sec_errors = self.errors - self.sec_start_errors;

        push_bounded(&mut self.throughput_hist, sec_total, HISTORY_LEN);
        push_bounded(&mut self.error_hist, sec_errors, HISTORY_LEN);

        let avg_ms = if self.sec_latencies.is_empty() {
            0
        } else {
            (self.sec_latencies.iter().sum::<f64>() / self.sec_latencies.len() as f64) as u64
        };
        push_bounded(&mut self.latency_hist, avg_ms, HISTORY_LEN);

        // Network bandwidth — inbound
        let sec_in = self.total_bytes_in - self.sec_start_bytes_in;
        self.inbound_bps = sec_in;
        if sec_in > self.peak_inbound_bps {
            self.peak_inbound_bps = sec_in;
        }
        self.sec_start_bytes_in = self.total_bytes_in;

        // Network bandwidth — outbound
        let sec_out = self.total_bytes_out - self.sec_start_bytes_out;
        self.outbound_bps = sec_out;
        if sec_out > self.peak_outbound_bps {
            self.peak_outbound_bps = sec_out;
        }
        self.sec_start_bytes_out = self.total_bytes_out;

        self.sec_start_total = self.total;
        self.sec_start_errors = self.errors;
        self.sec_latencies.clear();
    }

    fn snapshot(&self, target_rate: u64, active_workers: u64) -> Snapshot {
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
            warming_up: false,
            warmup_secs_left: 0,
            inbound_bps: self.inbound_bps,
            peak_inbound_bps: self.peak_inbound_bps,
            outbound_bps: self.outbound_bps,
            peak_outbound_bps: self.peak_outbound_bps,
            active_workers,
            peak_workers: self.peak_workers,
            max_workers: self.max_workers,
        }
    }

    fn warmup_snapshot(&self, target_rate: u64, secs_left: u8) -> Snapshot {
        Snapshot {
            warming_up: true,
            warmup_secs_left: secs_left,
            target_rate,
            did_count: self.did_count,
            server_url: self.server_url.clone(),
            ..Snapshot::default()
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
    metrics: Arc<SharedMetrics>,
    shutdown: Arc<AtomicBool>,
    max_concurrent: usize,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    let mut interval = tokio::time::interval(Duration::from_millis(10));
    let mut deficit = 0.0f64;
    let dispatch_start = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        interval.tick().await;
        let rate = target_rate.load(Ordering::Relaxed) as f64;
        // Linear ramp-up: scale effective rate from 0 to target over WARMUP_SECS
        let elapsed = dispatch_start.elapsed().as_secs_f64();
        let ramp = (elapsed / WARMUP_SECS).min(1.0);
        deficit += rate * ramp * 0.01; // 10ms tick
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
            let req_bytes = url.len() as u64;
            let c = client.clone();
            let m = metrics.clone();

            tokio::spawn(async move {
                m.active_workers.fetch_add(1, Ordering::Relaxed);
                let start = Instant::now();
                let result = c.get(&url).send().await;
                let latency = start.elapsed();

                let (ok, resp_bytes) = match result {
                    Ok(resp) => {
                        let ok = resp.status().is_success();
                        let bytes = resp.bytes().await.map(|b| b.len() as u64).unwrap_or(0);
                        (ok, bytes)
                    }
                    Err(_) => (false, 0),
                };

                // Lock-free for counts, brief lock for latency
                m.total.fetch_add(1, Ordering::Relaxed);
                if ok {
                    m.success.fetch_add(1, Ordering::Relaxed);
                } else {
                    m.errors.fetch_add(1, Ordering::Relaxed);
                }
                m.bytes_inbound.fetch_add(resp_bytes, Ordering::Relaxed);
                m.bytes_outbound.fetch_add(req_bytes, Ordering::Relaxed);
                m.latencies.lock().unwrap().push(latency.as_secs_f64() * 1000.0);
                m.active_workers.fetch_sub(1, Ordering::Relaxed);

                drop(permit);
            });
        }
    }
}

/// Reads shared metrics every 100 ms and publishes snapshots to the TUI.
/// Sparkline history is pushed once per second (every 10th tick).
async fn run_aggregator(
    metrics: Arc<SharedMetrics>,
    snap_tx: watch::Sender<Snapshot>,
    target_rate: Arc<AtomicU64>,
    did_count: usize,
    server_url: String,
    max_workers: usize,
    shutdown: Arc<AtomicBool>,
) {
    let mut agg = Aggregator::new(did_count, server_url, max_workers);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut sub_tick: u8 = 0;

    loop {
        tick.tick().await;

        // Swap out the latency vec (brief lock, O(1) pointer swap)
        let batch = std::mem::take(&mut *metrics.latencies.lock().unwrap());

        // Read cumulative counters
        let total = metrics.total.load(Ordering::Relaxed);
        let success = metrics.success.load(Ordering::Relaxed);
        let errors = metrics.errors.load(Ordering::Relaxed);
        let bytes_in = metrics.bytes_inbound.load(Ordering::Relaxed);
        let bytes_out = metrics.bytes_outbound.load(Ordering::Relaxed);
        let active = metrics.active_workers.load(Ordering::Relaxed);

        let rate = target_rate.load(Ordering::Relaxed);

        if agg.warmup_remaining > 0 {
            // During warmup: decrement counter, discard latencies, publish warmup snapshot
            agg.warmup_remaining -= 1;
            let secs_left = (agg.warmup_remaining + 9) / 10; // ceiling division to whole seconds

            if agg.warmup_remaining == 0 {
                // Warmup just ended — capture baselines and reset aggregator state
                agg.baseline_total = total;
                agg.baseline_success = success;
                agg.baseline_errors = errors;
                agg.baseline_bytes_in = bytes_in;
                agg.baseline_bytes_out = bytes_out;
                agg.start = Instant::now();
                agg.latency_buf.clear();
                agg.throughput_hist.clear();
                agg.latency_hist.clear();
                agg.error_hist.clear();
                agg.sec_latencies.clear();
                agg.min_lat = f64::MAX;
                agg.max_lat = 0.0;
                agg.total = 0;
                agg.success = 0;
                agg.errors = 0;
                agg.total_bytes_in = 0;
                agg.total_bytes_out = 0;
                agg.sec_start_total = 0;
                agg.sec_start_errors = 0;
                agg.sec_start_bytes_in = 0;
                agg.sec_start_bytes_out = 0;
                agg.peak_workers = 0;
                sub_tick = 0;
            }

            let _ = snap_tx.send(agg.warmup_snapshot(rate, secs_left));
        } else {
            agg.update(total, success, errors, bytes_in, bytes_out, active, &batch);

            // Push sparkline data once per second
            sub_tick += 1;
            if sub_tick >= 10 {
                agg.tick_second();
                sub_tick = 0;
            }

            let _ = snap_tx.send(agg.snapshot(rate, active));
        }

        if shutdown.load(Ordering::Relaxed) {
            break;
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
    // Split each sparkline area into a y-axis label column and the sparkline.
    // ratatui Sparkline renders from the start of the slice, so we pass only
    // the tail matching the inner width to get immediate scrolling.
    let [tp_y, tp_spark] = Layout::horizontal([
        Constraint::Length(Y_AXIS_WIDTH),
        Constraint::Min(1),
    ])
    .areas(throughput_area);
    let tp_tail = sparkline_tail(&snap.throughput_history, tp_spark.width);
    let tp_max = tp_tail.iter().copied().max().unwrap_or(0);
    render_y_axis(frame, tp_y, &fmt_compact(tp_max));
    frame.render_widget(
        Sparkline::default()
            .data(tp_tail)
            .style(Style::default().fg(Color::Green))
            .block(sparkline_block(
                format!(" Throughput ({} req/s) ", snap.current_rps),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                tp_tail.len(),
            )),
        tp_spark,
    );

    // ---- Latency sparkline ----
    let [lat_y, lat_spark] = Layout::horizontal([
        Constraint::Length(Y_AXIS_WIDTH),
        Constraint::Min(1),
    ])
    .areas(latency_area);
    let lat_tail = sparkline_tail(&snap.latency_history, lat_spark.width);
    let lat_max = lat_tail.iter().copied().max().unwrap_or(0);
    render_y_axis(frame, lat_y, &fmt_compact(lat_max));
    frame.render_widget(
        Sparkline::default()
            .data(lat_tail)
            .style(Style::default().fg(Color::Yellow))
            .block(sparkline_block(
                format!(" Latency ({:.1}ms avg) ", snap.avg_latency_ms),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                lat_tail.len(),
            )),
        lat_spark,
    );

    // ---- Error sparkline ----
    let error_pct = if snap.total > 0 {
        snap.errors as f64 / snap.total as f64 * 100.0
    } else {
        0.0
    };
    let [err_y, err_spark] = Layout::horizontal([
        Constraint::Length(Y_AXIS_WIDTH),
        Constraint::Min(1),
    ])
    .areas(error_area);
    let err_tail = sparkline_tail(&snap.error_history, err_spark.width);
    let err_max = err_tail.iter().copied().max().unwrap_or(0);
    render_y_axis(frame, err_y, &fmt_compact(err_max));
    frame.render_widget(
        Sparkline::default()
            .data(err_tail)
            .style(Style::default().fg(Color::Red))
            .block(sparkline_block(
                format!(
                    " Errors ({:.1}% | {}/s) ",
                    error_pct,
                    snap.error_history.last().unwrap_or(&0)
                ),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                err_tail.len(),
            )),
        err_spark,
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
        Line::from(""),
        Line::from(vec![
            Span::styled("  Workers", Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("   Active:   "),
            Span::styled(
                format!("{:>4} / {}", snap.active_workers, snap.max_workers),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::raw("   Peak:     "),
            Span::styled(
                format!("{:>4} / {}", snap.peak_workers, snap.max_workers),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Network", Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("   In:  "),
            Span::styled(
                format!("{:>10}", fmt_bytes_rate(snap.inbound_bps)),
                Style::default().fg(Color::Magenta),
            ),
            Span::raw("  Peak: "),
            Span::styled(
                format!("{:>10}", fmt_bytes_rate(snap.peak_inbound_bps)),
                Style::default().fg(Color::Magenta),
            ),
        ]),
        Line::from(vec![
            Span::raw("   Out: "),
            Span::styled(
                format!("{:>10}", fmt_bytes_rate(snap.outbound_bps)),
                Style::default().fg(Color::Magenta),
            ),
            Span::raw("  Peak: "),
            Span::styled(
                format!("{:>10}", fmt_bytes_rate(snap.peak_outbound_bps)),
                Style::default().fg(Color::Magenta),
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

    // ---- Warmup popup overlay ----
    if snap.warming_up {
        let popup_area = centered_rect(40, 7, area);
        frame.render_widget(Clear, popup_area);
        let popup_text = vec![
            Line::from(""),
            Line::styled(
                "  Starting test...",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Line::styled(
                format!("  Warming up ({}s remaining)", snap.warmup_secs_left),
                Style::default().fg(Color::Yellow),
            ),
            Line::from(""),
        ];
        frame.render_widget(
            Paragraph::new(popup_text).block(
                Block::bordered()
                    .title(" Initializing ")
                    .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                    .border_style(Style::default().fg(Color::Cyan)),
            ),
            popup_area,
        );
    }
}

// =========================================================================
// Helpers
// =========================================================================

/// Return the tail of `data` that fits inside a bordered sparkline area.
/// The inner width is `area_width - 2` (one char border each side).
fn sparkline_tail(data: &[u64], area_width: u16) -> &[u64] {
    let inner = area_width.saturating_sub(2) as usize;
    let start = data.len().saturating_sub(inner);
    &data[start..]
}

/// Build a bordered block with a coloured top title and a time-axis on the
/// bottom border showing how far back the visible data extends.
fn sparkline_block(title: String, title_style: Style, visible_secs: usize) -> Block<'static> {
    let axis = Style::default().fg(Color::DarkGray);
    let mut block = Block::bordered()
        .title(title)
        .title_style(title_style)
        .border_style(Style::default().fg(Color::DarkGray));

    if visible_secs > 0 {
        block = block
            .title_bottom(Line::styled(format!(" {} ", format_age(visible_secs)), axis).left_aligned())
            .title_bottom(Line::styled(" now ", axis).right_aligned());
    }
    block
}

/// Render y-axis labels (max at top, 0 at bottom) in a narrow column next
/// to a bordered sparkline. Labels are right-aligned and positioned to line
/// up with the first and last inner rows of the adjacent bordered block.
fn render_y_axis(frame: &mut Frame, area: Rect, max_label: &str) {
    if area.height < 3 {
        return;
    }
    let style = Style::default().fg(Color::DarkGray);
    let mut lines: Vec<Line> = vec![Line::from(""); area.height as usize];
    // Max value at the first inner row of the sparkline (row 1)
    lines[1] = Line::styled(max_label, style).right_aligned();
    // Zero at the last inner row (row height-2), if distinct from the max row
    let zero_row = area.height as usize - 2;
    if zero_row > 1 {
        lines[zero_row] = Line::styled("0", style).right_aligned();
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// Format a value compactly for y-axis labels (e.g. "150", "12k", "3M").
fn fmt_compact(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{}M", n / 1_000_000)
    } else if n >= 1_000 {
        format!("{}k", n / 1_000)
    } else {
        n.to_string()
    }
}

/// Format a number of seconds as a relative age label, e.g. "-2m00s" or "-45s".
fn format_age(seconds: usize) -> String {
    if seconds >= 60 {
        format!("-{}m{:02}s", seconds / 60, seconds % 60)
    } else {
        format!("-{}s", seconds)
    }
}

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

/// Format bytes/sec as a human-readable rate string.
fn fmt_bytes_rate(bps: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bps as f64;
    if b >= GB {
        format!("{:.1} GB/s", b / GB)
    } else if b >= MB {
        format!("{:.1} MB/s", b / MB)
    } else if b >= KB {
        format!("{:.1} KB/s", b / KB)
    } else {
        format!("{} B/s", bps)
    }
}

/// Return a centered `Rect` of the given width and height within `area`.
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
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

    // ----- Create random DIDs if requested -----
    if args.create_dids > 0 {
        eprintln!("  Creating {} random DIDs...", args.create_dids);
        for i in 1..=args.create_dids {
            let result = client
                .create_did(&my_secret, None)
                .await
                .with_context(|| format!("failed to create DID {i}/{}", args.create_dids))?;
            eprintln!("    [{i}/{}] {} -> {}", args.create_dids, result.mnemonic, result.did);
        }
        eprintln!("  Created {} DIDs.", args.create_dids);
        eprintln!();
    }

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
    let metrics = Arc::new(SharedMetrics::new());

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
    let d_metrics = metrics.clone();
    let d_workers = args.workers;
    let d_client = http_client.clone();
    tokio::spawn(async move {
        dispatcher(d_rate, d_client, d_mnemonics, d_url, d_metrics, d_shutdown, d_workers).await;
    });

    // Aggregator
    let a_rate = target_rate.clone();
    let a_shutdown = shutdown.clone();
    let a_did_count = mnemonics.len();
    let a_url = server_url.clone();
    let a_metrics = metrics.clone();
    tokio::spawn(async move {
        run_aggregator(a_metrics, snap_tx, a_rate, a_did_count, a_url, d_workers, a_shutdown).await;
    });

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
