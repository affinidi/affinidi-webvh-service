//! WebVH DID Resolution Performance Test
//!
//! A rich TUI benchmarking tool for load-testing WebVH DID resolution.
//!
//! Supports two modes:
//! - **Server mode** (default): authenticates with a DID Hosting control plane
//!   (`did-hosting-control` or the `did-hosting-daemon`'s embedded control plane)
//!   via DIDComm, lists active DIDs, and benchmarks resolution against
//!   each DID's own hosting URL. The management endpoint
//!   (`--server-url`) and the public hosting URL (`--hosting-url`,
//!   embedded in newly minted DIDs) are different hosts in a control-
//!   plane deployment. Requires `--webvh-did` (the service's DID, used
//!   as the DIDComm `to` field of the auth message).
//! - **File mode** (`--did-file`): reads `did:webvh:...` identifiers from a
//!   file and derives resolution URLs directly. No authentication needed —
//!   works against any hosted WebVH DID.
//!
//! # Usage
//!
//! ```bash
//! # Server mode against a control plane: management vs. hosting are split
//! cargo run -p did-hosting-server --example perf_test -- \
//!   --server-url https://admin.example.com \
//!   --hosting-url https://webvh.example.com \
//!   --webvh-did did:webvh:<scid>:webvh.example.com \
//!   --create-dids 10 --rate 100
//!
//! # Server mode against a single-host did-hosting-server (no --hosting-url needed)
//! cargo run -p did-hosting-server --example perf_test -- \
//!   --server-url https://webvh.example.com \
//!   --webvh-did did:webvh:<scid>:webvh.example.com \
//!   --rate 100
//!
//! # File mode: test against any hosted DIDs
//! cargo run -p did-hosting-server --example perf_test -- \
//!   --did-file my-dids.txt --rate 100
//! ```

use std::collections::VecDeque;
use std::io::{self, Write as _};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::prelude::*;
use sysinfo::{CpuRefreshKind, System};
use tokio::sync::watch;

use did_hosting_common::did::generate_ed25519_identity;
use did_hosting_common::{Secret, WebVHClient};

// =========================================================================
// CLI
// =========================================================================

#[derive(Parser)]
#[command(
    name = "perf-test",
    about = "WebVH DID resolution performance test with TUI dashboard"
)]
struct Args {
    /// Management URL (control plane or standalone did-hosting-server). All
    /// authenticated API calls go here.
    #[arg(long, short = 's', default_value = "http://localhost:8530")]
    server_url: String,

    /// Public hosting URL where DID logs are served. When omitted,
    /// `--server-url` is used for both. Required when management and
    /// hosting are on different origins (e.g. a control plane at
    /// `admin.example.com` minting DIDs that resolve at
    /// `webvh.example.com`) — otherwise `--create-dids` mints DIDs that
    /// no peer can resolve.
    #[arg(long)]
    hosting_url: Option<String>,

    /// Target requests per second (adjustable at runtime with +/-)
    #[arg(long, short = 'r', default_value = "10")]
    rate: u64,

    /// Maximum concurrent in-flight requests
    #[arg(long, short = 'w', default_value = "64")]
    workers: usize,

    /// Number of tokio worker threads. Defaults to the number of CPU
    /// cores reported by `std::thread::available_parallelism()`. Note:
    /// extra threads only help if there is enough concurrent work to
    /// fan out — at low `--rate` most requests run sequentially and
    /// only a couple of cores will show load.
    #[arg(long, short = 'T')]
    threads: Option<usize>,

    /// Ed25519 seed as 64 hex characters. If omitted, generates a fresh identity.
    #[arg(long)]
    seed: Option<String>,

    /// Number of random WebVH DIDs to create on startup for testing.
    /// Each DID gets a server-generated random mnemonic.
    #[arg(long, default_value = "0")]
    create_dids: usize,

    /// Number of DIDs to create in parallel (used with --create-dids)
    #[arg(long, default_value = "4")]
    create_parallel: usize,

    /// Mediator DID. Currently unused; will route the DIDComm auth
    /// message through a mediator when full DIDComm transport lands.
    #[arg(long)]
    mediator_did: Option<String>,

    /// Request timeout in seconds
    #[arg(long, short = 't', default_value = "5")]
    timeout: u64,

    /// File containing `did:webvh:...` identifiers (one per line). When
    /// provided, skips authentication and DID listing — resolution URLs
    /// are derived directly from the DIDs. Useful for testing against any
    /// hosted DID Hosting server without needing ACL access. Lines starting
    /// with '#' and blank lines are ignored.
    #[arg(long, short = 'f')]
    did_file: Option<String>,

    /// DID of the DID Hosting service we're authenticating against. Used as the
    /// DIDComm `to` field of the signed authenticate message. Required
    /// in server mode (when `--did-file` is not set).
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
/// Per-tick (10ms) exponential smoothing factor for rate changes.
/// With 0.02, effective rate reaches ~87% in 1s, ~98% in 2s, ~99.8% in 3s.
const RATE_SMOOTHING: f64 = 0.02;

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
    worker_history: Vec<u64>,
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
    /// Per-core CPU utilization (0..100). Empty until the first sysinfo
    /// refresh completes; the summary panel hides the CPU section when
    /// this is empty.
    cpu_per_core: Vec<f32>,
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
            worker_history: vec![],
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
            cpu_per_core: Vec::new(),
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
    worker_hist: VecDeque<u64>,
    last_active_workers: u64,
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
    // CPU sampling. `cpu_system` is refreshed every other 100ms tick to
    // honour sysinfo's MINIMUM_CPU_UPDATE_INTERVAL (200ms); its first
    // call always returns 0% per CPU because percentages are computed
    // from deltas, so we kick it once on construction.
    cpu_system: System,
    cpu_per_core: Vec<f32>,
    cpu_tick_phase: u8,
}

impl Aggregator {
    fn new(did_count: usize, server_url: String, max_workers: usize) -> Self {
        let mut cpu_system = System::new();
        cpu_system.refresh_cpu_specifics(CpuRefreshKind::nothing().with_cpu_usage());
        let core_count = cpu_system.cpus().len();

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
            worker_hist: VecDeque::with_capacity(HISTORY_LEN),
            last_active_workers: 0,
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
            cpu_system,
            cpu_per_core: vec![0.0; core_count],
            cpu_tick_phase: 0,
        }
    }

    /// Refresh per-core CPU usage. Caller throttles to 200ms+ between
    /// invocations so sysinfo's deltas are meaningful.
    fn sample_cpu(&mut self) {
        self.cpu_system
            .refresh_cpu_specifics(CpuRefreshKind::nothing().with_cpu_usage());
        self.cpu_per_core = self
            .cpu_system
            .cpus()
            .iter()
            .map(|c| c.cpu_usage())
            .collect();
    }

    /// Absorb a batch of metrics from the shared atomic counters.
    #[allow(clippy::too_many_arguments)]
    fn update(
        &mut self,
        raw_total: u64,
        raw_success: u64,
        raw_errors: u64,
        raw_bytes_in: u64,
        raw_bytes_out: u64,
        active_workers: u64,
        latencies: &[f64],
    ) {
        if active_workers > self.peak_workers {
            self.peak_workers = active_workers;
        }
        self.last_active_workers = active_workers;
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
        push_bounded(&mut self.worker_hist, self.last_active_workers, HISTORY_LEN);

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
            worker_history: self.worker_hist.iter().copied().collect(),
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
            cpu_per_core: self.cpu_per_core.clone(),
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
    urls: Arc<Vec<String>>,
    metrics: Arc<SharedMetrics>,
    shutdown: Arc<AtomicBool>,
    max_concurrent: usize,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    let mut interval = tokio::time::interval(Duration::from_millis(10));
    let mut deficit = 0.0f64;
    let mut effective_rate = 0.0f64;
    let dispatch_start = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        interval.tick().await;
        let target = target_rate.load(Ordering::Relaxed) as f64;
        // Smooth rate changes: exponentially converge toward target (~3s to settle)
        effective_rate += (target - effective_rate) * RATE_SMOOTHING;
        // Startup ramp: linearly scale 0→1 over WARMUP_SECS
        let elapsed = dispatch_start.elapsed().as_secs_f64();
        let ramp = (elapsed / WARMUP_SECS).min(1.0);
        deficit += effective_rate * ramp * 0.01; // 10ms tick
        let to_spawn = deficit.floor() as u64;
        deficit -= to_spawn as f64;

        for _ in 0..to_spawn {
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let idx = pick_random_index(urls.len());
            let url = urls[idx].clone();
            let req_bytes = url.len() as u64;
            let c = client.clone();
            let m = metrics.clone();

            tokio::spawn(async move {
                m.active_workers.fetch_add(1, Ordering::Relaxed);
                let start = Instant::now();
                let result = c.get(&url).send().await;
                let latency = start.elapsed();

                let (ok, resp_bytes, timed_out) = match result {
                    Ok(resp) => {
                        let ok = resp.status().is_success();
                        let bytes = resp.bytes().await.map(|b| b.len() as u64).unwrap_or(0);
                        (ok, bytes, false)
                    }
                    Err(e) => (false, 0, e.is_timeout()),
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
                if !timed_out {
                    m.latencies
                        .lock()
                        .unwrap()
                        .push(latency.as_secs_f64() * 1000.0);
                }
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

        // CPU usage refreshed every other 100ms tick (= 200ms, the
        // minimum interval sysinfo asks for between samples). Cheap
        // enough on every other tick that we don't need a separate
        // task — keeps the snapshot path single-threaded.
        agg.cpu_tick_phase = agg.cpu_tick_phase.wrapping_add(1);
        if agg.cpu_tick_phase.is_multiple_of(2) {
            agg.sample_cpu();
        }

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
            let secs_left = agg.warmup_remaining.div_ceil(10); // ceiling division to whole seconds

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
                agg.worker_hist.clear();
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
    if area.width < 60 || area.height < 16 {
        // Terminal too small to render the dashboard cleanly. Bail
        // silently — ratatui will still paint a blank frame.
        return;
    }

    let [header_area, main_area, footer_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(10),
        Constraint::Length(1),
    ])
    .areas(area);

    let [top_row, bottom_row] =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(main_area);

    let [throughput_area, latency_area] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top_row);

    let [left_bottom, summary_area] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .areas(bottom_row);

    let [worker_area, error_area] =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
            .areas(left_bottom);

    let buf = frame.buffer_mut();

    paint_header(buf, header_area, snap);

    let tp_chart_w = throughput_area.width.saturating_sub(Y_AXIS_WIDTH + 2);
    let tp_tail = sparkline_tail(&snap.throughput_history, tp_chart_w);
    paint_chart_panel(
        buf,
        throughput_area,
        &format!("Throughput  {} req/s", snap.current_rps),
        tp_tail,
        None,
        &BAR_THROUGHPUT,
    );

    let lat_chart_w = latency_area.width.saturating_sub(Y_AXIS_WIDTH + 2);
    let lat_tail = sparkline_tail(&snap.latency_history, lat_chart_w);
    paint_chart_panel(
        buf,
        latency_area,
        &format!("Latency  {:.1}ms avg", snap.avg_latency_ms),
        lat_tail,
        None,
        &BAR_LATENCY,
    );

    let wk_chart_w = worker_area.width.saturating_sub(Y_AXIS_WIDTH + 2);
    let wk_tail = sparkline_tail(&snap.worker_history, wk_chart_w);
    let wk_max_floor = wk_tail
        .iter()
        .copied()
        .max()
        .unwrap_or(0)
        .max(snap.max_workers as u64);
    paint_chart_panel(
        buf,
        worker_area,
        &format!(
            "Workers  {}/{} · peak {}",
            snap.active_workers, snap.max_workers, snap.peak_workers
        ),
        wk_tail,
        Some(wk_max_floor),
        &BAR_WORKERS,
    );

    let error_pct = if snap.total > 0 {
        snap.errors as f64 / snap.total as f64 * 100.0
    } else {
        0.0
    };
    let err_chart_w = error_area.width.saturating_sub(Y_AXIS_WIDTH + 2);
    let err_tail = sparkline_tail(&snap.error_history, err_chart_w);
    paint_chart_panel(
        buf,
        error_area,
        &format!(
            "Errors  {:.2}% · {}/s",
            error_pct,
            snap.error_history.last().copied().unwrap_or(0)
        ),
        err_tail,
        None,
        &BAR_ERRORS,
    );

    paint_summary_panel(buf, summary_area, snap);
    paint_footer(buf, footer_area);

    if snap.warming_up {
        paint_warmup_overlay(buf, area, snap);
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

// ---- Theme & paint helpers ----------------------------------------------
//
// The dashboard renders directly into the ratatui buffer rather than
// composing widgets, so we have pixel-level control over colour, border
// style, and per-cell shading. Style language is borrowed from the
// affinidi mediator-setup wizard: rounded gradient borders fading
// purple → blue, brand title colour, and per-panel "stress band" bar
// charts where each cell is coloured by its vertical position.

const PALETTE_BORDER_LOW: (u8, u8, u8) = (160, 100, 220); // purple top
const PALETTE_BORDER_HIGH: (u8, u8, u8) = (50, 120, 220); // blue bottom
const PALETTE_TITLE: Color = Color::Rgb(140, 180, 255);
const PALETTE_ACCENT: Color = Color::Rgb(72, 209, 204);
const PALETTE_TEXT: Color = Color::White;
const PALETTE_DIM: Color = Color::Rgb(170, 170, 190);
const PALETTE_MUTED: Color = Color::Rgb(110, 110, 130);
const PALETTE_OVERLAY_BG: Color = Color::Rgb(20, 20, 32);

const HEALTH_GOOD: Color = Color::Rgb(80, 220, 130);
const HEALTH_WARN: Color = Color::Rgb(230, 200, 70);
const HEALTH_BAD: Color = Color::Rgb(230, 90, 90);

const NET_OUT: Color = Color::Rgb(220, 130, 230);
const NET_IN: Color = Color::Rgb(130, 220, 230);

#[derive(Clone, Copy)]
struct BarPalette {
    bottom: (u8, u8, u8),
    middle: (u8, u8, u8),
    top: (u8, u8, u8),
}

const BAR_THROUGHPUT: BarPalette = BarPalette {
    bottom: (40, 100, 90),
    middle: (60, 200, 180),
    top: (180, 240, 220),
};
const BAR_LATENCY: BarPalette = BarPalette {
    bottom: (60, 160, 120),
    middle: (220, 200, 80),
    top: (230, 90, 60),
};
const BAR_WORKERS: BarPalette = BarPalette {
    bottom: (40, 80, 160),
    middle: (120, 100, 220),
    top: (220, 130, 230),
};
const BAR_ERRORS: BarPalette = BarPalette {
    bottom: (90, 30, 50),
    middle: (200, 60, 70),
    top: (240, 180, 80),
};

fn lerp_rgb(a: (u8, u8, u8), b: (u8, u8, u8), t: f32) -> Color {
    let t = t.clamp(0.0, 1.0);
    Color::Rgb(
        (a.0 as f32 + (b.0 as f32 - a.0 as f32) * t) as u8,
        (a.1 as f32 + (b.1 as f32 - a.1 as f32) * t) as u8,
        (a.2 as f32 + (b.2 as f32 - a.2 as f32) * t) as u8,
    )
}

fn border_color(t: f32) -> Color {
    lerp_rgb(PALETTE_BORDER_LOW, PALETTE_BORDER_HIGH, t)
}

/// Sample the panel's three-stop colour band at vertical ratio `t` ∈ [0,1].
/// Each rendered bar cell uses its row's `t` (NOT the bar's fill ratio),
/// so a tall bar shows the full spectrum bottom-to-top while a short bar
/// stays in the cool low end — gives the dashboard its btop-style "stress"
/// gradient.
fn bar_color(p: &BarPalette, t: f32) -> Color {
    let t = t.clamp(0.0, 1.0);
    if t < 0.5 {
        lerp_rgb(p.bottom, p.middle, t * 2.0)
    } else {
        lerp_rgb(p.middle, p.top, (t - 0.5) * 2.0)
    }
}

fn latency_color(ms: f64) -> Color {
    if ms <= 50.0 {
        HEALTH_GOOD
    } else if ms <= 200.0 {
        HEALTH_WARN
    } else {
        HEALTH_BAD
    }
}

fn success_rate_color(pct: f64) -> Color {
    if pct >= 99.0 {
        HEALTH_GOOD
    } else if pct >= 95.0 {
        HEALTH_WARN
    } else {
        HEALTH_BAD
    }
}

fn error_rate_color(pct: f64) -> Color {
    if pct < 1.0 {
        HEALTH_GOOD
    } else if pct < 5.0 {
        HEALTH_WARN
    } else {
        HEALTH_BAD
    }
}

/// Paint a rounded panel border with a vertical purple→blue gradient.
/// Title is overlaid on the top edge in brand colour. Returns the inner
/// rect (one cell inset on each side).
fn paint_gradient_border(buf: &mut Buffer, area: Rect, title: &str) -> Rect {
    if area.width < 2 || area.height < 2 {
        return Rect::new(area.x, area.y, 0, 0);
    }
    const TL: &str = "╭";
    const TR: &str = "╮";
    const BL: &str = "╰";
    const BR: &str = "╯";
    const HZ: &str = "─";
    const VT: &str = "│";

    let h = area.height;
    for row in 0..h {
        let y = area.y + row;
        let t = if h <= 1 {
            0.5
        } else {
            row as f32 / (h - 1) as f32
        };
        let style = Style::default().fg(border_color(t));
        if row == 0 {
            buf[(area.x, y)].set_symbol(TL).set_style(style);
            buf[(area.x + area.width - 1, y)]
                .set_symbol(TR)
                .set_style(style);
            for x in (area.x + 1)..(area.x + area.width - 1) {
                buf[(x, y)].set_symbol(HZ).set_style(style);
            }
            if !title.is_empty() {
                let label = format!(" {title} ");
                let title_style = Style::default()
                    .fg(PALETTE_TITLE)
                    .add_modifier(Modifier::BOLD);
                paint_text(
                    buf,
                    area.x + 2,
                    y,
                    area.width.saturating_sub(4),
                    &label,
                    title_style,
                );
            }
        } else if row == h - 1 {
            buf[(area.x, y)].set_symbol(BL).set_style(style);
            buf[(area.x + area.width - 1, y)]
                .set_symbol(BR)
                .set_style(style);
            for x in (area.x + 1)..(area.x + area.width - 1) {
                buf[(x, y)].set_symbol(HZ).set_style(style);
            }
        } else {
            buf[(area.x, y)].set_symbol(VT).set_style(style);
            buf[(area.x + area.width - 1, y)]
                .set_symbol(VT)
                .set_style(style);
        }
    }
    Rect::new(area.x + 1, area.y + 1, area.width - 2, area.height - 2)
}

/// Overlay a left "-Xs / -Xm" label and a right "now" marker on the
/// bottom border of `area`. Replaces the gradient `─` characters with
/// muted-text labels in place.
fn paint_time_axis(buf: &mut Buffer, area: Rect, visible_secs: usize) {
    if area.height < 1 || visible_secs == 0 || area.width < 14 {
        return;
    }
    let y = area.y + area.height - 1;
    let style = Style::default().fg(PALETTE_MUTED);

    let left = format!(" {} ", format_age(visible_secs));
    paint_text(
        buf,
        area.x + 2,
        y,
        area.width.saturating_sub(4),
        &left,
        style,
    );

    let right = " now ";
    let n = right.chars().count() as u16;
    paint_text(buf, area.x + area.width - 2 - n, y, n, right, style);
}

/// Paint a filled bar chart into `area`, one column per data point,
/// right-aligned (newest sample on the right). Each cell is coloured
/// by its vertical row ratio against the chart, giving the panel a
/// shaded "stress band" — short bars stay in the cool low end of the
/// palette, tall bars climb into the warm top.
///
/// Sub-cell precision uses the eighth-block characters ▁▂▃▄▅▆▇█ for
/// the topmost partial row of each bar.
fn paint_shaded_bars(
    buf: &mut Buffer,
    area: Rect,
    data: &[u64],
    max_floor: Option<u64>,
    palette: &BarPalette,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    const FULL: &str = "█";
    const SUB: [&str; 8] = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

    let data_max = data.iter().copied().max().unwrap_or(0);
    let max = max_floor.unwrap_or(0).max(data_max).max(1);

    let n = data.len().min(area.width as usize);
    let start = data.len().saturating_sub(n);
    let h = area.height as f64;
    let v_denom = area.height.saturating_sub(1).max(1) as f32;
    // Horizontal brightness ramp — oldest column on the left dims to
    // ~55%, newest column on the right stays at full intensity. Skip
    // the ramp when fewer than ~4 columns are visible so the very
    // first frames don't show an awkward single-bar fade.
    let age_denom = (n.saturating_sub(1)).max(1) as f32;
    let apply_age_dim = n >= 4;
    // Right-align the visible window: newest bar lands on the right
    // edge of the chart, older bars scroll off to the left as data
    // accumulates. Until the chart fills, blank cells sit on the left.
    let x_offset = area.width.saturating_sub(n as u16);

    for (i, &v) in data[start..].iter().enumerate() {
        let x = area.x + x_offset + i as u16;
        let total_eighths = ((v as f64 / max as f64) * h * 8.0).round() as u32;
        let full_rows = (total_eighths / 8) as u16;
        let frac = (total_eighths % 8) as usize;
        let age_t = if apply_age_dim {
            i as f32 / age_denom
        } else {
            1.0
        };
        let brightness = 0.55 + 0.45 * age_t;

        for r in 0..full_rows.min(area.height) {
            let y = area.y + area.height - 1 - r;
            let v_t = r as f32 / v_denom;
            let color = dim_color(bar_color(palette, v_t), brightness);
            buf[(x, y)]
                .set_symbol(FULL)
                .set_style(Style::default().fg(color));
        }
        if full_rows < area.height && frac > 0 {
            let r = full_rows;
            let y = area.y + area.height - 1 - r;
            let v_t = r as f32 / v_denom;
            let color = dim_color(bar_color(palette, v_t), brightness);
            buf[(x, y)]
                .set_symbol(SUB[frac - 1])
                .set_style(Style::default().fg(color));
        }
    }
}

/// Scale an RGB color toward black by `factor` (1.0 = unchanged,
/// 0.0 = black). Non-RGB colors pass through unchanged so the helper
/// is safe to call on any palette entry.
fn dim_color(c: Color, factor: f32) -> Color {
    let factor = factor.clamp(0.0, 1.0);
    match c {
        Color::Rgb(r, g, b) => Color::Rgb(
            (r as f32 * factor) as u8,
            (g as f32 * factor) as u8,
            (b as f32 * factor) as u8,
        ),
        other => other,
    }
}

fn paint_text(buf: &mut Buffer, x: u16, y: u16, max_w: u16, text: &str, style: Style) {
    let end = x + max_w;
    for (cur, ch) in (x..).zip(text.chars()) {
        if cur >= end {
            return;
        }
        buf[(cur, y)].set_char(ch).set_style(style);
    }
}

fn paint_text_right(buf: &mut Buffer, area: Rect, text: &str, style: Style) {
    let n = text.chars().count() as u16;
    if n == 0 || area.width == 0 {
        return;
    }
    let start_x = area.x + area.width.saturating_sub(n);
    paint_text(buf, start_x, area.y, area.width, text, style);
}

fn paint_text_centered(buf: &mut Buffer, area: Rect, text: &str, style: Style) {
    let n = text.chars().count() as u16;
    if n == 0 || area.width == 0 {
        return;
    }
    let pad = area.width.saturating_sub(n) / 2;
    paint_text(
        buf,
        area.x + pad,
        area.y,
        area.width.saturating_sub(pad),
        text,
        style,
    );
}

fn paint_line(buf: &mut Buffer, x: u16, y: u16, max_w: u16, line: &Line<'_>) {
    let mut cur = x;
    let end = x + max_w;
    for span in &line.spans {
        for ch in span.content.chars() {
            if cur >= end {
                return;
            }
            buf[(cur, y)].set_char(ch).set_style(span.style);
            cur += 1;
        }
    }
}

fn paint_header(buf: &mut Buffer, area: Rect, snap: &Snapshot) {
    let _ = paint_gradient_border(buf, area, "");
    if area.height < 3 {
        return;
    }
    let y = area.y + 1;
    let inner_x = area.x + 2;
    let inner_w = area.width.saturating_sub(4);

    // Brand title on the left, gradient-shaded across its characters.
    let title = "  WebVH Perf Test";
    let title_chars: Vec<char> = title.chars().collect();
    let title_len = title_chars.len() as u16;
    for (i, ch) in title_chars.iter().enumerate() {
        let x = inner_x + i as u16;
        if x >= inner_x + inner_w {
            break;
        }
        let denom = (title_len.saturating_sub(1)).max(1) as f32;
        let t = i as f32 / denom;
        let color = lerp_rgb(PALETTE_BORDER_LOW, PALETTE_BORDER_HIGH, t);
        buf[(x, y)]
            .set_char(*ch)
            .set_style(Style::default().fg(color).add_modifier(Modifier::BOLD));
    }

    // Right-aligned info line. Strip the URL scheme so the host fits
    // alongside the other counters without crowding the title.
    let server_label = snap
        .server_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let info = format!(
        " {} · {} dids · target {} req/s · {} ",
        server_label,
        snap.did_count,
        snap.target_rate,
        format_duration(snap.elapsed)
    );
    let info_w = info.chars().count() as u16;
    if title_len + info_w + 2 < inner_w {
        let info_x = area.x + area.width - 2 - info_w;
        paint_text(
            buf,
            info_x,
            y,
            info_w,
            &info,
            Style::default().fg(PALETTE_DIM),
        );
    }
}

fn paint_chart_panel(
    buf: &mut Buffer,
    area: Rect,
    title: &str,
    data: &[u64],
    max_floor: Option<u64>,
    palette: &BarPalette,
) {
    let inner = paint_gradient_border(buf, area, title);
    if inner.width < Y_AXIS_WIDTH + 1 || inner.height < 1 {
        return;
    }
    let chart = Rect::new(
        inner.x + Y_AXIS_WIDTH,
        inner.y,
        inner.width - Y_AXIS_WIDTH,
        inner.height,
    );

    let data_max = data.iter().copied().max().unwrap_or(0);
    let display_max = max_floor.unwrap_or(0).max(data_max);

    // Y-axis labels in the left-most column (right-aligned, muted)
    let label_area = Rect::new(inner.x, inner.y, Y_AXIS_WIDTH.saturating_sub(1), 1);
    paint_text_right(
        buf,
        label_area,
        &fmt_compact(display_max),
        Style::default().fg(PALETTE_MUTED),
    );
    if inner.height >= 2 {
        let by = inner.y + inner.height - 1;
        let zero_area = Rect::new(inner.x, by, Y_AXIS_WIDTH.saturating_sub(1), 1);
        paint_text_right(buf, zero_area, "0", Style::default().fg(PALETTE_MUTED));
    }

    paint_shaded_bars(buf, chart, data, max_floor, palette);
    paint_time_axis(buf, area, data.len());
}

fn paint_summary_panel(buf: &mut Buffer, area: Rect, snap: &Snapshot) {
    let inner = paint_gradient_border(buf, area, "Summary");
    if inner.width < 24 || inner.height < 4 {
        return;
    }

    // Two-column metrics block once the panel is wide enough; falls
    // back to a single column on narrow terminals.
    let two_col = inner.width >= 50;

    let mut row: u16 = 0;

    if two_col {
        let col_w = (inner.width.saturating_sub(2)) / 2;
        let col_a_x = inner.x;
        let col_b_x = inner.x + col_w + 2;

        let top_a = build_requests_lines(snap);
        let top_b = build_throughput_lines(snap);
        row = paint_two_columns(buf, inner, col_a_x, col_b_x, col_w, row, &top_a, &top_b);

        if row + 1 < inner.height {
            row += 1; // spacer between blocks
        }

        let mid_a = build_latency_lines(snap);
        let mid_b = build_network_lines(snap);
        row = paint_two_columns(buf, inner, col_a_x, col_b_x, col_w, row, &mid_a, &mid_b);
    } else {
        let lines = build_single_column_lines(snap);
        for line in lines.iter() {
            if row >= inner.height {
                return;
            }
            paint_line(buf, inner.x, inner.y + row, inner.width, line);
            row += 1;
        }
    }

    // CPU section spans full width below the metrics block. Each
    // meter's bar is gradient-shaded across its horizontal extent
    // (green at the start, amber middle, red right edge).
    if !snap.cpu_per_core.is_empty() && row + 2 < inner.height {
        row += 1; // spacer
        paint_line(
            buf,
            inner.x,
            inner.y + row,
            inner.width,
            &Line::from(Span::styled(
                "  CPU",
                Style::default()
                    .fg(PALETTE_TITLE)
                    .add_modifier(Modifier::BOLD),
            )),
        );
        row += 1;

        for (core_idx, &usage) in snap.cpu_per_core.iter().enumerate() {
            if row >= inner.height {
                break;
            }
            paint_cpu_meter(
                buf,
                Rect::new(inner.x, inner.y + row, inner.width, 1),
                core_idx,
                usage,
            );
            row += 1;
        }
    }
}

/// Paint two parallel column line lists at the same starting row.
/// Returns the next free row after the longer column finishes.
#[allow(clippy::too_many_arguments)]
fn paint_two_columns(
    buf: &mut Buffer,
    inner: Rect,
    col_a_x: u16,
    col_b_x: u16,
    col_w: u16,
    start_row: u16,
    col_a: &[Line<'static>],
    col_b: &[Line<'static>],
) -> u16 {
    let n = col_a.len().max(col_b.len()) as u16;
    let mut row = start_row;
    for i in 0..n {
        if row >= inner.height {
            break;
        }
        if let Some(line) = col_a.get(i as usize) {
            paint_line(buf, col_a_x, inner.y + row, col_w, line);
        }
        if let Some(line) = col_b.get(i as usize) {
            paint_line(buf, col_b_x, inner.y + row, col_w, line);
        }
        row += 1;
    }
    row
}

fn summary_section_style() -> Style {
    Style::default()
        .fg(PALETTE_TITLE)
        .add_modifier(Modifier::BOLD)
}

fn summary_label_style() -> Style {
    Style::default().fg(PALETTE_DIM)
}

fn summary_dim_style() -> Style {
    Style::default().fg(PALETTE_MUTED)
}

fn build_requests_lines(snap: &Snapshot) -> Vec<Line<'static>> {
    let success_pct = if snap.total > 0 {
        snap.success as f64 / snap.total as f64 * 100.0
    } else {
        0.0
    };
    let error_pct = if snap.total > 0 {
        snap.errors as f64 / snap.total as f64 * 100.0
    } else {
        0.0
    };
    let label = summary_label_style();
    let dim = summary_dim_style();
    vec![
        Line::from(Span::styled("  Requests", summary_section_style())),
        Line::from(vec![
            Span::styled("    Total    ", label),
            Span::styled(
                format!("{:>10}", fmt_num(snap.total)),
                Style::default()
                    .fg(PALETTE_TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("    Success  ", label),
            Span::styled(
                format!("{:>10}", fmt_num(snap.success)),
                Style::default().fg(success_rate_color(success_pct)),
            ),
            Span::styled(format!(" {:>5.1}%", success_pct), dim),
        ]),
        Line::from(vec![
            Span::styled("    Errors   ", label),
            Span::styled(
                format!("{:>10}", fmt_num(snap.errors)),
                Style::default().fg(error_rate_color(error_pct)),
            ),
            Span::styled(format!(" {:>5.2}%", error_pct), dim),
        ]),
    ]
}

fn build_throughput_lines(snap: &Snapshot) -> Vec<Line<'static>> {
    let label = summary_label_style();
    let accent = Style::default()
        .fg(PALETTE_ACCENT)
        .add_modifier(Modifier::BOLD);
    vec![
        Line::from(Span::styled("  Throughput", summary_section_style())),
        Line::from(vec![
            Span::styled("    Current  ", label),
            Span::styled(format!("{:>7} req/s", snap.current_rps), accent),
        ]),
        Line::from(vec![
            Span::styled("    Rolling  ", label),
            Span::styled(
                format!("{:>5} req/min", snap.rolling_rpm),
                Style::default().fg(PALETTE_DIM),
            ),
        ]),
    ]
}

fn build_latency_lines(snap: &Snapshot) -> Vec<Line<'static>> {
    let label = summary_label_style();
    vec![
        Line::from(Span::styled("  Latency", summary_section_style())),
        Line::from(vec![
            Span::styled("    Min   ", label),
            Span::styled(
                format!("{:>7.1}ms", snap.min_latency_ms),
                Style::default().fg(PALETTE_TEXT),
            ),
        ]),
        Line::from(vec![
            Span::styled("    Avg   ", label),
            Span::styled(
                format!("{:>7.1}ms", snap.avg_latency_ms),
                Style::default().fg(latency_color(snap.avg_latency_ms)),
            ),
        ]),
        Line::from(vec![
            Span::styled("    Max   ", label),
            Span::styled(
                format!("{:>7.1}ms", snap.max_latency_ms),
                Style::default().fg(PALETTE_TEXT),
            ),
        ]),
        Line::from(vec![
            Span::styled("    P50   ", label),
            Span::styled(
                format!("{:>7.1}ms", snap.p50_latency_ms),
                Style::default().fg(latency_color(snap.p50_latency_ms)),
            ),
        ]),
        Line::from(vec![
            Span::styled("    P95   ", label),
            Span::styled(
                format!("{:>7.1}ms", snap.p95_latency_ms),
                Style::default().fg(latency_color(snap.p95_latency_ms)),
            ),
        ]),
        Line::from(vec![
            Span::styled("    P99   ", label),
            Span::styled(
                format!("{:>7.1}ms", snap.p99_latency_ms),
                Style::default().fg(latency_color(snap.p99_latency_ms)),
            ),
        ]),
    ]
}

fn build_network_lines(snap: &Snapshot) -> Vec<Line<'static>> {
    let label = summary_label_style();
    let dim = summary_dim_style();
    vec![
        Line::from(Span::styled("  Network", summary_section_style())),
        Line::from(vec![
            Span::styled("    ↑ Out  ", label),
            Span::styled(
                format!("{:>10}", fmt_bytes_rate(snap.outbound_bps)),
                Style::default().fg(NET_OUT),
            ),
        ]),
        Line::from(vec![
            Span::styled("     peak  ", dim),
            Span::styled(
                format!("{:>10}", fmt_bytes_rate(snap.peak_outbound_bps)),
                Style::default().fg(PALETTE_DIM),
            ),
        ]),
        Line::from(vec![
            Span::styled("    ↓ In   ", label),
            Span::styled(
                format!("{:>10}", fmt_bytes_rate(snap.inbound_bps)),
                Style::default().fg(NET_IN),
            ),
        ]),
        Line::from(vec![
            Span::styled("     peak  ", dim),
            Span::styled(
                format!("{:>10}", fmt_bytes_rate(snap.peak_inbound_bps)),
                Style::default().fg(PALETTE_DIM),
            ),
        ]),
    ]
}

/// Compact single-column layout used when the summary panel is too
/// narrow for a side-by-side metrics block.
fn build_single_column_lines(snap: &Snapshot) -> Vec<Line<'static>> {
    let mut out = build_requests_lines(snap);
    out.push(Line::from(""));
    out.extend(build_throughput_lines(snap));
    out.push(Line::from(""));
    out.extend(build_latency_lines(snap));
    out.push(Line::from(""));
    out.extend(build_network_lines(snap));
    out
}

fn paint_cpu_meter(buf: &mut Buffer, area: Rect, core_idx: usize, usage: f32) {
    if area.height == 0 {
        return;
    }
    let prefix = format!("    Core {core_idx:>2}  ");
    let pct = format!("  {:>3.0}%", usage);
    let prefix_w = prefix.chars().count() as u16;
    let pct_w = pct.chars().count() as u16;
    if area.width < prefix_w + pct_w + 4 {
        return;
    }
    let bar_w = area.width - prefix_w - pct_w;

    paint_text(
        buf,
        area.x,
        area.y,
        prefix_w,
        &prefix,
        Style::default().fg(PALETTE_DIM),
    );
    paint_horizontal_meter(
        buf,
        Rect::new(area.x + prefix_w, area.y, bar_w, 1),
        usage / 100.0,
    );
    paint_text(
        buf,
        area.x + prefix_w + bar_w,
        area.y,
        pct_w,
        &pct,
        Style::default()
            .fg(cpu_text_color(usage))
            .add_modifier(Modifier::BOLD),
    );
}

/// Paint a horizontal meter inside `area`. The fill grows left→right
/// and each filled cell is shaded by its horizontal position within
/// the meter — empty cells stay as faint dots in the muted palette.
fn paint_horizontal_meter(buf: &mut Buffer, area: Rect, fill: f32) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    const SUB: [&str; 8] = ["▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"];
    let fill = fill.clamp(0.0, 1.0);
    let total_eighths = (fill * area.width as f32 * 8.0).round() as u32;
    let full_cells = (total_eighths / 8) as u16;
    let frac = (total_eighths % 8) as usize;
    let denom = area.width.saturating_sub(1).max(1) as f32;
    let track_style = Style::default().fg(Color::Rgb(50, 50, 65));

    for x in 0..area.width {
        buf[(area.x + x, area.y)]
            .set_symbol("░")
            .set_style(track_style);
    }
    for x in 0..full_cells.min(area.width) {
        let t = x as f32 / denom;
        buf[(area.x + x, area.y)]
            .set_symbol("█")
            .set_style(Style::default().fg(bar_color(&BAR_LATENCY, t)));
    }
    if full_cells < area.width && frac > 0 {
        let x = full_cells;
        let t = x as f32 / denom;
        buf[(area.x + x, area.y)]
            .set_symbol(SUB[frac - 1])
            .set_style(Style::default().fg(bar_color(&BAR_LATENCY, t)));
    }
}

fn cpu_text_color(usage: f32) -> Color {
    if usage >= 80.0 {
        HEALTH_BAD
    } else if usage >= 50.0 {
        HEALTH_WARN
    } else {
        HEALTH_GOOD
    }
}

fn paint_footer(buf: &mut Buffer, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let cues: &[(&str, &str)] = &[
        ("[q]", "quit"),
        ("[+/↑]", "+10"),
        ("[-/↓]", "-10"),
        ("[]]", "2x"),
        ("[[]", "0.5x"),
    ];
    let key_style = Style::default()
        .fg(PALETTE_ACCENT)
        .add_modifier(Modifier::BOLD);
    let desc_style = Style::default().fg(PALETTE_MUTED);

    let mut x = area.x + 1;
    let y = area.y;
    let end = area.x + area.width;
    for (key, desc) in cues {
        for ch in key.chars() {
            if x >= end {
                return;
            }
            buf[(x, y)].set_char(ch).set_style(key_style);
            x += 1;
        }
        if x >= end {
            return;
        }
        buf[(x, y)].set_char(' ');
        x += 1;
        for ch in desc.chars() {
            if x >= end {
                return;
            }
            buf[(x, y)].set_char(ch).set_style(desc_style);
            x += 1;
        }
        for _ in 0..3 {
            if x >= end {
                return;
            }
            buf[(x, y)].set_char(' ');
            x += 1;
        }
    }
}

fn paint_warmup_overlay(buf: &mut Buffer, area: Rect, snap: &Snapshot) {
    let popup = centered_rect(46, 7, area);
    let bg = Style::default().bg(PALETTE_OVERLAY_BG);
    for y in popup.y..popup.y + popup.height {
        for x in popup.x..popup.x + popup.width {
            buf[(x, y)].set_char(' ').set_style(bg);
        }
    }
    let inner = paint_gradient_border(buf, popup, "Initializing");
    if inner.height >= 3 {
        let title = Rect::new(inner.x, inner.y + 1, inner.width, 1);
        paint_text_centered(
            buf,
            title,
            "Starting test...",
            Style::default()
                .fg(PALETTE_TITLE)
                .add_modifier(Modifier::BOLD)
                .bg(PALETTE_OVERLAY_BG),
        );
    }
    if inner.height >= 4 {
        let sub = Rect::new(inner.x, inner.y + 2, inner.width, 1);
        paint_text_centered(
            buf,
            sub,
            &format!("Warming up — {}s remaining", snap.warmup_secs_left),
            Style::default().fg(PALETTE_ACCENT).bg(PALETTE_OVERLAY_BG),
        );
    }
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

/// Convert a `did:webvh:SCID:HOST:PATH` identifier to a resolution URL.
///
/// The host component may contain `%3A` for ports (e.g. `localhost%3A8085`).
/// Path segments after the host are joined with `/` to form the mnemonic.
/// The resulting URL uses HTTPS by default.
///
/// # Examples
/// - `did:webvh:Qm...:example.com:my-did` → `https://example.com/my-did/did.jsonl`
/// - `did:webvh:Qm...:localhost%3A8085:my-did` → `https://localhost:8085/my-did/did.jsonl`
fn did_webvh_to_url(did: &str) -> Result<String> {
    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() < 5 || parts[0] != "did" || parts[1] != "webvh" {
        bail!("invalid did:webvh identifier: {did}");
    }
    // parts[2] = SCID, parts[3] = host (with %3A for port), parts[4..] = path segments
    let host = parts[3].replace("%3A", ":");
    let path = parts[4..].join("/");
    Ok(format!("https://{host}/{path}/did.jsonl"))
}

/// Load DID identifiers from a file and convert them to resolution URLs.
///
/// Blank lines and lines starting with '#' are skipped.
fn load_did_file(path: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read DID file: {path}"))?;
    let mut urls = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let url = did_webvh_to_url(trimmed)
            .with_context(|| format!("line {}: {trimmed}", line_num + 1))?;
        urls.push(url);
    }
    if urls.is_empty() {
        bail!("DID file {path} contains no valid entries");
    }
    Ok(urls)
}

// =========================================================================
// Main
// =========================================================================

fn main() -> Result<()> {
    let args = Args::parse();

    // Build the tokio runtime explicitly so worker_threads is a
    // first-class knob. Default matches `std::thread::available_parallelism`
    // (what `#[tokio::main]` would pick anyway), but it's now visible
    // and overridable via `--threads`.
    let worker_threads = args.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    eprintln!();
    eprintln!("  Tokio worker threads: {worker_threads}");

    runtime.block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    let server_url = args.server_url.trim_end_matches('/').to_string();

    // ----- Build resolution URLs -----
    // Two modes: file mode (--did-file) or server mode (authenticate + list).
    let (urls, display_label) = if let Some(ref did_file) = args.did_file {
        if args.create_dids > 0 {
            bail!("--did-file and --create-dids cannot be used together");
        }
        eprintln!();
        eprintln!("  Loading DIDs from: {did_file}");
        let urls = load_did_file(did_file)?;
        eprintln!("  Loaded {} DIDs", urls.len());
        eprintln!();
        (urls, format!("File: {did_file}"))
    } else {
        // ----- Server mode: authenticate, optionally create, then list -----
        let webvh_did = args
            .webvh_did
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--webvh-did is required in server mode (the DID the auth \
                     message is addressed to). Use `--did-file` to skip auth."
                )
            })?
            .to_string();

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

        let hosting_url = args
            .hosting_url
            .as_deref()
            .map(|u| u.trim_end_matches('/').to_string());

        eprintln!();
        eprintln!("  Identity:     {my_did}");
        eprintln!("  WebVH DID:    {webvh_did}");
        eprintln!("  Server URL:   {server_url}");
        match hosting_url.as_deref() {
            Some(h) => eprintln!("  Hosting URL:  {h}"),
            None => eprintln!("  Hosting URL:  (same as server URL)"),
        }
        eprintln!();

        if args.seed.is_none() {
            eprintln!("  Fresh did:key generated for this run. Add it to the DID Hosting");
            eprintln!("  control plane's ACL before continuing — e.g.:");
            eprintln!("    did-hosting-control add-acl --did {my_did}");
            eprintln!("    did-hosting-daemon  add-acl --did {my_did}");
            eprintln!();
            eprint!("  Press Enter to continue after adding to ACL...");
            io::stderr().flush()?;
            let mut buf = String::new();
            io::stdin().read_line(&mut buf)?;
        }

        // Authenticate via DIDComm
        eprintln!("  Authenticating via DIDComm...");
        let mut client = WebVHClient::new(&server_url);
        if let Some(ref h) = hosting_url {
            client = client.with_hosting_url(h);
        }
        client
            .authenticate(&my_did, &my_secret, &webvh_did)
            .await
            .context("DIDComm authentication failed")?;
        eprintln!("  Authenticated!");

        // Create random DIDs if requested
        let (client, _my_secret) = if args.create_dids > 0 {
            let parallel = args.create_parallel.max(1);
            eprintln!(
                "  Creating {} random DIDs ({} parallel)...",
                args.create_dids, parallel
            );

            let client = Arc::new(client);
            let my_secret = Arc::new(my_secret);
            let sem = Arc::new(tokio::sync::Semaphore::new(parallel));
            let counter = Arc::new(AtomicU64::new(0));
            let total = args.create_dids;

            let mut handles = Vec::with_capacity(total);
            for _ in 0..total {
                let permit = sem.clone().acquire_owned().await.unwrap();
                let c = client.clone();
                let s = my_secret.clone();
                let ctr = counter.clone();
                handles.push(tokio::spawn(async move {
                    let result = c.create_did(&s, None).await;
                    drop(permit);
                    let i = ctr.fetch_add(1, Ordering::Relaxed) + 1;
                    match result {
                        Ok(r) => {
                            eprintln!("    [{i}/{total}] {} -> {}", r.mnemonic, r.did);
                            Ok(())
                        }
                        Err(e) => {
                            eprintln!("    [{i}/{total}] FAILED: {e}");
                            Err(e)
                        }
                    }
                }));
            }

            let mut failures = 0u64;
            for h in handles {
                if h.await.unwrap().is_err() {
                    failures += 1;
                }
            }
            if failures > 0 {
                bail!("failed to create {failures}/{total} DIDs");
            }

            eprintln!("  Created {} DIDs.", total);
            eprintln!();

            let client = Arc::into_inner(client).expect("client Arc still shared");
            let my_secret = Arc::into_inner(my_secret).expect("secret Arc still shared");
            (client, my_secret)
        } else {
            (client, my_secret)
        };

        // Fetch active DIDs. Resolution targets are derived from each
        // DID's embedded host, not from `--server-url` — the management
        // endpoint (control plane) is often on a different host than
        // the public hosting URL the DID itself advertises.
        eprintln!("  Fetching DID list...");
        let all_dids = client.list_dids().await.context("failed to list DIDs")?;

        let urls: Vec<String> = all_dids
            .iter()
            .filter(|d| d.version_count > 0 && !d.disabled)
            .filter_map(|d| d.did_id.as_deref())
            .filter_map(|did| match did_webvh_to_url(did) {
                Ok(url) => Some(url),
                Err(e) => {
                    eprintln!("  skipping unparseable DID '{did}': {e}");
                    None
                }
            })
            .collect();

        eprintln!(
            "  Found {} active DIDs (of {} total)",
            urls.len(),
            all_dids.len()
        );

        if urls.is_empty() {
            eprintln!();
            eprintln!("  No active (published & enabled) DIDs found.");
            eprintln!("  Create and publish DIDs first, e.g.:");
            eprintln!(
                "    cargo run -p did-hosting-server --example client -- \\\n      --server-url {server_url} --webvh-did {webvh_did}"
            );
            bail!("no active DIDs to test against");
        }

        (urls, server_url.clone())
    };

    eprintln!(
        "  Starting performance test: {} req/s target, {} max concurrent",
        args.rate, args.workers
    );
    eprintln!();

    // ----- Shared state -----
    let did_count = urls.len();
    let target_rate = Arc::new(AtomicU64::new(args.rate));
    let shutdown = Arc::new(AtomicBool::new(false));
    let urls = Arc::new(urls);
    let metrics = Arc::new(SharedMetrics::new());

    let (snap_tx, snap_rx) = watch::channel(Snapshot::default());

    // ----- Spawn background tasks -----
    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(args.workers)
        .timeout(Duration::from_secs(args.timeout))
        .build()?;

    // Dispatcher
    let d_rate = target_rate.clone();
    let d_shutdown = shutdown.clone();
    let d_urls = urls.clone();
    let d_metrics = metrics.clone();
    let d_workers = args.workers;
    let d_client = http_client.clone();
    tokio::spawn(async move {
        dispatcher(d_rate, d_client, d_urls, d_metrics, d_shutdown, d_workers).await;
    });

    // Aggregator
    let a_rate = target_rate.clone();
    let a_shutdown = shutdown.clone();
    let a_metrics = metrics.clone();
    let a_label = display_label.clone();
    tokio::spawn(async move {
        run_aggregator(
            a_metrics, snap_tx, a_rate, did_count, a_label, d_workers, a_shutdown,
        )
        .await;
    });

    // ----- TUI event loop -----
    // Install panic hook to restore terminal on crash
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        original_hook(info);
    }));

    let mut terminal = ratatui::init();
    let result = run_tui(
        &mut terminal,
        snap_rx,
        target_rate.clone(),
        shutdown.clone(),
    );

    ratatui::restore();

    if let Err(e) = result {
        eprintln!("TUI error: {e}");
    }

    // Print final stats
    let snap = snap_rx_final(
        &display_label,
        did_count,
        target_rate.load(Ordering::Relaxed),
    );
    eprintln!();
    eprintln!("  Performance test complete.");
    eprintln!(
        "  Total: {} | Success: {} | Errors: {}",
        snap.total, snap.success, snap.errors
    );
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
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
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
