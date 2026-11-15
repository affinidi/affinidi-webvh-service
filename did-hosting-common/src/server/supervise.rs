//! Background work as data, and the supervisor that runs it.
//!
//! Every service (the edge, the control plane, the daemon that embeds both)
//! describes its periodic work as a list of [`PeriodicTask`]s built by the
//! service's own crate, and runs it with [`run_periodic`]. The daemon builds
//! the same lists and merges them ([`merge_tasks`]), dropping by name only
//! what its documented skip list names — so a tick added to a standalone
//! service reaches the daemon without a second copy, and a test can check
//! that nothing was left out.
//!
//! Long-running work (the HTTP listener, the outbox worker, a sweep) runs
//! under a [`Supervisor`], which notices when one stops before it was asked
//! to and applies the task's [`Policy`]:
//!
//! - [`Policy::Restart`] — restarted with exponential backoff
//!   ([`RESTART_BACKOFF_MIN`] to [`RESTART_BACKOFF_MAX`]). For work whose state
//!   is durable or derived (the outbox, the sweeps, reconcile loops), where
//!   running again is always safe and stopping would silently stop
//!   replication, expiry or stats.
//! - [`Policy::Critical`] — the process shuts down and exits non-zero, so the
//!   orchestrator restarts it. For work that cannot be restarted in place (an
//!   OS thread that owns the listening socket, the storage task that persists
//!   the store at shutdown).
//!
//! Each unexpected exit is logged at `error`. Shutdown runs in [`Stage`]s, in
//! order — workers, then listeners, then storage — each with a deadline, so
//! the store is persisted only after everything that writes to it has
//! stopped, and one stalled task cannot hold the process up forever.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::sync::{oneshot, watch};
use tokio::task::{JoinError, JoinSet};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// A boxed `Send` future, the shape every task body returns.
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// One tick's work. Handed the shutdown signal, so a long tick (a paced
/// flush) can stop early.
pub type TickFn = Box<dyn FnMut(watch::Receiver<bool>) -> BoxFuture + Send>;

/// How a periodic task schedules its next tick when one overruns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missed {
    /// Keep the original cadence, skipping ticks that were missed.
    Skip,
    /// Wait a full interval after an overrunning tick finishes.
    Delay,
}

/// One named piece of periodic work.
pub struct PeriodicTask {
    /// Stable name: what a skip list and the parity tests refer to.
    pub name: &'static str,
    /// Time between ticks. The first tick is one interval after start.
    pub interval: Duration,
    /// What happens after a tick that overran its interval.
    pub missed: Missed,
    /// Whether the task runs at all (a task gated on configuration still has
    /// a name, so the parity checks see it either way).
    pub enabled: bool,
    tick: TickFn,
}

impl PeriodicTask {
    /// A task named `name` that runs `tick` every `interval`.
    pub fn new<F, Fut>(name: &'static str, interval: Duration, mut tick: F) -> Self
    where
        F: FnMut(watch::Receiver<bool>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self {
            name,
            interval,
            missed: Missed::Skip,
            enabled: true,
            tick: Box::new(move |shutdown| Box::pin(tick(shutdown))),
        }
    }

    /// Wait a full interval after a tick that overran.
    pub fn delay_missed(mut self) -> Self {
        self.missed = Missed::Delay;
        self
    }

    /// Run only when `enabled`.
    pub fn enabled_if(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

impl std::fmt::Debug for PeriodicTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeriodicTask")
            .field("name", &self.name)
            .field("interval", &self.interval)
            .field("missed", &self.missed)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

/// The names of `tasks`, in order.
pub fn names(tasks: &[PeriodicTask]) -> Vec<&'static str> {
    tasks.iter().map(|t| t.name).collect()
}

/// Merge task lists into one, as the daemon does: the first task of each name
/// wins (two services that share a tick, such as the DID count recount, run
/// it once), and every name in `skip` is dropped.
pub fn merge_tasks(
    lists: impl IntoIterator<Item = Vec<PeriodicTask>>,
    skip: &[&str],
) -> Vec<PeriodicTask> {
    let mut seen: HashSet<&'static str> = HashSet::new();
    let mut merged = Vec::new();
    for task in lists.into_iter().flatten() {
        if skip.contains(&task.name) || !seen.insert(task.name) {
            continue;
        }
        merged.push(task);
    }
    merged
}

/// Run `tasks` one tick at a time, each on its own interval, until
/// `shutdown` turns `true` (or its sender is dropped).
///
/// Ticks never overlap: the store writes they make (a flush, a cleanup, a
/// sweep) are serialised the way the single storage loop they replace
/// serialised them.
pub async fn run_periodic(mut tasks: Vec<PeriodicTask>, mut shutdown: watch::Receiver<bool>) {
    tasks.retain(|t| t.enabled);
    if *shutdown.borrow() {
        return;
    }
    let start = Instant::now();
    let mut next: Vec<Instant> = tasks.iter().map(|t| start + t.interval).collect();
    loop {
        let Some((due, at)) = next.iter().copied().enumerate().min_by_key(|(_, at)| *at) else {
            // Nothing to run; wait for shutdown.
            let _ = shutdown.changed().await;
            return;
        };
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                continue;
            }
            _ = tokio::time::sleep_until(at) => {}
        }
        let task = &mut tasks[due];
        (task.tick)(shutdown.clone()).await;
        let now = Instant::now();
        next[due] = match task.missed {
            Missed::Delay => now + task.interval,
            Missed::Skip => {
                let mut at = at + task.interval;
                while at <= now {
                    at += task.interval;
                }
                at
            }
        };
        if *shutdown.borrow() {
            return;
        }
    }
}

/// When a supervised task is stopped, relative to the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    /// Background workers: sweeps, the outbox, reconcile and sync loops, the
    /// messaging service. Stopped first.
    Workers = 0,
    /// The HTTP listener. Stopped once no worker is running.
    Listeners = 1,
    /// The storage task: its last flush and the store's persist run after
    /// everything that writes to the store has stopped.
    Storage = 2,
}

const STAGES: [Stage; 3] = [Stage::Workers, Stage::Listeners, Stage::Storage];

/// What a supervised task does when it stops on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Restart it, with exponential backoff.
    Restart,
    /// Shut the process down and exit non-zero.
    Critical,
}

/// First wait before restarting a task that stopped.
pub const RESTART_BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Longest wait between restarts.
pub const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A task that ran at least this long before stopping restarts after the
/// shortest wait again.
const RESTART_BACKOFF_RESET: Duration = Duration::from_secs(300);

/// How long each shutdown stage may take before its tasks are abandoned.
pub const SHUTDOWN_STAGE_DEADLINE: Duration = Duration::from_secs(30);

/// The stop signal of one [`Stage`], in both shapes the services' loops take.
#[derive(Clone, Debug)]
pub struct Shutdown {
    token: CancellationToken,
    rx: watch::Receiver<bool>,
}

impl Shutdown {
    /// Cancelled when the stage stops.
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Turns `true` when the stage stops.
    pub fn watch(&self) -> watch::Receiver<bool> {
        self.rx.clone()
    }

    /// Whether the stage has been told to stop.
    pub fn is_stopping(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Resolves once the stage has been told to stop.
    pub async fn stopped(&self) {
        self.token.cancelled().await
    }
}

struct StageSignal {
    tx: watch::Sender<bool>,
    shutdown: Shutdown,
}

impl StageSignal {
    fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            tx,
            shutdown: Shutdown {
                token: CancellationToken::new(),
                rx,
            },
        }
    }

    fn stop(&self) {
        self.shutdown.token.cancel();
        let _ = self.tx.send(true);
    }
}

/// How a supervised task ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// It stopped because its stage was told to.
    Stopped,
    /// It stopped on its own, or panicked, while it was meant to be running.
    Failed(String),
}

/// A task that ended while the process was meant to be running, under
/// [`Policy::Critical`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskFailure {
    /// The task's name.
    pub task: &'static str,
    /// Why it ended.
    pub reason: String,
}

impl std::fmt::Display for TaskFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} stopped: {}", self.task, self.reason)
    }
}

impl std::error::Error for TaskFailure {}

type Outcome = (&'static str, Exit);

/// Runs a service's long-running tasks and threads, and stops them in order.
pub struct Supervisor {
    service: &'static str,
    signals: [StageSignal; 3],
    sets: [JoinSet<Outcome>; 3],
    failures: Vec<TaskFailure>,
}

impl Supervisor {
    /// A supervisor for `service` (used in its log lines).
    pub fn new(service: &'static str) -> Self {
        Self {
            service,
            signals: [StageSignal::new(), StageSignal::new(), StageSignal::new()],
            sets: [JoinSet::new(), JoinSet::new(), JoinSet::new()],
            failures: Vec::new(),
        }
    }

    /// The stop signal of `stage`, for work that is not itself supervised but
    /// has to stop with it (the messaging service's cancellation token).
    pub fn signal(&self, stage: Stage) -> Shutdown {
        self.signals[stage as usize].shutdown.clone()
    }

    /// Run the future `make` returns under `policy`. Under
    /// [`Policy::Restart`] it is called again, after a backoff, each time the
    /// future it made ends before `stage` is stopped.
    pub fn spawn<F, Fut>(&mut self, stage: Stage, name: &'static str, policy: Policy, mut make: F)
    where
        F: FnMut(Shutdown) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let shutdown = self.signal(stage);
        let service = self.service;
        self.sets[stage as usize].spawn(async move {
            let mut backoff = RESTART_BACKOFF_MIN;
            loop {
                let started = Instant::now();
                // On a task of its own, so a panic is reported rather than
                // unwinding through the supervisor; aborted with this one.
                let run = AbortOnDrop(tokio::spawn(make(shutdown.clone())));
                let result = run.join().await;
                if shutdown.is_stopping() {
                    return (name, Exit::Stopped);
                }
                let reason = describe(result);
                if policy == Policy::Critical {
                    error!(
                        service,
                        task = name,
                        reason,
                        "a critical task stopped; shutting down"
                    );
                    return (name, Exit::Failed(reason));
                }
                if started.elapsed() >= RESTART_BACKOFF_RESET {
                    backoff = RESTART_BACKOFF_MIN;
                }
                error!(
                    service,
                    task = name,
                    reason,
                    restart_in = ?backoff,
                    "a background task stopped; restarting"
                );
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.stopped() => return (name, Exit::Stopped),
                }
                backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
            }
        });
    }

    /// Run `fut`, made once from `stage`'s stop signal, as a
    /// [`Policy::Critical`] task: for work that owns what it was handed (a
    /// bound listener) and so cannot be made again.
    pub fn spawn_critical<F, Fut>(&mut self, stage: Stage, name: &'static str, make: F)
    where
        F: FnOnce(Shutdown) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut make = Some(make);
        self.spawn(stage, name, Policy::Critical, move |sd| {
            let make = make.take().expect("a critical task is started once");
            make(sd)
        });
    }

    /// Run `body` on an OS thread of its own, as a [`Policy::Critical`] task:
    /// a thread owns what it was handed (a listening socket, a runtime), so it
    /// cannot be restarted in place. `body` is handed the stop signal of
    /// `stage`.
    pub fn spawn_thread<F>(
        &mut self,
        stage: Stage,
        name: &'static str,
        body: F,
    ) -> std::io::Result<()>
    where
        F: FnOnce(Shutdown) + Send + 'static,
    {
        let shutdown = self.signal(stage);
        let (done_tx, done_rx) = oneshot::channel::<()>();
        let thread_shutdown = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                body(thread_shutdown);
                // Not sent when `body` panics: the dropped sender says so.
                let _ = done_tx.send(());
            })?;
        let service = self.service;
        self.sets[stage as usize].spawn(async move {
            let finished = done_rx.await.is_ok();
            let joined = tokio::task::spawn_blocking(move || handle.join()).await;
            let panicked = !finished || !matches!(joined, Ok(Ok(())));
            if panicked {
                error!(service, thread = name, "thread panicked");
                return (name, Exit::Failed("panicked".into()));
            }
            if shutdown.is_stopping() {
                (name, Exit::Stopped)
            } else {
                error!(
                    service,
                    thread = name,
                    "a critical thread stopped; shutting down"
                );
                (name, Exit::Failed("exited before shutdown".into()))
            }
        });
        Ok(())
    }

    /// Wait for `signal` (the process's shutdown signal), returning early with
    /// the failure if a critical task stops first.
    pub async fn run_until(&mut self, signal: impl Future<Output = ()>) -> Result<(), TaskFailure> {
        let mut signal = std::pin::pin!(signal);
        loop {
            let [workers, listeners, storage] = &mut self.sets;
            let joined = tokio::select! {
                _ = &mut signal => return Ok(()),
                Some(r) = workers.join_next(), if !workers.is_empty() => r,
                Some(r) = listeners.join_next(), if !listeners.is_empty() => r,
                Some(r) = storage.join_next(), if !storage.is_empty() => r,
            };
            match outcome(joined) {
                (_, Exit::Stopped) => {}
                (task, Exit::Failed(reason)) => {
                    let failure = TaskFailure { task, reason };
                    self.failures.push(failure.clone());
                    return Err(failure);
                }
            }
        }
    }

    /// Stop `stage` and wait — at most `deadline` — for its tasks to end.
    /// Tasks still running at the deadline are aborted (a thread is left to
    /// die with the process) and reported as failures.
    pub async fn stop_stage(&mut self, stage: Stage, deadline: Duration) {
        self.signals[stage as usize].stop();
        let service = self.service;
        let set = &mut self.sets[stage as usize];
        let until = Instant::now() + deadline;
        while !set.is_empty() {
            match tokio::time::timeout_at(until, set.join_next()).await {
                Ok(Some(joined)) => {
                    if let (task, Exit::Failed(reason)) = outcome(joined) {
                        self.failures.push(TaskFailure { task, reason });
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    error!(
                        service,
                        ?stage,
                        remaining = set.len(),
                        ?deadline,
                        "tasks did not stop within the shutdown deadline; abandoning them"
                    );
                    self.failures.push(TaskFailure {
                        task: stage_name(stage),
                        reason: format!("{} task(s) did not stop within {deadline:?}", set.len()),
                    });
                    set.abort_all();
                    while set.join_next().await.is_some() {}
                    break;
                }
            }
        }
    }

    /// Stop every stage still running, in order, and report whether
    /// anything failed — while running or while stopping.
    pub async fn finish(mut self, deadline: Duration) -> Result<(), Vec<TaskFailure>> {
        for stage in STAGES {
            self.stop_stage(stage, deadline).await;
        }
        if self.failures.is_empty() {
            info!(service = self.service, "all tasks stopped");
            Ok(())
        } else {
            for f in &self.failures {
                warn!(service = self.service, task = f.task, reason = %f.reason, "task failure");
            }
            Err(self.failures)
        }
    }
}

fn stage_name(stage: Stage) -> &'static str {
    match stage {
        Stage::Workers => "workers",
        Stage::Listeners => "listeners",
        Stage::Storage => "storage",
    }
}

fn outcome(joined: Result<Outcome, JoinError>) -> Outcome {
    match joined {
        Ok(o) => o,
        // The wrapper itself never panics; it can only be aborted.
        Err(e) => ("supervisor", Exit::Failed(e.to_string())),
    }
}

fn describe(result: Result<(), JoinError>) -> String {
    match result {
        Ok(()) => "exited before shutdown".into(),
        Err(e) if e.is_panic() => {
            let panic = e.into_panic();
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown payload".into());
            format!("panicked: {msg}")
        }
        Err(e) => e.to_string(),
    }
}

/// A spawned task, aborted if the future awaiting it is dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl AbortOnDrop {
    async fn join(mut self) -> Result<(), JoinError> {
        (&mut self.0).await
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Retry `attempt` with exponential backoff ([`RESTART_BACKOFF_MIN`] to
/// [`RESTART_BACKOFF_MAX`]) until it succeeds or `shutdown` is cancelled
/// (`None`). Each failure is logged at `warn` with `what`.
pub async fn retry_with_backoff<T, E, F, Fut>(
    what: &str,
    shutdown: &CancellationToken,
    mut attempt: F,
) -> Option<T>
where
    E: std::fmt::Display,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut backoff = RESTART_BACKOFF_MIN;
    loop {
        let result = tokio::select! {
            r = attempt() => r,
            _ = shutdown.cancelled() => return None,
        };
        match result {
            Ok(v) => return Some(v),
            Err(e) => {
                warn!(error = %e, retry_in = ?backoff, "failed to start {what}; retrying");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.cancelled() => return None,
                }
                backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counter_task(name: &'static str, every: Duration, n: Arc<AtomicUsize>) -> PeriodicTask {
        PeriodicTask::new(name, every, move |_| {
            let n = n.clone();
            async move {
                n.fetch_add(1, Ordering::SeqCst);
            }
        })
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_tasks_tick_on_their_own_intervals_until_shutdown() {
        let fast = Arc::new(AtomicUsize::new(0));
        let slow = Arc::new(AtomicUsize::new(0));
        let off = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = watch::channel(false);
        let runner = tokio::spawn(run_periodic(
            vec![
                counter_task("fast", Duration::from_secs(1), fast.clone()),
                counter_task("slow", Duration::from_secs(5), slow.clone()),
                counter_task("off", Duration::from_secs(1), off.clone()).enabled_if(false),
            ],
            rx,
        ));
        tokio::time::sleep(Duration::from_millis(10_500)).await;
        tx.send(true).unwrap();
        runner.await.unwrap();
        assert_eq!(fast.load(Ordering::SeqCst), 10);
        assert_eq!(slow.load(Ordering::SeqCst), 2);
        assert_eq!(off.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn merging_keeps_the_first_of_each_name_and_drops_the_skipped() {
        let n = Arc::new(AtomicUsize::new(0));
        let a = vec![
            counter_task("shared", Duration::from_secs(1), n.clone()),
            counter_task("a-only", Duration::from_secs(1), n.clone()),
        ];
        let b = vec![
            counter_task("shared", Duration::from_secs(9), n.clone()),
            counter_task("skipped", Duration::from_secs(1), n.clone()),
        ];
        let merged = merge_tasks([a, b], &["skipped"]);
        assert_eq!(names(&merged), ["shared", "a-only"]);
        assert_eq!(merged[0].interval, Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_restartable_task_is_restarted_with_backoff() {
        let runs = Arc::new(AtomicUsize::new(0));
        let mut sup = Supervisor::new("test");
        let counted = runs.clone();
        sup.spawn(
            Stage::Workers,
            "flaky",
            Policy::Restart,
            move |sd: Shutdown| {
                let counted = counted.clone();
                async move {
                    if counted.fetch_add(1, Ordering::SeqCst) < 3 {
                        panic!("boom");
                    }
                    sd.stopped().await;
                }
            },
        );
        // 1s + 2s + 4s of backoff.
        let outcome = sup
            .run_until(tokio::time::sleep(Duration::from_secs(10)))
            .await;
        assert!(outcome.is_ok());
        assert_eq!(runs.load(Ordering::SeqCst), 4);
        assert!(sup.finish(SHUTDOWN_STAGE_DEADLINE).await.is_ok());
    }

    #[tokio::test]
    async fn a_critical_task_that_stops_ends_the_run_with_its_failure() {
        let mut sup = Supervisor::new("test");
        sup.spawn(
            Stage::Workers,
            "steady",
            Policy::Critical,
            |sd: Shutdown| async move { sd.stopped().await },
        );
        sup.spawn(Stage::Storage, "storage", Policy::Critical, |_| async {});
        let failure = sup
            .run_until(std::future::pending())
            .await
            .expect_err("a critical exit ends the run");
        assert_eq!(failure.task, "storage");
        let failures = sup.finish(SHUTDOWN_STAGE_DEADLINE).await.unwrap_err();
        assert_eq!(failures.len(), 1, "{failures:?}");
    }

    #[tokio::test]
    async fn a_thread_that_panics_is_reported_and_one_that_stops_on_request_is_not() {
        let mut sup = Supervisor::new("test");
        sup.spawn_thread(Stage::Listeners, "polite", |sd: Shutdown| {
            let mut rx = sd.watch();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let _ = rx.changed().await;
            });
        })
        .unwrap();
        sup.spawn_thread(Stage::Listeners, "doomed", |_| panic!("boom"))
            .unwrap();
        let failure = sup.run_until(std::future::pending()).await.unwrap_err();
        assert_eq!(failure.task, "doomed");
        let failures = sup.finish(SHUTDOWN_STAGE_DEADLINE).await.unwrap_err();
        assert_eq!(failures.len(), 1, "only the panic: {failures:?}");
    }

    /// Stages stop in order: a storage task sees the workers already gone.
    #[tokio::test]
    async fn stages_stop_in_order() {
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut sup = Supervisor::new("test");
        for (stage, name) in [
            (Stage::Storage, "storage"),
            (Stage::Listeners, "http"),
            (Stage::Workers, "outbox"),
        ] {
            let order = order.clone();
            sup.spawn(stage, name, Policy::Critical, move |sd: Shutdown| {
                let order = order.clone();
                async move {
                    sd.stopped().await;
                    order.lock().unwrap().push(name);
                }
            });
        }
        sup.run_until(async {}).await.unwrap();
        sup.finish(SHUTDOWN_STAGE_DEADLINE).await.unwrap();
        assert_eq!(*order.lock().unwrap(), ["outbox", "http", "storage"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stage_that_overruns_its_deadline_is_abandoned_and_reported() {
        let mut sup = Supervisor::new("test");
        sup.spawn(Stage::Listeners, "stalled", Policy::Critical, |_| {
            std::future::pending::<()>()
        });
        sup.run_until(async {}).await.unwrap();
        let failures = sup.finish(Duration::from_secs(30)).await.unwrap_err();
        assert_eq!(failures[0].task, "listeners");
    }

    #[tokio::test(start_paused = true)]
    async fn retry_with_backoff_retries_until_success_or_cancel() {
        let tries = AtomicUsize::new(0);
        let token = CancellationToken::new();
        let got = retry_with_backoff("thing", &token, || async {
            if tries.fetch_add(1, Ordering::SeqCst) < 2 {
                Err("not yet")
            } else {
                Ok(7)
            }
        })
        .await;
        assert_eq!(got, Some(7));
        token.cancel();
        let never: Option<()> =
            retry_with_backoff("thing", &token, || async { Err::<(), _>("no") }).await;
        assert_eq!(never, None);
    }
}
