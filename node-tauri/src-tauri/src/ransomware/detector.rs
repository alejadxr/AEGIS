// ---------------------------------------------------------------------------
// Ransomware signal correlator (Task #2)
//
// Collects `Signal` events from canary, entropy, mass-extension, and
// Shadow-Copy-deletion watchers. When it sees 2+ distinct signal kinds
// within `CORRELATION_WINDOW`, it calls `handle_incident`.
//
// Also drives the mass-extension-change detector via a background scan of
// sysinfo process writes: because per-process file I/O requires ETW/eBPF
// (Tier 2), the cross-platform path here is filesystem-event based:
// notify events grouped per parent directory.
// ---------------------------------------------------------------------------

use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use sysinfo::System;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration as TokioDuration};

use crate::ransomware::{handle_incident, RansomwareState};

/// Correlation window — at least 2 distinct signals must fire inside this
/// window for the response chain to run.
const CORRELATION_WINDOW: i64 = 2; // seconds

/// Minimum number of distinct signal kinds needed to trigger.
const MIN_DISTINCT_SIGNALS: usize = 2;

/// How many past signals to keep in memory for correlation.
const MAX_SIGNAL_BACKLOG: usize = 256;

/// Extensions we consider "user data" — mass churn on these is suspicious.
const TARGET_EXTS: &[&str] = &[
    "docx", "doc", "xlsx", "xls", "pdf", "jpg", "jpeg", "png", "txt", "zip",
    "pptx", "ppt", "csv", "rtf", "odt", "ods", "mp4", "mov",
];

/// Threshold for mass-extension-change detection.
const MASS_CHANGE_COUNT: usize = 20;
const MASS_CHANGE_WINDOW_SECS: i64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalKind {
    CanaryModified,
    MassExtensionChange,
    EntropySpike,
    ShadowCopyDeletion,
    BackupToolKilled,
    RansomNoteDropped,
}

#[derive(Debug, Clone)]
pub struct Signal {
    pub kind: SignalKind,
    pub detail: String,
    pub at: DateTime<Utc>,
    pub pid: Option<u32>,
    pub path: Option<PathBuf>,
}

/// Ring buffer of recent signals. Push-only from outside; the correlator
/// drains it.
#[derive(Debug)]
pub struct Detector {
    backlog: VecDeque<Signal>,
    /// Per-directory rolling counter for mass-extension detection.
    ext_hits: HashMap<PathBuf, Vec<DateTime<Utc>>>,
    /// Tracks last incident time to suppress duplicates.
    last_incident: Option<DateTime<Utc>>,
}

impl Detector {
    pub fn new() -> Self {
        Self {
            backlog: VecDeque::with_capacity(MAX_SIGNAL_BACKLOG),
            ext_hits: HashMap::new(),
            last_incident: None,
        }
    }

    pub fn push(&mut self, sig: Signal) {
        if self.backlog.len() >= MAX_SIGNAL_BACKLOG {
            self.backlog.pop_front();
        }
        self.backlog.push_back(sig);
    }

    /// Record a file-change event for mass-extension tracking. If the
    /// threshold trips, emits a `MassExtensionChange` signal.
    pub fn record_file_change(&mut self, path: &PathBuf) {
        let ext = match path.extension().and_then(|e| e.to_str()) {
            Some(e) => e.to_ascii_lowercase(),
            None => return,
        };
        if !TARGET_EXTS.contains(&ext.as_str()) {
            return;
        }
        let parent = match path.parent() {
            Some(p) => p.to_path_buf(),
            None => return,
        };
        let now = Utc::now();
        let entry = self.ext_hits.entry(parent.clone()).or_default();
        entry.push(now);

        // Prune entries outside the window
        let cutoff = now - Duration::seconds(MASS_CHANGE_WINDOW_SECS);
        entry.retain(|t| *t > cutoff);

        if entry.len() >= MASS_CHANGE_COUNT {
            let sig = Signal {
                kind: SignalKind::MassExtensionChange,
                detail: format!(
                    "{} target-extension writes in {}s under {}",
                    entry.len(),
                    MASS_CHANGE_WINDOW_SECS,
                    parent.display()
                ),
                at: now,
                pid: None,
                path: Some(parent),
            };
            // Push without re-locking entry's borrow
            entry.clear();
            self.push(sig);
        }
    }

    /// Returns the set of correlated signals if the trigger conditions hold.
    fn correlate(&mut self) -> Option<Vec<Signal>> {
        let now = Utc::now();

        // Skip if we recently fired — prevents incident storms
        if let Some(last) = self.last_incident {
            if (now - last) < Duration::seconds(10) {
                return None;
            }
        }

        let cutoff = now - Duration::seconds(CORRELATION_WINDOW);
        let recent: Vec<Signal> = self
            .backlog
            .iter()
            .filter(|s| s.at >= cutoff)
            .cloned()
            .collect();

        // Count distinct signal kinds in the window
        let distinct: std::collections::HashSet<SignalKind> =
            recent.iter().map(|s| s.kind).collect();

        if distinct.len() >= MIN_DISTINCT_SIGNALS {
            self.last_incident = Some(now);
            // Consume: drop signals older than cutoff so they don't double-fire
            self.backlog.retain(|s| s.at >= cutoff);
            Some(recent)
        } else {
            None
        }
    }
}

/// Background loop: every 250ms, check if correlation conditions are met,
/// and if so, run the response chain.
pub async fn run_correlator(state: Arc<Mutex<RansomwareState>>) {
    log::info!("[ransomware] correlator started");
    loop {
        sleep(TokioDuration::from_millis(250)).await;

        let fire = {
            let mut s = state.lock().await;
            if !s.enabled {
                continue;
            }
            s.detector.correlate()
        };

        if let Some(signals) = fire {
            // Best-effort: pick a pid from the most recent signal that has one
            let pid = signals.iter().rev().find_map(|s| s.pid);
            // Collect affected files from signals that have paths
            let files: Vec<PathBuf> = signals
                .iter()
                .filter_map(|s| s.path.clone())
                .collect();

            // If we don't have a pid from the signal, pick the most recently
            // started process whose executable exists in a writable path as a
            // last-resort heuristic (Tier 1; ETW improves this in task #5).
            let pid = pid.or_else(guess_offending_pid);

            tokio::spawn(handle_incident(state.clone(), pid, signals, files));
        }
    }
}

/// Best-effort Tier-1 heuristic: find the most recently started process
/// that is neither a system process nor AEGIS itself. This is intentionally
/// coarse; the ETW integration in Task #5 gives us precise per-write PIDs.
fn guess_offending_pid() -> Option<u32> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let own_pid: u32 = std::process::id();

    let mut candidates: Vec<(u32, u64, String)> = Vec::new();
    for (pid, proc_) in sys.processes() {
        let pid_u = pid.as_u32();
        if pid_u == own_pid || pid_u < 100 {
            continue;
        }
        let name = proc_.name().to_string_lossy().to_string();
        if name.eq_ignore_ascii_case("system") || name.eq_ignore_ascii_case("idle") {
            continue;
        }
        candidates.push((pid_u, proc_.start_time(), name));
    }
    candidates.sort_by_key(|(_, t, _)| std::cmp::Reverse(*t));
    candidates.first().map(|(p, _, _)| *p)
}
