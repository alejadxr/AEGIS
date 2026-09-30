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
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration as TokioDuration};

use std::path::Path;

use crate::ransomware::{handle_incident, RansomwareState, ResponseMode};

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

/// Directory names that hold regenerable build output. A write under any of
/// these is normal developer work, so LOW-confidence signals ignore it.
const BUILD_DIRS: &[&str] = &[
    "target",
    "node_modules",
    "obj",
    "build",
    "dist",
    ".git",
    "__pycache__",
];

/// `bin\Debug` / `bin\Release` (matched as consecutive components; a bare
/// `bin` is not excluded because it also holds installed executables).
const BUILD_DIR_PAIRS: &[(&str, &str)] = &[("bin", "debug"), ("bin", "release")];

/// Extensions of compiler / bytecode artifacts.
const ARTIFACT_EXTS: &[&str] = &["o", "obj", "rlib", "rmeta", "pdb", "lib", "a", "d", "pyc"];

/// True if `path` is a regenerable build artifact. Only ever used to discard
/// LOW-confidence signals; HIGH-confidence signals are never filtered by path.
pub fn is_build_artifact_path(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if ARTIFACT_EXTS.contains(&ext.to_ascii_lowercase().as_str()) {
            return true;
        }
    }
    // Split on both separators so Windows paths are handled on any host.
    let raw = path.to_string_lossy().to_ascii_lowercase();
    let comps: Vec<&str> = raw.split(|c| c == '/' || c == '\\').collect();
    if comps.iter().any(|c| BUILD_DIRS.contains(c)) {
        return true;
    }
    comps
        .windows(2)
        .any(|w| BUILD_DIR_PAIRS.iter().any(|(a, b)| w[0] == *a && w[1] == *b))
}

/// How much a signal alone says about ransomware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Behaviour with essentially no benign explanation. May trigger the
    /// autonomous response.
    High,
    /// Also produced by ordinary software (builds, installers, admin
    /// tooling). Reported to the server, never acted on locally.
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalKind {
    CanaryModified,
    MassExtensionChange,
    EntropySpike,
    ShadowCopyDeletion,
    BackupToolKilled,
    RansomNoteDropped,
}

impl SignalKind {
    pub fn confidence(self) -> Confidence {
        match self {
            // A user-invisible decoy was touched, a ransom note was written,
            // or the VSS restore points were wiped: no benign workflow does
            // these.
            SignalKind::CanaryModified
            | SignalKind::RansomNoteDropped
            | SignalKind::ShadowCopyDeletion => Confidence::High,
            // Compilers, archivers and installers write high-entropy files
            // and many new extensions in bursts.
            SignalKind::EntropySpike | SignalKind::MassExtensionChange => Confidence::Low,
            // Backup software is stopped by updates, uninstallers and admins
            // routinely; a real attacker does it too, but that shows up as
            // a shadow-copy deletion or a canary hit.
            SignalKind::BackupToolKilled => Confidence::Low,
        }
    }
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
        if sig.kind.confidence() == Confidence::Low
            && sig.path.as_deref().map_or(false, is_build_artifact_path)
        {
            return;
        }
        if self.backlog.len() >= MAX_SIGNAL_BACKLOG {
            self.backlog.pop_front();
        }
        self.backlog.push_back(sig);
    }

    /// Record a file-change event for mass-extension tracking. If the
    /// threshold trips, emits a `MassExtensionChange` signal.
    pub fn record_file_change(&mut self, path: &PathBuf) {
        if is_build_artifact_path(path) {
            return;
        }
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
    pub(crate) fn correlate(&mut self) -> Option<Correlation> {
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
            let has_high = recent.iter().any(|s| s.kind.confidence() == Confidence::High);
            Some(Correlation { signals: recent, has_high })
        } else {
            None
        }
    }
}

/// Result of a successful correlation.
#[derive(Debug)]
pub(crate) struct Correlation {
    pub signals: Vec<Signal>,
    /// At least one HIGH-confidence signal is in the window.
    pub has_high: bool,
}

/// What to do about a correlation. The autonomous response needs both a
/// HIGH-confidence signal and `enforce` mode; everything else is report-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    /// Kill the attributed process tree (if any), roll back, report.
    Enforce,
    /// HIGH signal seen but mode is `observe`: report only.
    Observed,
    /// LOW signals only: report only.
    ReportOnly,
}

pub fn decide(mode: ResponseMode, has_high: bool) -> Response {
    match (has_high, mode) {
        (true, ResponseMode::Enforce) => Response::Enforce,
        (true, ResponseMode::Observe) => Response::Observed,
        (false, _) => Response::ReportOnly,
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
            let mode = s.response_mode;
            s.detector.correlate().map(|c| (c, mode))
        };

        if let Some((corr, mode)) = fire {
            let response = decide(mode, corr.has_high);
            let signals = corr.signals;
            // Only a pid attributed by a signal is used. Never guessed: see
            // `kill_target`.
            let pid = signals.iter().rev().find_map(|s| s.pid);
            let files: Vec<PathBuf> = signals.iter().filter_map(|s| s.path.clone()).collect();
            tokio::spawn(handle_incident(state.clone(), pid, signals, files, response));
        }
    }
}

/// Which process to kill for a correlation. Killing requires enforce mode AND
/// a pid attributed by a signal. With no attribution we do not kill anything:
/// guessing (e.g. "newest process") hits unrelated processes such as a
/// compiler or browser and misses the real encryptor. Per-PID attribution via
/// ETW/eBPF is future work; until then unattributed incidents are reported and
/// rolled back only.
pub(crate) fn kill_target(response: Response, pid: Option<u32>) -> Option<u32> {
    if response == Response::Enforce {
        pid
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(kind: SignalKind, path: &str) -> Signal {
        Signal {
            kind,
            detail: "t".into(),
            at: Utc::now(),
            pid: None,
            path: Some(PathBuf::from(path)),
        }
    }

    #[test]
    fn build_burst_yields_no_action_and_no_high() {
        let mut d = Detector::new();
        for i in 0..400 {
            let ext = ["o", "rlib", "rmeta", "obj", "pdb"][i % 5];
            let p = PathBuf::from(format!("/home/dev/proj/target/debug/deps/f{i}.{ext}"));
            d.record_file_change(&p);
            d.push(sig(SignalKind::EntropySpike, p.to_str().unwrap()));
            d.push(sig(SignalKind::MassExtensionChange, "/home/dev/proj/target/debug/deps"));
        }
        match d.correlate() {
            None => {}
            Some(c) => {
                assert!(!c.has_high);
                assert_ne!(decide(ResponseMode::Enforce, c.has_high), Response::Enforce);
            }
        }
    }

    #[test]
    fn enforce_without_attributed_pid_kills_nothing() {
        assert_eq!(kill_target(Response::Enforce, None), None);
    }

    #[test]
    fn enforce_with_attributed_pid_targets_that_pid() {
        assert_eq!(kill_target(Response::Enforce, Some(4242)), Some(4242));
    }

    #[test]
    fn non_enforce_never_kills_even_with_pid() {
        assert_eq!(kill_target(Response::Observed, Some(4242)), None);
        assert_eq!(kill_target(Response::ReportOnly, Some(4242)), None);
    }

    #[test]
    fn build_dir_matching() {
        for p in [
            "C:\\src\\app\\bin\\Debug\\a.dll",
            "C:\\src\\app\\bin\\Release\\a.dll",
            "/x/node_modules/y/z.js",
            "/x/.git/objects/ab",
            "/x/a.pyc",
            "/x/__pycache__/m.py",
        ] {
            assert!(is_build_artifact_path(Path::new(p)), "{p}");
        }
        for p in ["/home/u/Documents/a.docx", "/usr/bin/tool", "/home/u/targets/a.txt"] {
            assert!(!is_build_artifact_path(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn entropy_plus_extension_outside_build_dirs_reports_only() {
        let mut d = Detector::new();
        d.push(sig(SignalKind::EntropySpike, "/home/u/Documents/a.docx"));
        d.push(sig(SignalKind::MassExtensionChange, "/home/u/Documents"));
        let c = d.correlate().expect("correlates");
        assert!(!c.has_high);
        assert_eq!(decide(ResponseMode::Enforce, c.has_high), Response::ReportOnly);
        assert_eq!(decide(ResponseMode::Observe, c.has_high), Response::ReportOnly);
    }

    #[test]
    fn ransom_note_plus_entropy_enforces_or_observes() {
        let mut d = Detector::new();
        d.push(sig(SignalKind::RansomNoteDropped, "/home/u/Documents/README_DECRYPT.txt"));
        d.push(sig(SignalKind::EntropySpike, "/home/u/Documents/a.docx"));
        let c = d.correlate().expect("correlates");
        assert!(c.has_high);
        assert_eq!(decide(ResponseMode::Enforce, c.has_high), Response::Enforce);
        assert_eq!(decide(ResponseMode::Observe, c.has_high), Response::Observed);
    }

    #[test]
    fn high_signal_is_never_excluded_by_path() {
        let mut d = Detector::new();
        d.push(sig(SignalKind::CanaryModified, "/x/target/canary.txt"));
        d.push(sig(SignalKind::RansomNoteDropped, "/x/node_modules/README_DECRYPT.txt"));
        assert!(d.correlate().expect("correlates").has_high);
    }
}
