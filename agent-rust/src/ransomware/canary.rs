//! Canary file watcher — Phase R-E
//!
//! Watches a set of sentinel files. Any modification, deletion, or rename
//! raises a [`CanaryEvent`] sent over an async mpsc channel.
//!
//! Uses the `notify` crate for cross-platform watching (inotify on Linux,
//! FSEvents on macOS, ReadDirectoryChangesW on Windows). No platform-specific
//! code lives here — notify abstracts it away.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;

/// An event raised when a canary file is touched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryEvent {
    /// The canary path that was affected.
    pub path: PathBuf,
    /// The PID of the process that caused the event, if it can be determined.
    /// On most platforms notify does not surface the PID — this is populated
    /// by higher-level logic when available.
    pub pid_if_known: Option<u32>,
    /// Unix timestamp (seconds since epoch) when the event was detected.
    pub timestamp: u64,
}

impl CanaryEvent {
    fn now(path: PathBuf) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            path,
            pid_if_known: None,
            timestamp,
        }
    }
}

/// Errors from the canary subsystem.
#[derive(Debug, thiserror::Error)]
pub enum CanaryError {
    #[error("notify error: {0}")]
    Notify(#[from] notify::Error),
    #[error("send error: channel closed")]
    Send,
}

/// Owns the notify watcher. Drop to stop watching.
pub struct CanaryWatcher {
    /// The underlying notify watcher — kept alive via ownership.
    _watcher: RecommendedWatcher,
}

impl CanaryWatcher {
    /// Create a new watcher. Events are forwarded to `tx`. The caller must
    /// hold the returned `CanaryWatcher` alive for as long as watching is
    /// desired.
    pub fn new(paths: Vec<PathBuf>, tx: Sender<CanaryEvent>) -> Result<Self, CanaryError> {
        // notify 7 API: handler closure receives Result<Event, Error>.
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        // Only react to events that represent modification or removal.
                        let interesting = matches!(
                            event.kind,
                            EventKind::Modify(_)
                                | EventKind::Remove(_)
                                | EventKind::Create(_)
                        );
                        if interesting {
                            for path in event.paths {
                                let ev = CanaryEvent::now(path);
                                // Use blocking send — we're in a notify thread, not async.
                                if tx.blocking_send(ev).is_err() {
                                    // Channel closed; stop silently.
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("[canary] notify error: {e}");
                    }
                }
            },
            Config::default(),
        )?;

        // Watch each canary path non-recursively (they are files, not dirs).
        // If a parent directory must be watched (some backends require it),
        // notify handles that transparently.
        for path in &paths {
            // Watch the parent directory so we catch deletes/renames of the
            // canary file itself, which may not fire on the file inode alone.
            if let Some(parent) = path.parent() {
                watcher.watch(parent, RecursiveMode::NonRecursive)?;
            } else {
                watcher.watch(path, RecursiveMode::NonRecursive)?;
            }
        }

        Ok(Self { _watcher: watcher })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_event_serde_round_trip() {
        let ev = CanaryEvent {
            path: PathBuf::from("/tmp/canary.dat"),
            pid_if_known: Some(1234),
            timestamp: 1_700_000_000,
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        let back: CanaryEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.path, ev.path);
        assert_eq!(back.pid_if_known, ev.pid_if_known);
        assert_eq!(back.timestamp, ev.timestamp);
    }

    #[test]
    fn canary_event_now_has_reasonable_timestamp() {
        let ev = CanaryEvent::now(PathBuf::from("/tmp/x"));
        // Must be after 2020-01-01
        assert!(ev.timestamp > 1_577_836_800);
        assert!(ev.pid_if_known.is_none());
    }
}
