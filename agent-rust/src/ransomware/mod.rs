//! Ransomware defense module — Phase R-E
//!
//! Provides [`RansomwareGuard`]: the public entry-point that orchestrates
//! canary watching, entropy classification, and process killing.

pub mod canary;
pub mod entropy;
pub mod killer;
pub mod rollback;
pub mod selfprotect;

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::ransomware::canary::{CanaryEvent, CanaryWatcher};
use crate::ransomware::entropy::EntropyClassifier;
use crate::ransomware::killer::Killer;

/// Configuration for the ransomware guard.
#[derive(Debug, Clone)]
pub struct RansomwareConfig {
    /// Paths of canary files to watch. These are sentinel files whose
    /// modification or deletion triggers an immediate alarm.
    pub canary_paths: Vec<PathBuf>,

    /// Number of writes per second threshold for entropy-based detection.
    /// Default: 50.
    pub write_rate_threshold: u64,

    /// Minimum mean Shannon entropy (bits/byte) of written data for a process
    /// to be classified as ransomware-like. Default: 7.5.
    pub entropy_threshold: f64,

    /// If true, forensic chain is captured before the offending process is
    /// killed. Default: true.
    pub capture_forensics: bool,
}

impl Default for RansomwareConfig {
    fn default() -> Self {
        Self {
            canary_paths: vec![],
            write_rate_threshold: 50,
            entropy_threshold: 7.5,
            capture_forensics: true,
        }
    }
}

/// Public guard that orchestrates all ransomware defense subsystems.
pub struct RansomwareGuard {
    config: RansomwareConfig,
}

impl RansomwareGuard {
    /// Create a new guard with the supplied configuration.
    pub fn new(config: RansomwareConfig) -> Self {
        Self { config }
    }

    /// Run the guard asynchronously. Returns when a fatal error occurs or the
    /// process is interrupted. The future never resolves normally during healthy
    /// operation — callers should `tokio::select!` or `tokio::spawn` it.
    pub async fn run(self) -> Result<(), RansomwareError> {
        let classifier = Arc::new(Mutex::new(EntropyClassifier::new(
            self.config.write_rate_threshold,
            self.config.entropy_threshold,
        )));
        let killer = Killer::new(self.config.capture_forensics);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<CanaryEvent>(256);

        // Start canary watcher on a background thread (notify uses threads).
        let watcher = CanaryWatcher::new(self.config.canary_paths.clone(), tx)?;
        // Keep watcher alive for the duration of `run`.
        let _watcher = watcher;

        let n_paths = self.config.canary_paths.len();
        log::info!("[ransomware] guard running — watching {n_paths} canary paths");

        while let Some(event) = rx.recv().await {
            log::warn!("[ransomware] canary triggered: {event:?}");

            // If a PID is known, classify and kill immediately.
            if let Some(pid) = event.pid_if_known {
                let now = std::time::Instant::now();
                let is_ransom = {
                    let cls = classifier.lock().await;
                    cls.is_ransom_like(pid, now)
                };

                // Canary modification alone is enough to act; entropy result
                // provides additional context for logging.
                log::warn!(
                    "[ransomware] killing PID {pid} (canary hit, entropy_ransom_like={is_ransom})"
                );
                match killer.kill_chain(pid).await {
                    Ok(snapshot) => {
                        log::warn!("[ransomware] killed chain: {snapshot:?}");
                    }
                    Err(e) => {
                        log::error!("[ransomware] kill failed: {e}");
                    }
                }
            } else {
                log::warn!("[ransomware] canary event without PID — manual investigation required");
            }
        }

        Err(RansomwareError::ChannelClosed)
    }
}

/// Errors produced by the ransomware guard.
#[derive(Debug, thiserror::Error)]
pub enum RansomwareError {
    #[error("canary channel closed unexpectedly")]
    ChannelClosed,

    #[error("canary watcher error: {0}")]
    Watcher(#[from] canary::CanaryError),

    #[error("killer error: {0}")]
    Killer(#[from] killer::KillerError),
}
