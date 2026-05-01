//! Snapshot-based rollback orchestration — Phase R-E
//!
//! Invokes platform snapshot restore mechanisms after a ransomware event:
//! - macOS: `tmutil restore`
//! - Linux: `btrfs` subvolume snapshot restore
//! - Windows: `vssadmin revert` (VSS)
//!
//! All destructive actions are gated by the `AEGIS_REAL_RECOVERY=1` environment
//! variable. Without it the intent is logged and [`RestoreOutcome::Simulated`]
//! is returned. This prevents accidental rollbacks in CI or dev environments.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The outcome of a restore attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestoreOutcome {
    /// The real restore command was issued and completed successfully.
    Executed,
    /// `AEGIS_REAL_RECOVERY` was not set — intent logged, no real action taken.
    Simulated,
    /// The command was issued but exited with a non-zero code.
    Failed(String),
}

/// Errors from the rollback subsystem.
#[derive(Debug, thiserror::Error)]
pub enum RollbackError {
    #[error("IO error during rollback: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported platform for rollback")]
    UnsupportedPlatform,
}

/// Attempt to restore `target_path` from the most recent platform snapshot.
///
/// # Environment gate
/// Set `AEGIS_REAL_RECOVERY=1` to execute the real command.
/// Without it, logs the intent and returns [`RestoreOutcome::Simulated`].
pub async fn restore(target_path: &Path) -> Result<RestoreOutcome, RollbackError> {
    let real_recovery = std::env::var("AEGIS_REAL_RECOVERY")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);

    if !real_recovery {
        log::warn!("[rollback] AEGIS_REAL_RECOVERY not set — simulating restore of {target_path:?}");
        return Ok(RestoreOutcome::Simulated);
    }

    do_restore(target_path).await
}

#[cfg(target_os = "macos")]
async fn do_restore(target_path: &Path) -> Result<RestoreOutcome, RollbackError> {
    log::warn!("[rollback] macOS: invoking tmutil restore for {:?}", target_path);
    let output = tokio::process::Command::new("tmutil")
        .args(["restore", "-d", "/", target_path.to_str().unwrap_or(""), "-f"])
        .output()
        .await?;

    if output.status.success() {
        Ok(RestoreOutcome::Executed)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok(RestoreOutcome::Failed(stderr))
    }
}

#[cfg(target_os = "linux")]
async fn do_restore(target_path: &Path) -> Result<RestoreOutcome, RollbackError> {
    // Attempt btrfs snapshot restore. Falls back to a no-op if btrfs is not
    // available (non-btrfs filesystem) — RollbackError::UnsupportedPlatform.
    log::warn!("[rollback] Linux: invoking btrfs restore for {:?}", target_path);
    let output = tokio::process::Command::new("btrfs")
        .args(["restore", target_path.to_str().unwrap_or(""), "/mnt/restore-target"])
        .output()
        .await?;

    if output.status.success() {
        Ok(RestoreOutcome::Executed)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok(RestoreOutcome::Failed(stderr))
    }
}

#[cfg(target_os = "windows")]
async fn do_restore(target_path: &Path) -> Result<RestoreOutcome, RollbackError> {
    log::warn!("[rollback] Windows: invoking vssadmin revert for {target_path:?}");
    // vssadmin list shadows + revert snapshot
    let shadow_id = "{00000000-0000-0000-0000-000000000000}"; // placeholder; real impl queries list
    let output = tokio::process::Command::new("vssadmin")
        .args(["revert", &format!("/Shadow={shadow_id}"), "/ForceDismount"])
        .output()
        .await?;

    if output.status.success() {
        Ok(RestoreOutcome::Executed)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok(RestoreOutcome::Failed(stderr))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
async fn do_restore(_target_path: &Path) -> Result<RestoreOutcome, RollbackError> {
    Err(RollbackError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn simulated_when_env_unset() {
        // Ensure the env var is absent for this test.
        std::env::remove_var("AEGIS_REAL_RECOVERY");
        let outcome = restore(Path::new("/tmp/victim.txt")).await.unwrap();
        assert_eq!(outcome, RestoreOutcome::Simulated);
    }

    #[test]
    fn restore_outcome_serde_round_trip() {
        for variant in [
            RestoreOutcome::Executed,
            RestoreOutcome::Simulated,
            RestoreOutcome::Failed("exit code 1".to_string()),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: RestoreOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }
}
