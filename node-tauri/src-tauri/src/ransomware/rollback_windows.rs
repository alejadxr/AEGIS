// ---------------------------------------------------------------------------
// Windows VSS (Volume Shadow Copy) rollback (Task #2)
//
// On a ransomware incident, attempt to restore affected files from the most
// recent Volume Shadow Copy. Uses `vssadmin list shadows` to enumerate
// available snapshots and robocopy to pull the original file back.
//
// Also exposes a background monitor that watches for Shadow Copy deletion
// via `vssadmin list shadows` polling — when the count drops unexpectedly,
// we emit a ShadowCopyDeletion signal.
// ---------------------------------------------------------------------------

#![cfg(target_os = "windows")]

use chrono::Utc;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::os::windows::process::CommandExt;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration as TokioDuration};

use crate::ransomware::detector::{Signal, SignalKind};
use crate::ransomware::RansomwareState;

const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Run `vssadmin list shadows` and parse out the number of available copies
/// plus the device path of the most recent one.
fn list_shadow_copies() -> (usize, Option<String>) {
    let out = Command::new("vssadmin")
        .args(["list", "shadows"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let Ok(out) = out else {
        return (0, None);
    };
    let text = String::from_utf8_lossy(&out.stdout);

    let mut count = 0usize;
    let mut latest: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("Shadow Copy Volume:") {
            count += 1;
            if let Some(rest) = line.split_once(':').map(|(_, v)| v.trim()) {
                latest = Some(rest.to_string());
            }
        }
    }
    (count, latest)
}

/// Restore the given files from the most recent shadow copy. Returns the
/// number of files successfully restored.
pub async fn restore_from_shadow_copy(files: &[PathBuf]) -> Result<u64, String> {
    let (n, device) = tokio::task::spawn_blocking(list_shadow_copies)
        .await
        .map_err(|e| e.to_string())?;

    if n == 0 {
        return Err("no shadow copies available".into());
    }
    let device = device.ok_or("could not parse shadow copy device path")?;

    // vssadmin gives us a device path like \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
    // We create a symlink/junction from a temp dir to that device, then copy
    // files back from it.
    let mount = PathBuf::from(r"C:\Windows\Temp\aegis_vss_mount");
    let _ = std::fs::remove_dir_all(&mount);

    // `mklink /D` requires shell so we go through cmd.exe
    let mklink = Command::new("cmd")
        .args(["/C", "mklink", "/D", mount.to_str().unwrap_or(""), &format!("{}\\", device)])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    if mklink.is_err() {
        return Err("mklink to shadow copy device failed".into());
    }

    let mut restored = 0u64;
    for f in files {
        // Translate absolute path like C:\Users\alice\docs\file.docx into
        // <mount>\Users\alice\docs\file.docx
        let Some(stripped) = strip_drive(f) else {
            continue;
        };
        let src = mount.join(stripped);
        if !src.exists() {
            continue;
        }
        match std::fs::copy(&src, f) {
            Ok(_) => {
                restored += 1;
                log::info!("[vss] restored {}", f.display());
            }
            Err(e) => log::warn!("[vss] restore failed for {}: {}", f.display(), e),
        }
    }

    // Clean up junction
    let _ = Command::new("cmd")
        .args(["/C", "rmdir", mount.to_str().unwrap_or("")])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    Ok(restored)
}

fn strip_drive(p: &Path) -> Option<PathBuf> {
    let s = p.to_string_lossy();
    // e.g. "C:\Users\alice\file.txt" -> "Users\alice\file.txt"
    if s.len() >= 3 && &s[1..3] == ":\\" {
        Some(PathBuf::from(&s[3..]))
    } else {
        None
    }
}

/// Background monitor: every 10s, poll vssadmin and watch for shadow copies
/// disappearing. A drop in count = vssadmin delete was likely run.
pub async fn monitor_shadow_copy_deletion(state: Arc<Mutex<RansomwareState>>) {
    log::info!("[vss] shadow copy monitor started");
    let mut last_count: Option<usize> = None;

    loop {
        sleep(TokioDuration::from_secs(10)).await;

        let (count, _) = tokio::task::spawn_blocking(list_shadow_copies)
            .await
            .unwrap_or((0, None));

        if let Some(prev) = last_count {
            if count < prev {
                log::warn!(
                    "[vss] shadow copy count dropped {} -> {} (possible deletion)",
                    prev,
                    count
                );
                let sig = Signal {
                    kind: SignalKind::ShadowCopyDeletion,
                    detail: format!("vss count dropped {} -> {}", prev, count),
                    at: Utc::now(),
                    pid: None,
                    path: None,
                };
                let mut s = state.lock().await;
                s.detector.push(sig);
            }
        }
        last_count = Some(count);
    }
}
