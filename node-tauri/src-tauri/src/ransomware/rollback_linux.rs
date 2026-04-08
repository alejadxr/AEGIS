// ---------------------------------------------------------------------------
// Linux rollback (Task #2)
//
// Tries three strategies in order:
//   1. btrfs snapshots   — if the target path sits on a btrfs subvolume,
//                          locate a recent snapshot and copy the file back.
//   2. LVM snapshots     — mount the most recent LVM snapshot RO and copy.
//   3. Userspace ringbuf — fallback: before any high-entropy write would
//                          be detected, agent-rust/fim preserves a copy in
//                          $HOME/.aegis/ringbuffer/. Restore from there.
//
// The ringbuffer is the only guaranteed-available fallback; btrfs/lvm are
// best-effort based on host configuration.
// ---------------------------------------------------------------------------

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

const RING_BUFFER_DIR: &str = ".aegis/ringbuffer";
const RING_BUFFER_SIZE: usize = 2000; // files

/// Restore the given files from the best available snapshot source.
/// Returns the number of files successfully restored.
pub async fn restore_from_snapshot(files: &[PathBuf]) -> Result<u64, String> {
    let mut restored = 0u64;
    for f in files {
        if restore_one(f).await {
            restored += 1;
        }
    }
    Ok(restored)
}

async fn restore_one(path: &Path) -> bool {
    // 1. btrfs
    if let Some(src) = find_btrfs_snapshot(path) {
        if std::fs::copy(&src, path).is_ok() {
            log::info!("[rollback] btrfs restored {}", path.display());
            return true;
        }
    }
    // 2. lvm
    if let Some(src) = find_lvm_snapshot(path) {
        if std::fs::copy(&src, path).is_ok() {
            log::info!("[rollback] lvm restored {}", path.display());
            return true;
        }
    }
    // 3. userspace ringbuffer
    if let Some(src) = find_ringbuffer_copy(path) {
        if std::fs::copy(&src, path).is_ok() {
            log::info!("[rollback] ringbuf restored {}", path.display());
            return true;
        }
    }
    false
}

fn find_btrfs_snapshot(path: &Path) -> Option<PathBuf> {
    // Use `btrfs subvolume list` to discover snapshot subvolumes that
    // mirror the user's home. Heuristic: look for /.snapshots/<timestamp>/
    let out = Command::new("btrfs")
        .args(["subvolume", "list", "/"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut best: Option<PathBuf> = None;
    for line in text.lines() {
        if let Some(pos) = line.find("path ") {
            let sub = line[pos + 5..].trim();
            let candidate = PathBuf::from("/").join(sub);
            if candidate.to_string_lossy().contains(".snapshots") {
                // Last match wins; they're listed oldest-to-newest
                best = Some(candidate);
            }
        }
    }
    let snap = best?;
    // Strip the leading '/' off `path` and join onto snap
    let rel = path.strip_prefix("/").ok()?;
    let candidate = snap.join(rel);
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

fn find_lvm_snapshot(path: &Path) -> Option<PathBuf> {
    // Parse `lvs --noheadings -o lv_name,origin,snap_percent`.
    let out = Command::new("lvs")
        .args(["--noheadings", "-o", "lv_name,origin"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut snap_name: Option<String> = None;
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && !parts[1].is_empty() {
            snap_name = Some(parts[0].to_string());
        }
    }
    let _ = snap_name?;

    // Best-effort: assume mount at /mnt/aegis_lvm_snap (created by setup)
    let mount = PathBuf::from("/mnt/aegis_lvm_snap");
    if !mount.exists() {
        return None;
    }
    let rel = path.strip_prefix("/").ok()?;
    let candidate = mount.join(rel);
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

fn find_ringbuffer_copy(path: &Path) -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let ring = PathBuf::from(home).join(RING_BUFFER_DIR);
    if !ring.exists() {
        return None;
    }

    // Files are stored by sha256(full_path) — look them up by name
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    let candidate = ring.join(hex);
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

/// Copy a file into the ringbuffer. Called by the FIM watcher *before* it
/// lets a suspicious write land. Best-effort, lossy under memory pressure.
#[allow(dead_code)]
pub fn ringbuffer_save(path: &Path) -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|e| e.to_string())?;
    let ring = PathBuf::from(home).join(RING_BUFFER_DIR);
    std::fs::create_dir_all(&ring).map_err(|e| e.to_string())?;

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    let dst = ring.join(hex);

    std::fs::copy(path, dst).map_err(|e| e.to_string())?;

    // Evict oldest entries when over budget
    if let Ok(rd) = std::fs::read_dir(&ring) {
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        if entries.len() > RING_BUFFER_SIZE {
            entries.sort_by_key(|e| {
                e.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            });
            let excess = entries.len() - RING_BUFFER_SIZE;
            for e in entries.iter().take(excess) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    Ok(())
}
