// ---------------------------------------------------------------------------
// Canary file generator and watcher (Task #2)
//
// Generates hidden decoy files (.docx-like, .xlsx-like, .pdf-like) in the
// user's Documents, Desktop, and Downloads directories. Any modification to
// these files is a strong ransomware signal — no legitimate app touches them.
// Also detects drops of known ransom note filenames in the watched tree.
// ---------------------------------------------------------------------------

use chrono::Utc;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rand::Rng;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::ransomware::detector::{Signal, SignalKind};
use crate::ransomware::RansomwareState;

/// Known ransom note filename patterns (case-insensitive).
const RANSOM_NOTE_PATTERNS: &[&str] = &[
    "how_to_decrypt",
    "how-to-decrypt",
    "decrypt_instructions",
    "your_files",
    "recovery_key",
    "!!!readme",
    "restore_files",
    "ransom",
];

/// True if a lowercased filename looks like a ransom note.
fn is_ransom_note(lower_name: &str) -> bool {
    RANSOM_NOTE_PATTERNS.iter().any(|p| lower_name.contains(p))
}

/// Seed 10 canary files across user directories (per profile in service mode).
pub fn seed_canaries() -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for targets in target_groups() {
        seed_group(&targets, &mut out);
    }

    if out.is_empty() {
        return Err("no canary files could be created".into());
    }
    Ok(out)
}

/// Seed up to 10 canaries across one profile's directories.
fn seed_group(targets: &[PathBuf], out: &mut Vec<PathBuf>) {
    // 10 canaries total, split across dirs
    let templates: [(&str, &[u8]); 5] = [
        ("_aegis_ledger.docx", b"aegis canary document v1"),
        ("_aegis_sheet.xlsx", b"aegis canary spreadsheet v1"),
        ("_aegis_report.pdf", b"aegis canary pdf v1"),
        ("_aegis_photo.jpg", b"aegis canary image v1"),
        ("_aegis_notes.txt", b"aegis canary notes v1"),
    ];

    let mut rng = rand::thread_rng();
    let mut count = 0;
    'outer: for dir in targets {
        if !dir.exists() {
            let _ = std::fs::create_dir_all(dir);
        }
        for (name, content) in &templates {
            // Salt filenames so they don't collide between runs
            let salt: u32 = rng.gen_range(1000..9999);
            let fname = format!(".{}_{}", salt, name);
            let path = dir.join(&fname);
            match std::fs::write(&path, content) {
                Ok(()) => {
                    // Mark hidden on Windows
                    #[cfg(target_os = "windows")]
                    {
                        let _ = set_hidden(&path);
                    }
                    out.push(path);
                    count += 1;
                    if count >= 10 {
                        break 'outer;
                    }
                }
                Err(e) => {
                    log::debug!("[canary] couldn't write {:?}: {}", path, e);
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn set_hidden(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    // Use attrib.exe as a safe portable fallback — avoids pulling in windows crate here
    // attrib +H "path"
    let _ = path.as_os_str().encode_wide();
    let status = std::process::Command::new("attrib")
        .arg("+H")
        .arg(path)
        .status();
    let _ = status;
    Ok(())
}

/// Directories to seed canaries in, one group per profile.
///
/// GUI/headless: the current user's profile. Windows service (LocalSystem):
/// `USERPROFILE` is the systemprofile, so every real profile under the Users
/// directory gets its own group instead.
fn target_groups() -> Vec<Vec<PathBuf>> {
    #[cfg(target_os = "windows")]
    {
        if crate::cli::is_service() {
            return service_profile_groups();
        }
    }
    vec![target_dirs()]
}

/// All directories canaries live in (used for watching).
fn all_target_dirs() -> Vec<PathBuf> {
    target_groups().into_iter().flatten().collect()
}

const PROFILE_SUBDIRS: [&str; 3] = ["Documents", "Desktop", "Downloads"];

/// The Documents/Desktop/Downloads folders of a profile that exist.
/// Profiles without any of them yield nothing.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn existing_profile_dirs(profile: &Path) -> Vec<PathBuf> {
    PROFILE_SUBDIRS
        .iter()
        .map(|d| profile.join(d))
        .filter(|p| p.is_dir())
        .collect()
}

#[cfg(target_os = "windows")]
fn service_profile_groups() -> Vec<Vec<PathBuf>> {
    crate::cli::service_profile_roots()
        .iter()
        .map(|p| existing_profile_dirs(p))
        .filter(|d| !d.is_empty())
        .collect()
}

/// Return the set of user directories we want to seed canaries in.
fn target_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    #[cfg(target_os = "windows")]
    {
        if let Ok(up) = std::env::var("USERPROFILE") {
            let base = PathBuf::from(up);
            out.push(base.join("Documents"));
            out.push(base.join("Desktop"));
            out.push(base.join("Downloads"));
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let base = PathBuf::from(home);
            out.push(base.join("Documents"));
            out.push(base.join("Desktop"));
            out.push(base.join("Downloads"));
        }
    }
    out
}

/// Watch canary files and the user directories they live in. Any canary
/// modification or ransom note drop emits a `Signal` to the detector.
pub async fn watch_canaries(state: Arc<Mutex<RansomwareState>>) -> Result<(), String> {
    let (tx, rx) = channel::<notify::Result<notify::Event>>();

    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| e.to_string())?;

    // Watch the parent directories of each canary recursively
    let dirs: Vec<PathBuf> = all_target_dirs();
    for dir in &dirs {
        if dir.exists() {
            if let Err(e) = watcher.watch(dir, RecursiveMode::Recursive) {
                log::warn!("[canary] failed to watch {:?}: {}", dir, e);
            } else {
                log::debug!("[canary] watching {:?}", dir);
            }
        }
    }

    let canary_set: Vec<PathBuf> = { state.lock().await.canary_paths.clone() };

    loop {
        // Block until we get an event
        let event = match rx.recv() {
            Ok(Ok(e)) => e,
            Ok(Err(e)) => {
                log::debug!("[canary] watcher error: {}", e);
                continue;
            }
            Err(_) => {
                // Channel closed, watcher dropped
                break;
            }
        };

        let kind_matches = matches!(
            event.kind,
            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_),
        );
        if !kind_matches {
            continue;
        }

        for path in &event.paths {
            // 1. Canary file modified?
            if canary_set.iter().any(|c| c == path) {
                let sig = Signal {
                    kind: SignalKind::CanaryModified,
                    detail: format!("canary touched: {}", path.display()),
                    at: Utc::now(),
                    pid: None,
                    path: Some(path.clone()),
                };
                log::warn!("[canary] TRIP: {}", sig.detail);
                let mut s = state.lock().await;
                s.detector.push(sig);
            }

            // 2. Known ransom note dropped?
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                let lower = name.to_ascii_lowercase();
                if is_ransom_note(&lower) {
                    let sig = Signal {
                        kind: SignalKind::RansomNoteDropped,
                        detail: format!("ransom note dropped: {}", path.display()),
                        at: Utc::now(),
                        pid: None,
                        path: Some(path.clone()),
                    };
                    log::warn!("[canary] ransom note: {}", sig.detail);
                    let mut s = state.lock().await;
                    s.detector.push(sig);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_readme_is_not_a_ransom_note() {
        assert!(!is_ransom_note("readme.txt"));
        assert!(!is_ransom_note("read_me.txt"));
    }

    #[test]
    fn explicit_ransom_notes_still_match() {
        for n in ["!!!readme!!!.txt", "how_to_decrypt.html", "restore_files.txt", "your_files_are_encrypted.txt"] {
            assert!(is_ransom_note(n), "{n}");
        }
    }
}

#[cfg(test)]
mod profile_dir_tests {
    use super::*;

    #[test]
    fn only_existing_standard_folders_are_used() {
        let root = std::env::temp_dir().join(format!("aegis-canary-{}", uuid::Uuid::new_v4()));
        let full = root.join("alice");
        let partial = root.join("bob");
        let empty = root.join("carol");
        for d in ["Documents", "Desktop", "Downloads"] {
            std::fs::create_dir_all(full.join(d)).unwrap();
        }
        std::fs::create_dir_all(partial.join("Documents")).unwrap();
        std::fs::create_dir_all(&empty).unwrap();

        assert_eq!(existing_profile_dirs(&full).len(), 3);
        assert_eq!(existing_profile_dirs(&partial), vec![partial.join("Documents")]);
        assert!(existing_profile_dirs(&empty).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
