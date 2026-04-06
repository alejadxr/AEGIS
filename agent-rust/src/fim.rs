//! File Integrity Monitoring (FIM) module.
//!
//! Uses the `notify` crate to watch filesystem paths for changes,
//! mirroring the Python agent's watchdog-based FIM.

use chrono::Utc;
use notify::{
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};

/// A FIM event record, ready for serialization / IPC output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimEvent {
    pub path: String,
    pub event_type: String,
    pub severity: String,
    pub timestamp: String,
    pub hash_before: String,
    pub hash_after: String,
    pub is_breadcrumb: bool,
}

/// Sensitive file patterns that trigger higher severity.
const SENSITIVE_PATTERNS: &[&str] = &[
    "authorized_keys",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "crontab",
    ".env",
    "credentials",
    "shadow",
];

/// Compute SHA-256 hash of a file using platform tools.
/// We avoid pulling in a full crypto crate for just this one hash.
/// Instead we shell out to shasum or use a tiny inline implementation.
///
/// For the prototype we use a simple approach: call the system's sha256
/// utility. In production, add `sha2` crate.
fn sha256_of_file(path: &Path) -> String {
    // Try using the platform's sha256 tool
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("shasum")
            .args(["-a", "256"])
            .arg(path)
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(hash) = stdout.split_whitespace().next() {
                    return hash.to_string();
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("sha256sum")
            .arg(path)
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(hash) = stdout.split_whitespace().next() {
                    return hash.to_string();
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let mut cmd = std::process::Command::new("certutil");
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        if let Ok(output) = cmd
            .args(["-hashfile"])
            .arg(path)
            .arg("SHA256")
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // certutil output: second line is the hash
                if let Some(hash_line) = stdout.lines().nth(1) {
                    return hash_line.trim().replace(' ', "");
                }
            }
        }
    }

    String::new()
}

/// Determine severity based on the file path.
fn classify_severity(path: &str) -> String {
    let path_lower = path.to_lowercase();
    for pattern in SENSITIVE_PATTERNS {
        if path_lower.contains(pattern) {
            return "high".to_string();
        }
    }
    "low".to_string()
}

/// Convert a notify EventKind to a human-readable string.
fn event_kind_to_string(kind: &EventKind) -> String {
    match kind {
        EventKind::Create(_) => "created".to_string(),
        EventKind::Modify(_) => "modified".to_string(),
        EventKind::Remove(_) => "deleted".to_string(),
        _ => "other".to_string(),
    }
}

/// Shared state for file hashes, protected by a mutex.
pub type HashStore = Arc<Mutex<HashMap<PathBuf, String>>>;

/// Start FIM watching on the given paths.
/// Returns a channel receiver that emits FimEvent values,
/// plus the watcher handle (must be kept alive).
///
/// breadcrumb_paths: paths that trigger critical alerts (canary files).
pub fn start_fim(
    watch_paths: &[&str],
    breadcrumb_paths: &[&str],
) -> Result<(mpsc::Receiver<FimEvent>, RecommendedWatcher), notify::Error> {
    let (tx, rx) = mpsc::channel::<FimEvent>();
    let hash_store: HashStore = Arc::new(Mutex::new(HashMap::new()));

    // Pre-hash existing files
    for path_str in watch_paths {
        let path = Path::new(path_str);
        if path.is_file() {
            let hash = sha256_of_file(path);
            if !hash.is_empty() {
                hash_store
                    .lock()
                    .unwrap()
                    .insert(path.to_path_buf(), hash);
            }
        } else if path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    if entry.path().is_file() {
                        let hash = sha256_of_file(&entry.path());
                        if !hash.is_empty() {
                            hash_store
                                .lock()
                                .unwrap()
                                .insert(entry.path(), hash);
                        }
                    }
                }
            }
        }
    }

    let breadcrumb_set: std::collections::HashSet<PathBuf> = breadcrumb_paths
        .iter()
        .map(|p| PathBuf::from(p))
        .collect();

    let tx_clone = tx.clone();
    let hash_store_clone = hash_store.clone();

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let event_type = event_kind_to_string(&event.kind);
                if event_type == "other" {
                    return;
                }

                for path in &event.paths {
                    let is_breadcrumb = breadcrumb_set.contains(path);

                    let severity = if is_breadcrumb {
                        "critical".to_string()
                    } else {
                        classify_severity(&path.to_string_lossy())
                    };

                    let hash_before = hash_store_clone
                        .lock()
                        .unwrap()
                        .get(path)
                        .cloned()
                        .unwrap_or_default();

                    let hash_after = if event_type != "deleted" && path.is_file() {
                        let h = sha256_of_file(path);
                        if !h.is_empty() {
                            hash_store_clone
                                .lock()
                                .unwrap()
                                .insert(path.clone(), h.clone());
                        }
                        h
                    } else {
                        hash_store_clone.lock().unwrap().remove(path);
                        String::new()
                    };

                    let fim_event = FimEvent {
                        path: path.to_string_lossy().to_string(),
                        event_type: event_type.clone(),
                        severity,
                        timestamp: Utc::now().to_rfc3339(),
                        hash_before,
                        hash_after,
                        is_breadcrumb,
                    };

                    let _ = tx_clone.send(fim_event);
                }
            }
        },
        Config::default(),
    )?;

    // Schedule watches
    for path_str in watch_paths {
        let path = Path::new(path_str);
        if path.exists() {
            let mode = if path.is_dir() {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            };
            watcher.watch(path, mode)?;
        }
    }

    for path_str in breadcrumb_paths {
        let path = Path::new(path_str);
        if let Some(parent) = path.parent() {
            if parent.exists() {
                watcher.watch(parent, RecursiveMode::NonRecursive)?;
            }
        }
    }

    Ok((rx, watcher))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_classify_severity() {
        assert_eq!(classify_severity("/etc/shadow"), "high");
        assert_eq!(classify_severity("/home/user/.ssh/authorized_keys"), "high");
        assert_eq!(classify_severity("/tmp/somefile.txt"), "low");
    }

    #[test]
    fn test_sha256_of_file() {
        let dir = std::env::temp_dir().join("aegis_fim_test");
        let _ = fs::create_dir_all(&dir);
        let file_path = dir.join("test.txt");
        {
            let mut f = fs::File::create(&file_path).unwrap();
            f.write_all(b"hello world").unwrap();
        }
        let hash = sha256_of_file(&file_path);
        // SHA-256 of "hello world"
        assert!(!hash.is_empty(), "hash should not be empty");
        let _ = fs::remove_file(&file_path);
        let _ = fs::remove_dir(&dir);
    }
}
