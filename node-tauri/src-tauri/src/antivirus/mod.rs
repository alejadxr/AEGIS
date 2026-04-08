// ---------------------------------------------------------------------------
// Antivirus Engine (Task #6)
//
// Signature-based malware scanner sitting alongside the behavioral EDR. Two
// modes:
//
//   - On-access scan: notify::Watcher fires on file write -> SHA256 ->
//                     hash_cache lookup -> if unknown, YARA scan ->
//                     if match, quarantine() + POST alert
//
//   - Scheduled scan: daily full crawl of user-configured paths
//
// Detection sources are layered:
//   1. Known-good allowlist (sled)
//   2. Known-bad hash reputation (MalwareBazaar SHA256 list, from backend)
//   3. YARA-Forge community ruleset
//   4. libclamav (optional, feature-gated)
//
// Files that match get moved to ~/.aegis/quarantine/<sha256>.aegis with
// the original path recorded in a side-car .meta.json.
// ---------------------------------------------------------------------------

pub mod hash_cache;
pub mod quarantine;
pub mod yara_engine;

#[cfg(feature = "clamav")]
pub mod clamav_bridge;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use hash_cache::HashCache;
use yara_engine::YaraEngine;

/// Result of scanning a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: String,
    pub sha256: String,
    pub verdict: Verdict,
    pub rule: Option<String>,
    pub engine: String,
    pub scanned_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    Error,
}

#[derive(Debug)]
pub struct AntivirusState {
    pub enabled: bool,
    pub server_url: String,
    pub agent_id: Option<String>,
    pub files_scanned: u64,
    pub files_quarantined: u64,
    pub signature_version: String,
    pub hash_cache: HashCache,
    pub yara: YaraEngine,
    pub watch_paths: Vec<PathBuf>,
}

impl AntivirusState {
    pub fn new(server_url: String, agent_id: Option<String>) -> Result<Self, String> {
        let hash_cache = HashCache::open()?;
        let yara = YaraEngine::new()?;
        Ok(Self {
            enabled: true,
            server_url,
            agent_id,
            files_scanned: 0,
            files_quarantined: 0,
            signature_version: "unknown".into(),
            hash_cache,
            yara,
            watch_paths: default_watch_paths(),
        })
    }
}

fn default_watch_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    #[cfg(target_os = "windows")]
    {
        if let Ok(up) = std::env::var("USERPROFILE") {
            let base = PathBuf::from(up);
            paths.push(base.join("Downloads"));
            paths.push(base.join("Documents"));
            paths.push(base.join("Desktop"));
            paths.push(base.join("AppData").join("Local").join("Temp"));
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let base = PathBuf::from(home);
            paths.push(base.join("Downloads"));
            paths.push(base.join("Documents"));
            paths.push(base.join("Desktop"));
            paths.push(PathBuf::from("/tmp"));
        }
    }
    paths
}

/// Start the antivirus engine: on-access watcher + daily scheduled scan +
/// daily signature update pull.
pub async fn start(state: Arc<Mutex<AntivirusState>>) {
    log::info!("[av] starting antivirus engine");

    // On-access scanner
    let state_acc = state.clone();
    tokio::spawn(async move {
        if let Err(e) = on_access_scanner(state_acc).await {
            log::error!("[av] on-access scanner exited: {}", e);
        }
    });

    // Daily scheduled full scan
    let state_sched = state.clone();
    tokio::spawn(async move {
        scheduled_scanner(state_sched).await;
    });

    // Daily signature update pull
    let state_upd = state.clone();
    tokio::spawn(async move {
        signature_updater(state_upd).await;
    });
}

// ---------------------------------------------------------------------------
// On-access scanner
// ---------------------------------------------------------------------------

async fn on_access_scanner(state: Arc<Mutex<AntivirusState>>) -> Result<(), String> {
    use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc::channel;

    let (tx, rx) = channel::<notify::Result<notify::Event>>();

    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| e.to_string())?;

    let paths: Vec<PathBuf> = { state.lock().await.watch_paths.clone() };
    for p in &paths {
        if p.exists() {
            if let Err(e) = watcher.watch(p, RecursiveMode::Recursive) {
                log::warn!("[av] couldn't watch {:?}: {}", p, e);
            }
        }
    }

    loop {
        let event = match rx.recv() {
            Ok(Ok(e)) => e,
            Ok(Err(e)) => {
                log::debug!("[av] watcher error: {}", e);
                continue;
            }
            Err(_) => break,
        };

        // Only scan on create / modify
        if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            continue;
        }

        for path in event.paths {
            if !path.is_file() {
                continue;
            }
            // Skip huge files on the hot path
            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > 64 * 1024 * 1024 {
                continue;
            }

            let state_clone = state.clone();
            let path_clone = path.clone();
            tokio::spawn(async move {
                let _ = scan_and_handle(state_clone, &path_clone).await;
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scheduled scanner
// ---------------------------------------------------------------------------

async fn scheduled_scanner(state: Arc<Mutex<AntivirusState>>) {
    // Delay first run so the agent can finish booting
    tokio::time::sleep(Duration::from_secs(300)).await;

    loop {
        log::info!("[av] starting scheduled full scan");
        let paths: Vec<PathBuf> = { state.lock().await.watch_paths.clone() };

        let mut scanned: u64 = 0;
        for root in &paths {
            scanned += walk_and_scan(state.clone(), root).await;
        }

        log::info!("[av] scheduled scan complete: {} files", scanned);

        // Repeat every 24h
        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
    }
}

/// Recursive directory walker that yields to the tokio runtime. Returns the
/// count of files scanned.
async fn walk_and_scan(state: Arc<Mutex<AntivirusState>>, root: &Path) -> u64 {
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut count: u64 = 0;
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if let Ok(ft) = entry.file_type() {
                if ft.is_dir() {
                    stack.push(path);
                    continue;
                }
                if ft.is_file() {
                    let meta = match entry.metadata() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if meta.len() > 64 * 1024 * 1024 {
                        continue;
                    }
                    let _ = scan_and_handle(state.clone(), &path).await;
                    count += 1;
                    // Yield periodically so we don't starve other tasks
                    if count % 32 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            }
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Core scan pipeline
// ---------------------------------------------------------------------------

async fn scan_and_handle(
    state: Arc<Mutex<AntivirusState>>,
    path: &Path,
) -> Result<(), String> {
    // 1. Hash the file
    let sha = hash_file(path).map_err(|e| e.to_string())?;

    // 2. Check hash cache
    let cached = { state.lock().await.hash_cache.lookup(&sha) };
    match cached {
        Some(hash_cache::Status::Known) => {
            return Ok(()); // known-good
        }
        Some(hash_cache::Status::Bad(rule)) => {
            return on_detection(state, path, &sha, Some(rule), "hash_cache").await;
        }
        None => {}
    }

    // 3. YARA scan
    let verdict = {
        let s = state.lock().await;
        s.yara.scan_file(path)
    };

    match verdict {
        Ok(Some(rule)) => {
            {
                let mut s = state.lock().await;
                s.hash_cache.mark_bad(&sha, &rule);
                s.files_scanned += 1;
            }
            on_detection(state, path, &sha, Some(rule), "yara").await
        }
        Ok(None) => {
            // 4. ClamAV (feature-gated)
            #[cfg(feature = "clamav")]
            {
                if let Ok(Some(rule)) = clamav_bridge::scan_file(path) {
                    {
                        let mut s = state.lock().await;
                        s.hash_cache.mark_bad(&sha, &rule);
                        s.files_scanned += 1;
                    }
                    return on_detection(state, path, &sha, Some(rule), "clamav").await;
                }
            }

            // Nothing fired — mark as known-good so we skip next time
            let mut s = state.lock().await;
            s.hash_cache.mark_good(&sha);
            s.files_scanned += 1;
            Ok(())
        }
        Err(e) => {
            log::debug!("[av] yara scan error on {}: {}", path.display(), e);
            Ok(())
        }
    }
}

async fn on_detection(
    state: Arc<Mutex<AntivirusState>>,
    path: &Path,
    sha: &str,
    rule: Option<String>,
    engine: &str,
) -> Result<(), String> {
    log::warn!(
        "[av] MALWARE: {} rule={:?} engine={} sha={}",
        path.display(),
        rule,
        engine,
        sha
    );

    // 1. Quarantine the file
    let quarantined = quarantine::move_to_quarantine(path, sha).unwrap_or(false);

    let (server_url, agent_id) = {
        let mut s = state.lock().await;
        if quarantined {
            s.files_quarantined += 1;
        }
        (s.server_url.clone(), s.agent_id.clone())
    };

    // 2. POST alert to backend
    if let Some(aid) = agent_id {
        let body = serde_json::json!({
            "agent_id": aid,
            "path": path.display().to_string(),
            "sha256": sha,
            "rule": rule,
            "engine": engine,
            "quarantined": quarantined,
            "detected_at": Utc::now().to_rfc3339(),
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        let _ = client
            .post(format!("{}/antivirus/detections", server_url))
            .json(&body)
            .send()
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SHA256 helper
// ---------------------------------------------------------------------------

pub fn hash_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Signature updater — pulls YARA + hash lists from backend once a day
// ---------------------------------------------------------------------------

async fn signature_updater(state: Arc<Mutex<AntivirusState>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await; // initial delay
        let (server_url, _) = {
            let s = state.lock().await;
            (s.server_url.clone(), s.agent_id.clone())
        };

        match pull_signatures(&server_url).await {
            Ok(bundle) => {
                let mut s = state.lock().await;
                if let Err(e) = s.yara.load_rules(&bundle.yara_rules) {
                    log::warn!("[av] yara rule load failed: {}", e);
                }
                for bad in &bundle.bad_hashes {
                    s.hash_cache.mark_bad(bad, "malwarebazaar");
                }
                s.signature_version = bundle.version;
                log::info!(
                    "[av] signatures updated to {} ({} bad hashes)",
                    s.signature_version,
                    bundle.bad_hashes.len()
                );
            }
            Err(e) => log::debug!("[av] signature pull failed: {}", e),
        }

        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
    }
}

#[derive(Debug, Deserialize)]
struct SignatureBundle {
    version: String,
    yara_rules: String,
    bad_hashes: Vec<String>,
}

async fn pull_signatures(server_url: &str) -> Result<SignatureBundle, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(format!("{}/antivirus/signatures", server_url))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("signatures endpoint returned {}", resp.status()));
    }
    resp.json::<SignatureBundle>()
        .await
        .map_err(|e| e.to_string())
}
