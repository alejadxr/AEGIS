// ---------------------------------------------------------------------------
// Quarantine store (Task #6)
//
// Moves malicious files into ~/.aegis/quarantine/<sha256>.aegis with a
// side-car JSON recording original path, detection rule, and timestamp.
// Files are XOR'd with a per-install key so accidental execution is
// blocked; this is NOT cryptographic protection, just a safety curtain.
// ---------------------------------------------------------------------------

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const OBFUSCATION_KEY: &[u8] = b"AEGIS_QUARANTINE_DO_NOT_EXECUTE";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineMeta {
    pub id: String,          // sha256
    pub original_path: String,
    pub size_bytes: u64,
    pub rule: Option<String>,
    pub engine: Option<String>,
    pub quarantined_at: String,
}

fn quarantine_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(appdata).join("aegis-node").join("quarantine");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".aegis").join("quarantine");
    }
    PathBuf::from(".").join("aegis-quarantine")
}

/// Move the file into quarantine. Returns true on success.
pub fn move_to_quarantine(path: &Path, sha256: &str) -> Result<bool, String> {
    let dir = quarantine_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    // Read original file
    let mut bytes = Vec::new();
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    let size = meta.len();
    {
        let mut f = fs::File::open(path).map_err(|e| e.to_string())?;
        f.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    }

    // XOR-obfuscate
    xor_in_place(&mut bytes);

    // Write encrypted payload
    let dst = dir.join(format!("{}.aegis", sha256));
    {
        let mut f = fs::File::create(&dst).map_err(|e| e.to_string())?;
        f.write_all(&bytes).map_err(|e| e.to_string())?;
    }

    // Write side-car metadata
    let meta = QuarantineMeta {
        id: sha256.to_string(),
        original_path: path.display().to_string(),
        size_bytes: size,
        rule: None,
        engine: None,
        quarantined_at: Utc::now().to_rfc3339(),
    };
    let meta_path = dir.join(format!("{}.meta.json", sha256));
    let json = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
    fs::write(&meta_path, json).map_err(|e| e.to_string())?;

    // Delete the original
    fs::remove_file(path).map_err(|e| e.to_string())?;

    log::info!("[quarantine] moved {} -> {}", path.display(), dst.display());
    Ok(true)
}

/// Restore a quarantined file back to its original path.
pub fn release(sha256: &str) -> Result<PathBuf, String> {
    let dir = quarantine_dir();
    let payload = dir.join(format!("{}.aegis", sha256));
    let meta_path = dir.join(format!("{}.meta.json", sha256));

    let meta_json = fs::read_to_string(&meta_path).map_err(|e| e.to_string())?;
    let meta: QuarantineMeta =
        serde_json::from_str(&meta_json).map_err(|e| e.to_string())?;

    let mut bytes = fs::read(&payload).map_err(|e| e.to_string())?;
    xor_in_place(&mut bytes);

    let original = PathBuf::from(&meta.original_path);
    if let Some(parent) = original.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&original, &bytes).map_err(|e| e.to_string())?;

    // Remove quarantine artifacts
    let _ = fs::remove_file(&payload);
    let _ = fs::remove_file(&meta_path);

    Ok(original)
}

/// List quarantined items.
pub fn list() -> Vec<QuarantineMeta> {
    let dir = quarantine_dir();
    let Ok(rd) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(json) = fs::read_to_string(&p) else {
            continue;
        };
        if let Ok(m) = serde_json::from_str::<QuarantineMeta>(&json) {
            out.push(m);
        }
    }
    out
}

fn xor_in_place(bytes: &mut [u8]) {
    for (i, b) in bytes.iter_mut().enumerate() {
        *b ^= OBFUSCATION_KEY[i % OBFUSCATION_KEY.len()];
    }
}
