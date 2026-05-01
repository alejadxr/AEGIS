//! Ransomware emulation harness — Phase R-F
//!
//! Generates 100 dummy files in a temp directory, encrypts them with a
//! deterministic XOR + entropy-padding scheme to produce high-entropy output,
//! drops a fake ransom note, and writes a JSON manifest so the Python e2e
//! orchestrator can assert what happened.
//!
//! # Safety
//! - Only writes inside a temp subdirectory. Real FS is never touched.
//! - Encrypted files use suffix `.aegis_test_locked` to avoid confusion with
//!   real ransomware artefacts.
//! - The C2 IP used is 198.51.100.42 (RFC 5737 documentation range).
//!
//! # Gating
//! The test checks `AEGIS_LIVEFIRE=1` at runtime and exits early with a message
//! if not set, rather than relying on feature flags (which would require
//! editing Cargo.toml).

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const C2_IP: &str = "198.51.100.42";
const LOCKED_SUFFIX: &str = ".aegis_test_locked";
const RANSOM_NOTE_NAME: &str = "README_AEGIS_TEST.txt";
const FILE_COUNT: usize = 100;
const XOR_KEY: u8 = 0xDE;
// 64 bytes of entropy padding appended to every encrypted file header
const ENTROPY_HEADER: &[u8] = b"\x9f\x3a\x7b\x11\xc4\x55\x6d\x22\
                                 \xf8\x01\x4e\x90\xad\x73\x2c\x88\
                                 \x5e\xb9\x17\x6a\xd3\x0f\x41\xcc\
                                 \x29\x84\xe7\x3f\x12\x5b\x96\x4d\
                                 \xa1\x68\x2e\xb3\x07\xf0\x39\x55\
                                 \xdc\x8b\x14\x7e\xc2\x93\x4f\xa6\
                                 \x1d\x60\x28\xe4\x79\x0c\xb7\x35\
                                 \x52\x9a\x3d\x86\xf1\x48\x23\xcd";

// ---------------------------------------------------------------------------
// Result struct
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct EmulationResult {
    pub temp_dir_path: PathBuf,
    pub files_encrypted_count: usize,
    pub ransom_note_path: PathBuf,
    pub c2_ip_used: &'static str,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn log_phase(phase: &str) {
    eprintln!("[aegis-emul {:>13}ms] {}", now_ms() % 100_000, phase);
}

/// Build a temp directory path that is unique per run without pulling tempfile.
fn make_temp_dir() -> PathBuf {
    let base = env::temp_dir();
    // Use SystemTime nanos as a unique id — no external deps required.
    let uid = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    base.join(format!("aegis_emul_{}", uid))
}

/// XOR-encrypt `data` with `XOR_KEY` and prepend the entropy header.
fn xor_encrypt(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENTROPY_HEADER.len() + data.len());
    out.extend_from_slice(ENTROPY_HEADER);
    for &b in data {
        out.push(b ^ XOR_KEY);
    }
    out
}

/// Generate realistic-looking content for file index `i`.
/// Even indices = text, odd indices = pseudo-binary.
fn generate_content(i: usize) -> Vec<u8> {
    if i % 2 == 0 {
        // Text content: looks like a document
        format!(
            "AEGIS TEST FILE #{i}\n\
             Classification: CONFIDENTIAL\n\
             Created: 2026-04-30\n\
             Contents: Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n\
             Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
             Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n\
             Key: ACCT-{:06X}-DATA\n\
             END OF FILE\n",
            i * 0xDEAD
        )
        .into_bytes()
    } else {
        // Pseudo-binary: repeating structured bytes that look like a file header
        let mut buf = Vec::with_capacity(256);
        // Fake magic bytes
        buf.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        for j in 0..248usize {
            buf.push(((i * 13 + j * 7) & 0xFF) as u8);
        }
        buf
    }
}

fn write_ransom_note(dir: &Path) -> PathBuf {
    let note_path = dir.join(RANSOM_NOTE_NAME);
    let content = format!(
        "--- AEGIS TEST RANSOM NOTE ---\n\
         THIS IS A SYNTHETIC EMULATION — NOT REAL RANSOMWARE\n\
         \n\
         Your files have been encrypted by the AEGIS livefire emulator.\n\
         C2 server: {C2_IP}\n\
         To recover: set AEGIS_LIVEFIRE=1 and run the recovery workflow.\n\
         \n\
         Techniques emulated:\n\
           T1486 - Data Encrypted for Impact\n\
           T1490 - Inhibit System Recovery\n\
           T1021.002 - SMB lateral movement (simulated)\n\
         \n\
         This note was auto-generated at {}ms since epoch.\n\
         --- END OF TEST NOTE ---\n",
        now_ms()
    );
    fs::write(&note_path, content).expect("failed to write ransom note");
    note_path
}

fn write_manifest(result: &EmulationResult) {
    let manifest_path = result.temp_dir_path.join("manifest.json");
    let json = format!(
        "{{\
          \"temp_dir\": \"{}\",\
          \"files_encrypted\": {},\
          \"ransom_note_path\": \"{}\",\
          \"c2_ip\": \"{}\",\
          \"started_at_ms\": {},\
          \"finished_at_ms\": {}\
        }}",
        result.temp_dir_path.display(),
        result.files_encrypted_count,
        result.ransom_note_path.display(),
        result.c2_ip_used,
        result.started_at_ms,
        result.finished_at_ms,
    );
    fs::write(&manifest_path, json).expect("failed to write manifest.json");
    eprintln!(
        "[aegis-emul] Manifest written: {}",
        manifest_path.display()
    );
}

// ---------------------------------------------------------------------------
// Core emulation function
// ---------------------------------------------------------------------------

/// Run the full ransomware emulation sequence and return a result struct.
///
/// Phase order (logged with timestamps):
///   1. Create temp directory
///   2. Generate 100 dummy files (mixed text + binary)
///   3. Encrypt all files in-place (XOR + entropy header, rename to .aegis_test_locked)
///   4. Drop ransom note
///   5. Write JSON manifest
pub fn run_emulation() -> EmulationResult {
    let started_at_ms = now_ms();

    // Phase 1 — staging
    log_phase("PHASE 1: creating temp directory");
    let temp_dir = make_temp_dir();
    fs::create_dir_all(&temp_dir).expect("failed to create temp dir");
    eprintln!("[aegis-emul] Temp dir: {}", temp_dir.display());

    // Phase 2 — generate dummy files
    log_phase("PHASE 2: generating 100 dummy files");
    let mut plaintext_paths = Vec::with_capacity(FILE_COUNT);
    for i in 0..FILE_COUNT {
        let filename = if i % 2 == 0 {
            format!("document_{:03}.docx", i)
        } else {
            format!("image_{:03}.png", i)
        };
        let path = temp_dir.join(&filename);
        let content = generate_content(i);
        fs::write(&path, content).expect("failed to write dummy file");
        plaintext_paths.push(path);
    }
    log_phase(&format!("PHASE 2: {} files created", FILE_COUNT));

    // Phase 3 — encrypt files
    log_phase("PHASE 3: encrypting files (XOR + entropy-padding)");
    let mut encrypted_count = 0usize;
    for src_path in &plaintext_paths {
        let plaintext = fs::read(src_path).expect("failed to read dummy file");
        let encrypted = xor_encrypt(&plaintext);

        // Rename: document_000.docx -> document_000.docx.aegis_test_locked
        let locked_name = format!(
            "{}{}",
            src_path.file_name().unwrap().to_string_lossy(),
            LOCKED_SUFFIX
        );
        let dst_path = temp_dir.join(&locked_name);
        fs::write(&dst_path, encrypted).expect("failed to write encrypted file");
        // Remove plaintext — mirrors real ransomware behaviour
        fs::remove_file(src_path).expect("failed to remove plaintext");
        encrypted_count += 1;
    }
    log_phase(&format!("PHASE 3: {} files encrypted", encrypted_count));

    // Phase 4 — ransom note
    log_phase("PHASE 4: dropping ransom note");
    let ransom_note_path = write_ransom_note(&temp_dir);
    log_phase(&format!(
        "PHASE 4: note at {}",
        ransom_note_path.display()
    ));

    let finished_at_ms = now_ms();
    log_phase(&format!(
        "COMPLETE: elapsed {}ms",
        finished_at_ms - started_at_ms
    ));

    let result = EmulationResult {
        temp_dir_path: temp_dir,
        files_encrypted_count: encrypted_count,
        ransom_note_path,
        c2_ip_used: C2_IP,
        started_at_ms,
        finished_at_ms,
    };

    // Phase 5 — manifest for Python orchestrator
    write_manifest(&result);

    result
}

// ---------------------------------------------------------------------------
// Test entry point
// ---------------------------------------------------------------------------

#[test]
fn test_ransomware_emulation_livefire() {
    // Gate: only run when AEGIS_LIVEFIRE=1 is explicitly set.
    let livefire = env::var("AEGIS_LIVEFIRE").unwrap_or_default();
    if livefire != "1" {
        eprintln!(
            "[aegis-emul] SKIPPED — set AEGIS_LIVEFIRE=1 to run livefire emulation.\n\
             This test generates 100 dummy files, encrypts them, and drops a ransom note\n\
             in a temp directory. It is designed for integration testing only."
        );
        return; // Not a failure — just skip.
    }

    eprintln!("[aegis-emul] === LIVEFIRE EMULATION START ===");
    let result = run_emulation();

    // Basic structural assertions
    assert_eq!(result.files_encrypted_count, FILE_COUNT);
    assert!(result.ransom_note_path.exists(), "ransom note must exist");
    assert_eq!(result.c2_ip_used, C2_IP);
    assert!(result.finished_at_ms >= result.started_at_ms);

    // All files in temp dir should have the locked suffix (plus the note and manifest)
    let locked_files: Vec<_> = fs::read_dir(&result.temp_dir_path)
        .expect("cannot read temp dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let n = name.to_string_lossy();
            n.ends_with(LOCKED_SUFFIX)
        })
        .collect();

    assert_eq!(
        locked_files.len(),
        FILE_COUNT,
        "expected {} locked files, found {}",
        FILE_COUNT,
        locked_files.len()
    );

    // Verify ransom note mentions the C2 IP
    let note_content = fs::read_to_string(&result.ransom_note_path).expect("cannot read note");
    assert!(
        note_content.contains(C2_IP),
        "ransom note must contain C2 IP {C2_IP}"
    );

    // Verify manifest.json exists and is non-empty
    let manifest_path = result.temp_dir_path.join("manifest.json");
    assert!(manifest_path.exists(), "manifest.json must exist");
    let manifest_str = fs::read_to_string(&manifest_path).expect("cannot read manifest");
    assert!(manifest_str.contains("files_encrypted"), "manifest must have files_encrypted");
    assert!(manifest_str.contains(C2_IP), "manifest must contain C2 IP");

    // Cleanup — remove temp dir so livefire tests are idempotent
    fs::remove_dir_all(&result.temp_dir_path).expect("cleanup failed");
    eprintln!("[aegis-emul] === LIVEFIRE EMULATION COMPLETE — temp dir cleaned up ===");
}

/// Quick smoke test (no AEGIS_LIVEFIRE required): verify XOR is deterministic
/// and entropy header is prepended correctly.
#[test]
fn test_xor_encrypt_deterministic() {
    let data = b"hello world";
    let enc1 = xor_encrypt(data);
    let enc2 = xor_encrypt(data);
    assert_eq!(enc1, enc2, "encryption must be deterministic");
    assert_eq!(&enc1[..ENTROPY_HEADER.len()], ENTROPY_HEADER);
    // Verify XOR is reversible
    let payload = &enc1[ENTROPY_HEADER.len()..];
    let decoded: Vec<u8> = payload.iter().map(|&b| b ^ XOR_KEY).collect();
    assert_eq!(&decoded, data);
}

/// Verify generate_content alternates between text and binary.
#[test]
fn test_generate_content_alternates() {
    let text = generate_content(0);
    assert!(text.starts_with(b"AEGIS TEST FILE #0"));
    let binary = generate_content(1);
    assert!(binary.starts_with(b"\x89PNG"));
}

/// Verify the temp dir name is deterministic in structure (prefixed correctly).
#[test]
fn test_temp_dir_name_format() {
    let p = make_temp_dir();
    let name = p.file_name().unwrap().to_string_lossy();
    assert!(name.starts_with("aegis_emul_"), "temp dir must start with aegis_emul_");
}
