// ---------------------------------------------------------------------------
// Shannon entropy calculator (Task #2)
//
// Used to detect encryption on a file write. Encrypted / compressed data has
// entropy ~7.9-8.0 bits per byte; plaintext documents are typically <5 bits.
// A file that transitions from low to high entropy is a strong ransomware
// signal.
// ---------------------------------------------------------------------------

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Threshold above which a sample is considered "ciphertext-like".
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.5;

/// Maximum bytes to read when sampling a file for entropy.
const SAMPLE_SIZE: usize = 16 * 1024;

/// Compute Shannon entropy (bits per byte) over a byte slice. Returns a value
/// in the range [0.0, 8.0].
pub fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

/// Sample up to 16KiB from the head + middle of a file and return its
/// Shannon entropy. Returns `None` if the file can't be opened.
pub fn file_entropy<P: AsRef<Path>>(path: P) -> Option<f64> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();

    let mut buf = vec![0u8; SAMPLE_SIZE.min(len as usize)];
    if buf.is_empty() {
        return Some(0.0);
    }

    // Read from the middle of the file when possible — ransomware often
    // leaves a small plaintext header, so the middle is more telling.
    let mid = if len > (SAMPLE_SIZE as u64) * 2 {
        (len / 2).saturating_sub((SAMPLE_SIZE / 2) as u64)
    } else {
        0
    };
    if f.seek(SeekFrom::Start(mid)).is_err() {
        return None;
    }
    let n = f.read(&mut buf).ok()?;
    Some(shannon(&buf[..n]))
}

/// Convenience: does the file look encrypted / high-entropy?
pub fn is_high_entropy<P: AsRef<Path>>(path: P) -> bool {
    file_entropy(path)
        .map(|e| e >= HIGH_ENTROPY_THRESHOLD)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_bytes_have_max_entropy() {
        let bytes: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let h = shannon(&bytes);
        assert!(h > 7.9, "expected ~8.0, got {}", h);
    }

    #[test]
    fn constant_bytes_have_zero_entropy() {
        let bytes = vec![b'A'; 4096];
        let h = shannon(&bytes);
        assert!(h.abs() < 0.001, "expected 0, got {}", h);
    }
}
