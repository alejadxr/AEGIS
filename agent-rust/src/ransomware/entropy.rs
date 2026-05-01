//! Write-rate + Shannon-entropy classifier — Phase R-E
//!
//! Tracks per-PID write activity and classifies a process as ransomware-like
//! when two conditions are met simultaneously within a sliding 10-second window:
//!
//! 1. Write rate ≥ `write_rate_threshold` writes/second.
//! 2. Mean Shannon entropy of written data ≥ `entropy_threshold` bits/byte.
//!
//! High entropy indicates encrypted or compressed output — a hallmark of
//! ransomware that encrypts files in-place.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

/// A single write observation for one PID.
#[derive(Debug, Clone)]
pub struct WriteSample {
    pub timestamp: Instant,
    /// Shannon entropy of the bytes written (bits/byte, range [0, 8]).
    pub entropy_bits: f64,
}

/// Entropy classifier state for all observed PIDs.
pub struct EntropyClassifier {
    /// Per-PID sliding window of write samples.
    per_pid: HashMap<u32, VecDeque<WriteSample>>,
    /// Sliding window duration.
    window: Duration,
    /// Maximum samples kept per PID (cap to bound memory).
    max_samples: usize,
    /// Write rate threshold (writes/second).
    write_rate_threshold: u64,
    /// Entropy threshold (bits/byte).
    entropy_threshold: f64,
}

impl EntropyClassifier {
    /// Create a new classifier with the given thresholds.
    pub fn new(write_rate_threshold: u64, entropy_threshold: f64) -> Self {
        Self {
            per_pid: HashMap::new(),
            window: Duration::from_secs(10),
            max_samples: 1000,
            write_rate_threshold,
            entropy_threshold,
        }
    }

    /// Record a write event for `pid` to `path`, where `bytes_written` bytes
    /// were written. The method reads a sample of the file at `path` to compute
    /// Shannon entropy; if the file is inaccessible the sample is skipped.
    pub fn observe(&mut self, pid: u32, path: &Path, bytes_written: u64) {
        let entropy = if bytes_written == 0 {
            0.0
        } else {
            sample_entropy(path, bytes_written).unwrap_or(0.0)
        };

        let sample = WriteSample {
            timestamp: Instant::now(),
            entropy_bits: entropy,
        };

        let deque = self.per_pid.entry(pid).or_default();
        deque.push_back(sample);
        // Cap to max_samples.
        while deque.len() > self.max_samples {
            deque.pop_front();
        }
    }

    /// Returns `true` if `pid`'s recent activity matches ransomware-like
    /// behaviour: high write rate AND high mean entropy within the window
    /// ending at `now`.
    pub fn is_ransom_like(&self, pid: u32, now: Instant) -> bool {
        let Some(deque) = self.per_pid.get(&pid) else {
            return false;
        };

        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let window_samples: Vec<&WriteSample> = deque
            .iter()
            .filter(|s| s.timestamp >= cutoff)
            .collect();

        if window_samples.is_empty() {
            return false;
        }

        // Write rate: samples_in_window / window_seconds.
        let window_secs = self.window.as_secs_f64();
        let rate = window_samples.len() as f64 / window_secs;

        if rate < self.write_rate_threshold as f64 {
            return false;
        }

        // Mean Shannon entropy.
        let mean_entropy: f64 =
            window_samples.iter().map(|s| s.entropy_bits).sum::<f64>()
                / window_samples.len() as f64;

        mean_entropy >= self.entropy_threshold
    }

    /// Inject a pre-computed sample directly. Intended for unit tests and
    /// integration test harnesses — allows precise control of timing and
    /// entropy without filesystem I/O.
    pub fn inject_sample(&mut self, pid: u32, sample: WriteSample) {
        let deque = self.per_pid.entry(pid).or_default();
        deque.push_back(sample);
        while deque.len() > self.max_samples {
            deque.pop_front();
        }
    }
}

/// Read up to 4 KiB from `path` and compute Shannon entropy in bits/byte.
fn sample_entropy(path: &Path, _bytes_written: u64) -> Option<f64> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 4096];
    let n = file.read(&mut buf).ok()?;
    if n == 0 {
        return Some(0.0);
    }
    Some(shannon_entropy(&buf[..n]))
}

/// Compute Shannon entropy of a byte slice in bits/byte (range [0, 8]).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn make_sample(ts: Instant, entropy: f64) -> WriteSample {
        WriteSample {
            timestamp: ts,
            entropy_bits: entropy,
        }
    }

    #[test]
    fn shannon_entropy_all_zeros_is_zero() {
        let data = vec![0u8; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn shannon_entropy_uniform_bytes_near_eight() {
        // 256 distinct bytes each appearing once → entropy ≈ 8.0
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "expected ~8.0, got {}", e);
    }

    #[test]
    fn shannon_entropy_ascii_text_is_low() {
        // English ASCII text has entropy well below 7.5
        let text = b"The quick brown fox jumps over the lazy dog. \
                     Pack my box with five dozen liquor jugs.";
        let e = shannon_entropy(text);
        assert!(e < 7.0, "expected low entropy for text, got {}", e);
    }

    #[test]
    fn is_ransom_like_returns_false_for_low_rate() {
        let mut cls = EntropyClassifier::new(50, 7.5);
        let now = Instant::now();
        // Only 5 samples — rate << 50/s
        for _ in 0..5 {
            cls.inject_sample(42, make_sample(now, 7.8));
        }
        assert!(!cls.is_ransom_like(42, now));
    }

    #[test]
    fn is_ransom_like_returns_false_for_low_entropy() {
        let mut cls = EntropyClassifier::new(50, 7.5);
        let now = Instant::now();
        // High rate but low entropy (plain text writes)
        for _ in 0..600 {
            cls.inject_sample(42, make_sample(now, 4.5));
        }
        assert!(!cls.is_ransom_like(42, now));
    }

    #[test]
    fn is_ransom_like_returns_true_for_high_rate_and_entropy() {
        let mut cls = EntropyClassifier::new(50, 7.5);
        let now = Instant::now();
        // 600 samples in the 10-second window → rate = 60/s, entropy = 7.8
        for _ in 0..600 {
            cls.inject_sample(42, make_sample(now, 7.8));
        }
        assert!(cls.is_ransom_like(42, now));
    }

    #[test]
    fn is_ransom_like_ignores_old_samples() {
        let mut cls = EntropyClassifier::new(50, 7.5);
        let now = Instant::now();
        // 600 samples older than 10 seconds
        let old = now - Duration::from_secs(15);
        for _ in 0..600 {
            cls.inject_sample(42, make_sample(old, 7.8));
        }
        // Should not classify as ransom (samples outside window)
        assert!(!cls.is_ransom_like(42, now));
    }

    #[test]
    fn unknown_pid_returns_false() {
        let cls = EntropyClassifier::new(50, 7.5);
        assert!(!cls.is_ransom_like(9999, Instant::now()));
    }
}
