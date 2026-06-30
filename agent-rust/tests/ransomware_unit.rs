//! Unit tests for the ransomware defense module — Phase R-E
//!
//! All tests run without admin/root and without touching real files outside
//! `tempfile::tempdir()`. Tests that require real process trees or platform
//! signals are marked `#[ignore]` and covered by the R-F integration harness.

use aegis_agent::ransomware::{
    canary::CanaryEvent,
    entropy::{shannon_entropy, EntropyClassifier, WriteSample},
    killer::ProcessChainSnapshot,
    rollback::RestoreOutcome,
    selfprotect::{enable_self_protection, ProtectionLevel},
};

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

// ── Entropy ────────────────────────────────────────────────────────────────

mod entropy_tests {
    use super::*;

    fn make_sample(ts: Instant, entropy: f64) -> WriteSample {
        WriteSample {
            timestamp: ts,
            entropy_bits: entropy,
        }
    }

    #[test]
    fn uniform_random_bytes_entropy_near_8() {
        // 256 distinct bytes → Shannon entropy ≈ 8.0 bits/byte.
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "expected ~8.0, got {}", e);
    }

    #[test]
    fn ascii_text_entropy_below_threshold() {
        // English ASCII text has entropy well below 7.5.
        let text = b"The quick brown fox jumps over the lazy dog. \
                     Pack my box with five dozen liquor jugs.";
        let e = shannon_entropy(text);
        assert!(e < 7.0, "text entropy should be low, got {}", e);
    }

    #[test]
    fn zero_bytes_entropy_is_zero() {
        let e = shannon_entropy(&[0u8; 512]);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn empty_slice_entropy_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn classifier_ransom_like_high_rate_and_entropy() {
        let mut cls = EntropyClassifier::new(50, 7.5);
        let now = Instant::now();
        // Inject 600 samples in the current window: rate = 60/s, entropy = 7.9
        for _ in 0..600 {
            cls.inject_sample(1, make_sample(now, 7.9));
        }
        assert!(cls.is_ransom_like(1, now), "should detect ransomware-like activity");
    }

    #[test]
    fn classifier_not_ransom_like_low_rate() {
        let mut cls = EntropyClassifier::new(50, 7.5);
        let now = Instant::now();
        // Only 10 samples in the window → rate = 1/s
        for _ in 0..10 {
            cls.inject_sample(2, make_sample(now, 7.9));
        }
        assert!(!cls.is_ransom_like(2, now), "low rate should not trigger");
    }

    #[test]
    fn classifier_not_ransom_like_low_entropy() {
        let mut cls = EntropyClassifier::new(50, 7.5);
        let now = Instant::now();
        // High rate but low entropy (plain text)
        for _ in 0..600 {
            cls.inject_sample(3, make_sample(now, 3.5));
        }
        assert!(!cls.is_ransom_like(3, now), "low entropy should not trigger");
    }

    #[test]
    fn classifier_ignores_stale_samples() {
        let mut cls = EntropyClassifier::new(50, 7.5);
        let now = Instant::now();
        // Samples older than the 10-second window
        let old = now - Duration::from_secs(20);
        for _ in 0..600 {
            cls.inject_sample(4, make_sample(old, 7.9));
        }
        assert!(!cls.is_ransom_like(4, now), "stale samples should be ignored");
    }

    #[test]
    fn classifier_unknown_pid_returns_false() {
        let cls = EntropyClassifier::new(50, 7.5);
        assert!(!cls.is_ransom_like(9999, Instant::now()));
    }

    #[test]
    fn classifier_respects_boundary_thresholds() {
        // Exactly at threshold values — should trigger.
        let mut cls = EntropyClassifier::new(50, 7.5);
        let now = Instant::now();
        // 500 samples in 10s window → exactly 50/s rate
        for _ in 0..500 {
            cls.inject_sample(5, make_sample(now, 7.5));
        }
        assert!(cls.is_ransom_like(5, now), "boundary values should trigger");
    }

    #[test]
    fn classifier_file_observe_with_real_tempfile() {
        use tempfile::NamedTempFile;
        use std::io::Write;

        // Write high-entropy bytes (pseudo-random via repeating pattern).
        let mut f = NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        f.write_all(&data).unwrap();
        f.flush().unwrap();

        let mut cls = EntropyClassifier::new(50, 7.5);
        // Call observe() which reads the file — should not panic.
        cls.observe(10, f.path(), 4096);
        // After one observe the rate is too low to trigger, but verify no crash.
        assert!(!cls.is_ransom_like(10, Instant::now()));
    }
}

// ── CanaryEvent ────────────────────────────────────────────────────────────

mod canary_tests {
    use super::*;

    #[test]
    fn canary_event_serde_round_trip() {
        let ev = CanaryEvent {
            path: PathBuf::from("/tmp/canary.dat"),
            pid_if_known: Some(1234),
            timestamp: 1_700_000_000,
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        let back: CanaryEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.path, ev.path);
        assert_eq!(back.pid_if_known, ev.pid_if_known);
        assert_eq!(back.timestamp, ev.timestamp);
    }

    #[test]
    fn canary_event_no_pid_serde() {
        let ev = CanaryEvent {
            path: PathBuf::from("/sentinel/canary_001.bin"),
            pid_if_known: None,
            timestamp: 1_600_000_000,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: CanaryEvent = serde_json::from_str(&json).unwrap();
        assert!(back.pid_if_known.is_none());
        assert_eq!(back.timestamp, 1_600_000_000);
    }

    #[test]
    fn canary_watcher_starts_cleanly() {
        use aegis_agent::ransomware::canary::CanaryWatcher;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let canary_path = dir.path().join("canary.dat");
        std::fs::write(&canary_path, b"AEGIS_CANARY_V1").unwrap();

        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let result = CanaryWatcher::new(vec![canary_path], tx);
        // Watcher should start without error.
        assert!(result.is_ok(), "CanaryWatcher::new should succeed: {:?}", result.err());
    }
}

// ── Killer / ProcessChainSnapshot ─────────────────────────────────────────

mod killer_tests {
    use super::*;

    fn make_snapshot() -> ProcessChainSnapshot {
        let mut cmd_map = HashMap::new();
        cmd_map.insert(42u32, vec!["ransomware.exe".to_string(), "--enc".to_string()]);
        cmd_map.insert(1u32, vec!["explorer.exe".to_string()]);

        ProcessChainSnapshot {
            tree: vec![
                aegis_agent::ransomware::killer::ProcessEntry {
                    pid: 42,
                    parent_pid: Some(1),
                    name: "ransomware.exe".to_string(),
                    cmdline: vec!["ransomware.exe".to_string(), "--enc".to_string()],
                },
                aegis_agent::ransomware::killer::ProcessEntry {
                    pid: 1,
                    parent_pid: None,
                    name: "explorer.exe".to_string(),
                    cmdline: vec!["explorer.exe".to_string()],
                },
            ],
            command_lines: cmd_map,
            open_files: vec!["/home/user/docs/report.docx".to_string()],
            network_connections: vec!["198.51.100.1:80".to_string()],
            captured_at: 1_700_000_001,
        }
    }

    #[test]
    fn process_chain_snapshot_serde_round_trip() {
        let snap = make_snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        let back: ProcessChainSnapshot = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.tree.len(), 2);
        assert_eq!(back.tree[0].pid, 42);
        assert_eq!(back.tree[0].parent_pid, Some(1));
        assert_eq!(back.tree[1].pid, 1);
        assert!(back.tree[1].parent_pid.is_none());
        assert_eq!(back.command_lines[&42u32], vec!["ransomware.exe", "--enc"]);
        assert_eq!(back.command_lines[&1u32], vec!["explorer.exe"]);
        assert_eq!(back.open_files, vec!["/home/user/docs/report.docx"]);
        assert_eq!(back.network_connections, vec!["198.51.100.1:80"]);
        assert_eq!(back.captured_at, 1_700_000_001);
    }

    #[test]
    fn empty_snapshot_serde() {
        let snap = ProcessChainSnapshot {
            tree: vec![],
            command_lines: HashMap::new(),
            open_files: vec![],
            network_connections: vec![],
            captured_at: 0,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: ProcessChainSnapshot = serde_json::from_str(&json).unwrap();
        assert!(back.tree.is_empty());
        assert_eq!(back.captured_at, 0);
    }

    /// Integration test: kills a real process tree. Requires a running process
    /// and should only run in controlled CI with appropriate permissions.
    #[tokio::test]
    #[ignore]
    async fn kill_chain_real_process() {
        use aegis_agent::ransomware::killer::Killer;
        // Spawn a sleep process, then kill it.
        let mut child = tokio::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id().expect("get pid");

        let killer = Killer::new(true);
        let result = killer.kill_chain(pid).await;
        assert!(result.is_ok());

        // Ensure the child is reaped.
        let _ = child.wait().await;
    }
}

// ── Rollback ──────────────────────────────────────────────────────────────

mod rollback_tests {
    use super::*;
    use aegis_agent::ransomware::rollback::restore;
    use std::path::Path;

    #[tokio::test]
    async fn simulated_when_env_var_absent() {
        std::env::remove_var("AEGIS_REAL_RECOVERY");
        let outcome = restore(Path::new("/tmp/victim.docx")).await.unwrap();
        assert_eq!(outcome, RestoreOutcome::Simulated);
    }

    #[test]
    fn restore_outcome_all_variants_serde() {
        for variant in [
            RestoreOutcome::Executed,
            RestoreOutcome::Simulated,
            RestoreOutcome::Failed("tmutil: error code 1".to_string()),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: RestoreOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    /// Integration test: only runs when AEGIS_REAL_RECOVERY=1 AND the platform
    /// snapshot tool is available. Run manually to verify real rollback.
    #[tokio::test]
    #[ignore]
    async fn executed_when_env_var_set() {
        std::env::set_var("AEGIS_REAL_RECOVERY", "1");
        let outcome = restore(Path::new("/tmp/test_victim.txt")).await;
        // May fail (no snapshot configured in CI), but must not panic.
        drop(outcome);
        std::env::remove_var("AEGIS_REAL_RECOVERY");
    }
}

// ── Self-protection ────────────────────────────────────────────────────────

mod selfprotect_tests {
    use super::*;

    #[test]
    fn enable_self_protection_returns_ok_without_panic() {
        let result = enable_self_protection();
        assert!(result.is_ok(), "should return Ok on all platforms: {:?}", result.err());
    }

    #[test]
    fn protection_level_serde_all_variants() {
        for level in [ProtectionLevel::None, ProtectionLevel::Partial, ProtectionLevel::Full] {
            let json = serde_json::to_string(&level).unwrap();
            let back: ProtectionLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(back, level);
        }
    }

    #[test]
    fn protection_level_debug() {
        // Verify Debug impl doesn't panic.
        let _ = format!("{:?}", ProtectionLevel::Partial);
    }
}
