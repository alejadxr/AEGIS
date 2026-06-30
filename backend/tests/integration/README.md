# Integration Test Runbook — Ransomware Defense (Phase R-F)

End-to-end livefire harness that emulates a ransomware attack and validates
the full AEGIS detection-response-recovery stack.

---

## Quick Start

```bash
# 1. Start the backend
cd backend && source venv/bin/activate
uvicorn app.main:app --reload --port 8000

# 2. (Optional) Build the Rust agent emulator
cd agent-rust && cargo build --release
# The Python e2e suite falls back to a Python stub if cargo is unavailable.

# 3. Export credentials
export AEGIS_API_KEY=your_api_key_here        # required
export AEGIS_API_URL=http://127.0.0.1:8000    # default, override if needed

# 4. Run the livefire suite
AEGIS_LIVEFIRE=1 pytest backend/tests/integration/ -v
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| AEGIS backend running | `uvicorn app.main:app --port 8000` |
| `AEGIS_API_KEY` set | Any valid API key seeded in the database |
| `AEGIS_LIVEFIRE=1` set | Hard gate — no tests run without it |
| `httpx` installed | `pip install httpx` (already in dev requirements) |
| Rust agent (optional) | Only needed for the 500ms kill-SLA test |

### Optional: Rust emulator binary

The 500ms agent-kill SLA test (``test_agent_terminates_emulator_within_sla``)
requires the Rust agent built with emulation-mode support (ransom-c deliverable):

```bash
cd agent-rust && cargo build --release
```

If the binary is not present, the test skips with a clear message.

---

## What the Emulator Does

The Rust emulator (`agent-rust/tests/ransomware_emulation.rs`) and its Python
stub fallback both:

1. Create a temporary directory (`$TMPDIR/aegis_emul_<uid>/`)
2. Generate 100 dummy files — alternating text (`.docx`) and binary (`.png`)
3. Encrypt every file with deterministic XOR + a 64-byte entropy header,
   renaming each to `<name>.aegis_test_locked`
4. Drop a fake ransom note at `README_AEGIS_TEST.txt` referencing C2 IP
   `198.51.100.42` (RFC 5737 documentation-only address)
5. Write a `manifest.json` for the Python orchestrator to consume

**The real filesystem is never touched.** All writes are inside the temp dir.

---

## Safety Notes

- Encrypted files use suffix `.aegis_test_locked`. They will NEVER be confused
  with real ransomware artefacts (`.locked`, `.enc`, etc.).
- The C2 IP `198.51.100.42` is from the RFC 5737 documentation range
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). It is not routable.
- The XOR cipher is intentionally weak and deterministic. This is an emulator,
  not a real encryption routine.
- The Python fallback stub (`_spawn_python_stub_emulator`) runs inline in the
  test process — no external binary required.

---

## Test Matrix

| Test | Requires Backend | Requires Agent Binary | Skips Without AEGIS_LIVEFIRE |
|---|---|---|---|
| `test_emulator_generates_expected_file_count` | No | No | Yes |
| `test_emulator_manifest_has_c2_ip` | No | No | Yes |
| `test_emulator_ransom_note_exists` | No | No | Yes |
| `test_emulator_locked_files_present` | No | No | Yes |
| `test_emulator_timing_recorded` | No | No | Yes |
| `test_agent_terminates_emulator_within_sla` | No | Yes (or skip) | Yes |
| `test_aegis_api_received_ransomware_event` | Yes | No | Yes |
| `test_ransomware_chain_rule_loaded` | Optional | No | Yes |
| `test_recovery_options_endpoint` | Yes | No | Yes |
| `test_c2_ip_in_auto_block_list` | Yes | No | Yes |

---

## Running the Rust Emulator Standalone

```bash
cd agent-rust
AEGIS_LIVEFIRE=1 cargo test --test ransomware_emulation -- --nocapture
```

The smoke tests (XOR determinism, content alternation, temp dir format) run in
normal CI without `AEGIS_LIVEFIRE`:

```bash
cd agent-rust
cargo test --test ransomware_emulation
```

---

## CI Gating

These tests NEVER run in normal CI (no `AEGIS_LIVEFIRE` set). They are
designed to run via a dedicated `e2e-livefire.yml` workflow (not yet written)
triggered manually or on a scheduled cadence against a staging deployment.

To verify test collection without running them:

```bash
python -m pytest backend/tests/integration/ --noconftest --collect-only
```

Expected output: all tests collected with `SKIPPED` markers, zero errors.

---

## Environment Variables Reference

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_LIVEFIRE` | unset | Must be `1` to run any livefire test |
| `AEGIS_API_URL` | `http://127.0.0.1:8000` | Backend base URL |
| `AEGIS_API_KEY` | `""` | API key for authenticated endpoints |
| `AEGIS_RUST_TEST_BIN` | auto-detected | Override path to Rust agent binary |
| `BLOCKED_IPS_FILE` | `~/.aegis/blocked_ips.txt` | Path to AEGIS blocked IPs file |

---

## Troubleshooting

**Tests skip even with `AEGIS_LIVEFIRE=1`**
- Check `AEGIS_LIVEFIRE` is exported, not just set: `export AEGIS_LIVEFIRE=1`

**`test_agent_terminates_emulator_within_sla` always skips**
- Build the agent: `cd agent-rust && cargo build --release`
- The `--emulation-mode` flag is a ransom-c deliverable; the test will skip
  until that flag is implemented.

**`test_aegis_api_received_ransomware_event` returns 401**
- Set `AEGIS_API_KEY` to a valid key from your running database.

**`test_recovery_options_endpoint` skips with "not yet merged"**
- SnapshotManager (ransom-c) has not been merged yet. Re-run after merge.

**`test_c2_ip_in_auto_block_list` xfails**
- The IP entered the pipeline but is awaiting guardrail approval.
- Set `block_ip: auto_approve` in the client guardrails settings for automated
  livefire runs.
