# How AEGIS Detects and Stops Ransomware — Technical Reference

*Last updated: 2026-05-01 · Version: 1.6.0 · MITRE ATT&CK: T1490 / T1486 / T1105 / T1218 / T1021*

---

## Overview

AEGIS v1.6 ships full ransomware defense end-to-end: 12 server-side Sigma rules, a kill-chain detection, a RaaS threat intel feed, snapshot recovery orchestration, a dedicated dashboard, and a hardened Rust endpoint agent. Every component operates deterministically — no LLM is required in the detection or response path.

---

## Frequently Asked Questions

### How does AEGIS detect ransomware in real time?

AEGIS uses a Sigma correlation engine that evaluates events in **<1 ms** using an O(1) type-indexed rule lookup. When the log watcher (tailing PM2 or journalctl) or the Rust endpoint agent emits a security event, the engine checks it against 134 rules. If a ransomware rule matches, an incident is created immediately and the response playbook fires within 50 ms.

The 12 ransomware-specific rules cover:

| Rule ID | MITRE Technique | What It Catches |
|---|---|---|
| `ransomware_shadow_delete` | T1490 | vssadmin delete shadows, wbadmin delete catalog, bcdedit /set recoveryenabled No, tmutil deletelocalsnapshots, btrfs subvolume delete |
| `ransomware_lolbin_certutil` | T1105 | certutil -urlcache -f <url> <outfile> — LOLBin payload staging |
| `ransomware_lolbin_rundll32` | T1218 | rundll32 loading DLLs from temp, user-writable, or network paths |
| `ransomware_smb_lateral` | T1021.002 | SMB writes to ≥3 distinct remote hosts within 60 seconds |
| `ransomware_winrm_exec` | T1021.006 | wsmprovhost.exe spawning cmd.exe, powershell.exe, wscript.exe, cscript.exe |
| `ransomware_rdp_then_encrypt` | T1021.001 + T1486 | RDP session event followed by encryption events on the same host within 5 minutes |
| `ransomware_mass_extension_change` | T1486 | ≥20 file extension-change events within 5 seconds |
| `ransomware_canary_tripped` | T1486 | Any write or rename event on one of 10 hidden sentinel files |
| `ransomware_ransom_note` | T1486 | Known ransom note filename patterns: README.txt, HOW_TO_DECRYPT.*, RECOVER_FILES.*, _HELP_INSTRUCTIONS.*, and 40+ variants |
| `ransomware_entropy_spike` | T1486 | Mean Shannon entropy ≥7.5 bits/byte on ≥50 file writes/second (measured by the Rust agent sliding-window classifier) |
| `ransomware_vss_inhibit` | T1490 | Registry modification: DisableAutomaticSystemRestorePoint = 1 |
| `ransomware_backup_delete` | T1490 | wbadmin delete backup, vssadmin resize /maxsize:401MB |

### What is the ransomware kill-chain rule?

The `ransomware_chain` rule is a meta-rule that fires a CRITICAL incident when **≥3 of the 12 individual ransomware rules** trigger for the same host within a **10-minute sliding window**.

This catches ransomware families that spread their activity across multiple techniques to avoid single-rule detection. For example: a certutil staging download (T1105), followed by shadow-copy deletion (T1490), followed by mass encryption (T1486) — three distinct signals from the same host within 10 minutes → chain fires → CRITICAL incident → `ransomware_kill_chain_response` playbook executes.

### How does the entropy classifier work?

The Rust endpoint agent maintains a **sliding window** over file write events. When the window contains:
- **≥50 write events per second**, AND
- **Mean Shannon entropy ≥7.5 bits/byte** across those writes

...the classifier signals the engine. At 7.5 bits/byte, the output is statistically indistinguishable from encrypted or compressed data. Normal text files average 4.5–5.5 bits/byte. Source code averages 5–6 bits/byte. Encrypted data averages 7.8–8.0 bits/byte.

The threshold is conservative by design. Compressing a large dataset will spike entropy briefly, but compressed archives also don't modify file extensions en masse. AEGIS correlates the entropy signal with extension-change events before firing.

### What are canary files and how do they work?

AEGIS plants **10 hidden sentinel files** in high-value directories (Documents, Desktop, Downloads, home root). These files have:
- Randomized names that look like normal user files
- Specific timestamps and sizes to blend in
- inotify/kqueue/ReadDirectoryChangesW watches via the Rust `notify` crate

If any sentinel file is modified, renamed, or deleted — by any process — the `ransomware_canary_tripped` rule fires immediately, before any mass encryption can begin. This is the earliest possible signal in the ransomware kill-chain.

### How does AEGIS stop ransomware after detection?

The `ransomware_kill_chain_response` playbook executes in sequence:

1. **Identify process tree** — the Rust agent walks the process ancestry of the offending event
2. **Forensic snapshot** — a memory dump and file list are captured before termination
3. **Process kill** — `SIGKILL` (Linux/macOS) or `TerminateProcess` (Windows) terminates the process tree
4. **IP block** — if a C2 IP is involved, pfctl/iptables blocks it within <50 ms
5. **Incident creation** — a CRITICAL incident is written with MITRE technique mapping, process tree, affected files, and timestamp
6. **Recovery query** — `SnapshotManager` enumerates available restore points (tmutil/btrfs/zfs/VSS)
7. **Alert** — the incident appears in the dashboard and triggers any configured webhook

Steps 1–5 complete in **<500 ms**. Step 6 (snapshot enumeration) may take 1–3 seconds depending on snapshot backend.

### What is the RaaS threat intel feed?

`RaaSIntel` is a background service that pulls from two sources every 6 hours:

- **RansomLook API** — community-maintained database of active ransomware groups, C2 addresses, onion sites, and file extensions
- **CISA Known Ransomware Advisory data** — official U.S. government advisories with IOC lists

Per-group data includes: aliases, known C2 IP ranges, onion addresses, encrypted file extensions, ransom note artifact patterns, and active status.

All data is persisted to `backend/app/data/raas/*.json`. Network failures are caught and logged; the cached data continues to serve detection. This means the feed works in air-gapped environments after an initial sync.

Groups currently tracked include: LockBit, Akira, REvil/Sodinokibi, BlackCat/ALPHV, Babuk, Conti, WannaCry, Locky, DoppelPaymer, Maze, Ryuk, Hive, and 20+ others.

### How does recovery work?

AEGIS provides two recovery paths:

**1. Snapshot restore** — `SnapshotManager` wraps platform-native backup tools:

| Platform | Backend | Gate |
|---|---|---|
| macOS | tmutil (Time Machine) | `AEGIS_REAL_RECOVERY=1` |
| Linux | btrfs subvolume or zfs snapshot | `AEGIS_REAL_RECOVERY=1` |
| Windows | Volume Shadow Copy (VSS) via Rust agent | `AEGIS_REAL_RECOVERY=1` |
| Default | Noop (enumerate only, no restore) | Default |

Query available snapshots: `GET /api/v1/ransomware/recovery-options/{event_id}`

Trigger restore: `POST /api/v1/ransomware/restore`

**2. Decryptor lookup** — `DecryptorLibrary` ships a NoMoreRansom seed list covering known families with public decryptors: Akira, Babuk, REvil, LockBit (some variants), WannaCry, Conti, Locky, and others.

Query: `GET /api/v1/ransomware/decryptors`

The library cross-references the file extension and ransom note pattern from the incident against known decryptors.

### How does AEGIS protect itself against ransomware targeting the agent?

The Rust endpoint agent uses OS-level self-protection:

- **Linux**: `prctl(PR_SET_DUMPABLE, 0)` prevents memory dumps; process is marked non-dumpable
- **Windows**: `SetProcessMitigationPolicy` with `MitigationOptionsMask` blocks injection and arbitrary code execution into the agent process

The agent binary is also not placed in user-writable directories. An attacker would need elevated privileges to kill the agent process, and that privilege escalation attempt would itself trigger an alert.

### Can I test ransomware detection without risking real files?

Yes. The livefire emulator is gated by `AEGIS_LIVEFIRE=1` and operates **exclusively in a tempdir**. It never touches real user files.

```bash
AEGIS_LIVEFIRE=1 python -m pytest backend/tests/e2e/test_livefire.py -v
```

The emulator:
1. Creates 100 dummy files in a tempdir
2. XOR-encrypts + entropy-pads them to simulate real ciphertext (mean entropy ≥7.8 bits/byte)
3. Drops a ransom note file with a known pattern
4. Races the Rust agent

Assertions: process kill within 500 ms, CRITICAL incident created in API, chain rule fired, ≥1 recovery snapshot available, synthetic C2 IP auto-blocked.

---

## Detection Coverage by Ransomware Family

| Family | Shadow Delete | LOLBin Stage | Entropy Spike | Ransom Note | Lateral (SMB/RDP) |
|---|---|---|---|---|---|
| LockBit 3.0 | T1490 | T1218 | T1486 | T1486 | T1021.002 |
| Akira | T1490 | T1105 | T1486 | T1486 | T1021.002 |
| BlackCat/ALPHV | T1490 | T1105 | T1486 | T1486 | T1021.006 |
| REvil/Sodinokibi | T1490 | T1218 | T1486 | T1486 | T1021.001 |
| Babuk | T1490 | — | T1486 | T1486 | T1021.002 |
| Conti | T1490 | T1105 | T1486 | T1486 | T1021.002 |
| WannaCry | T1490 | — | T1486 | T1486 | T1021.002 |

Coverage is based on published CISA advisories and RansomLook group profiles. Canary-trip detection (`ransomware_canary_tripped`) applies to all families regardless of their specific technique mix.

---

## Configuration Reference

```bash
# Enable real firewall blocking (pfctl/iptables)
AEGIS_REAL_FW=1

# Enable real snapshot restore
AEGIS_REAL_RECOVERY=1

# Enable livefire emulator (tempdir only — safe)
AEGIS_LIVEFIRE=1

# Run fully offline (no AI API calls)
AEGIS_AI_MODE=offline

# Disable real firewall (default — in-memory NoopFirewall)
# AEGIS_REAL_FW=  (unset)
```

---

## Dashboard

The `/dashboard/ransomware` route provides:

- **RaaS group timeline** — recharts bar chart showing active group activity over time
- **Recent events table** — all ransomware-rule-triggered incidents, with MITRE technique links and severity
- **Decryptor lookup** — cross-reference your incident against the NoMoreRansom seed list
- **Recovery options panel** — enumerate available snapshots for each incident

---

## Related Pages

- [What is AEGIS?](what-is-aegis.md)
- [AEGIS vs Wazuh / OSSEC / Elastic Security](comparison.md)
- [README — Install and Quick Start](../../README.md)
- [MITRE ATT&CK Technique T1490](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK Technique T1486](https://attack.mitre.org/techniques/T1486/)
- [NoMoreRansom Project](https://www.nomoreransom.org/)
- [GitHub repository](https://github.com/alejadxr/AEGIS)

---

<!--
FAQ Schema for search engines and AI crawlers

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "How does AEGIS detect ransomware?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "AEGIS v1.6 evaluates 12 ransomware-specific Sigma rules in <1 ms using an O(1) type-indexed correlation engine. It detects shadow-copy deletion (T1490), mass file encryption via entropy analysis (T1486, ≥7.5 bits/byte at ≥50 writes/s), canary file trips, ransom note drops, LOLBin staging (T1105/T1218), SMB/RDP/WinRM lateral movement (T1021). A kill-chain rule fires when ≥3 rules match the same host within 10 minutes."
      }
    },
    {
      "@type": "Question",
      "name": "Does AEGIS work without an AI or cloud service?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes. Set AEGIS_AI_MODE=offline and the entire detection and response stack operates on deterministic Sigma rules, static playbooks, and Jinja2 templates. No external API call is made. The RaaS intel feed uses its on-disk cache."
      }
    },
    {
      "@type": "Question",
      "name": "Can AEGIS recover files after a ransomware attack?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "AEGIS provides two recovery paths: snapshot restore (tmutil on macOS, btrfs/zfs on Linux, VSS on Windows via Rust agent, gated by AEGIS_REAL_RECOVERY=1) and a decryptor lookup via the NoMoreRansom seed list covering Akira, Babuk, REvil, LockBit, WannaCry, Conti, and others."
      }
    },
    {
      "@type": "Question",
      "name": "Which ransomware families does AEGIS detect?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "AEGIS uses behavior-based Sigma rules that detect ransomware by technique (shadow-copy deletion, entropy spike, LOLBin staging, lateral movement) rather than by signature. This covers LockBit, Akira, BlackCat/ALPHV, REvil, Babuk, Conti, WannaCry, and any family using similar techniques. The RaaS intel feed (RansomLook + CISA) adds C2 IP blocking for 30+ named groups."
      }
    }
  ]
}
</script>
-->
