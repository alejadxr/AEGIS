# Ransomware Defense Solution Pack

**AEGIS v1.6 — Phase R-D**

## Overview

This solution pack provides end-to-end ransomware detection and automated response. It integrates 12 Sigma rules, 1 correlation chain, a 7-step containment playbook, an SMB canary honeypot, and a dedicated frontend dashboard.

## What it detects

| Rule | MITRE ATT&CK |
|------|-------------|
| Canary file modified | T1486 |
| Mass extension change | T1486 |
| Shadow copy deletion (vssadmin / wbadmin / bcdedit) | T1490 |
| LOLBin abuse (certutil, rundll32) | T1218 |
| SMB lateral movement | T1021.002 |
| WinRM remote exec | T1021.006 |
| Ransom note dropped | T1486 |
| RDP → encrypt chain | T1021.001 + T1486 |

## Playbook Steps

1. **isolate_host** — Network-cut the infected host (auto-approved)
2. **kill_chain_processes** — Terminate malicious processes (auto-approved)
3. **deny_shadow_delete** — Block vssadmin/wbadmin/bcdedit further execution (auto-approved)
4. **trigger_snapshot** — Emergency disk snapshot before more encryption (auto-approved)
5. **block_c2_ips** — Push all C2 IPs into iptables + persistence file (auto-approved)
6. **notify_admin** — Critical alert to all admin channels (auto-approved)
7. **write_postmortem** — Generate postmortem stub (requires human approval to close)

## Canary Honeypot

The `FINANCE_ARCHIVE` SMB canary share contains 5 honey files. Any write, rename, or delete triggers an immediate critical alert and auto-executes the playbook.

## Frontend Dashboard

Visit `/dashboard/ransomware` in the AEGIS UI for:
- Live event feed filtered to ransomware signatures
- RaaS group activity timeline (area chart)
- Decryptor lookup by file extension

## Installation

The manifest is automatically loaded by AEGIS on startup via `rules_loader.py`. No manual steps required.
