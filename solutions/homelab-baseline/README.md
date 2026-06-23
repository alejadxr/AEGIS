# Homelab Baseline

Minimal AEGIS coverage for self-hosters. High signal, low noise.

## Coverage

- SSH brute force detection
- Port scan / network reconnaissance
- Vulnerability scanner detection (Nmap, Nessus, Nuclei, etc.)
- Blind SQL injection
- Credential stuffing

## Rules (5)

| Rule | Severity | Category |
|------|----------|----------|
| brute_force_ssh | high | authentication |
| port_scan | medium | discovery |
| sigma_recon_vuln_scanner | medium | discovery |
| sigma_web_sqli_blind | high | web_attacks |
| credential_stuffing | high | authentication |

## Playbooks

- **baseline_threat_response** — Blocks attacker IP for 24h, logs event for review

## Installation

```bash
python -m app.cli.solutions install homelab-baseline
```
