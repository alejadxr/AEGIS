# Linux Server Hardening

AEGIS solution for hardening Linux servers and detecting post-exploitation activity.

## Coverage

- SSH brute force and credential stuffing
- Sudo abuse and privilege escalation
- SUID binary exploitation
- Rootkit detection
- Log tampering and deletion
- Malicious cron job persistence

## Rules (6)

| Rule | Severity | Category |
|------|----------|----------|
| brute_force_ssh | high | authentication |
| sigma_privesc_sudo_abuse | high | privilege_escalation |
| sigma_privesc_suid | high | privilege_escalation |
| sigma_evasion_rootkit | critical | defense_evasion |
| sigma_evasion_log_deletion | high | defense_evasion |
| sigma_persist_cron | medium | persistence |

## Playbooks

- **ssh_brute_force_response** — Auto-blocks IP, locks account, adds SSH rate limiting
- **privilege_escalation_response** — Isolates host, kills process tree, rotates all creds

## Installation

```bash
python -m app.cli.solutions install linux-server-hardening
```
