# Web Application Defense

Comprehensive AEGIS solution for detecting and responding to web application attacks.

## Coverage

- SQL Injection (UNION SELECT, blind, time-based)
- Cross-Site Scripting (reflected and stored)
- Command Injection
- Path Traversal
- Web Shell detection and response
- Directory brute-force / enumeration

## Rules (6)

| Rule | Severity | Category |
|------|----------|----------|
| sigma_web_sqli_union | high | web_attacks |
| sigma_web_xss_reflected | high | web_attacks |
| sigma_web_command_injection | high | web_attacks |
| sigma_web_path_traversal | medium | web_attacks |
| sigma_persist_webshell | critical | persistence |
| sigma_recon_dir_bruteforce | medium | discovery |

## Playbooks

- **web_attack_response** — Auto-blocks attacker IP, rate-limits endpoint, captures request
- **web_shell_response** — Critical: isolates host, quarantines file, rotates credentials

## Installation

```bash
python -m app.cli.solutions install web-app-defense
```
