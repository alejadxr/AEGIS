# AEGIS Firewall Agent

FastAPI service (port 8765) that manages the `AEGIS_BLOCK` iptables chain on the
gateway host. AEGIS (the backend) pushes blocks to it via `firewall_client`.

## Authentication

| Env var | Where | Meaning |
|---|---|---|
| `AEGIS_FIREWALL_SECRET` | agent AND backend `.env` | Shared secret, sent as header `X-AEGIS-FW-Auth`. |
| `AEGIS_FIREWALL_PUBLIC_READ` | agent | Comma-separated GET paths allowed without the secret. Default `/blocked` (consumers that cannot send the header, e.g. the Sable middleware). Mutating methods are never public. |

Behaviour:

- Secret **unset** on the agent: compat mode, nothing is enforced (anyone who can
  reach the port can block/unblock IPs). Do not leave it this way.
- Secret **set**: every route requires the header (constant-time compare), except
  `GET /health` and `GET` on the public-read allowlist. Rejected attempts are
  logged at WARNING (`auth rejected: METHOD /path from IP`), at most once per
  30 s per client/method/path. The secret is never logged.

## Rollout

Order matters: set the backend first (it sends the header harmlessly while the
agent is still in compat mode), then the agent (which turns enforcement on).

1. Generate a secret (do not paste it in chat or commit it):
   `openssl rand -hex 32`
2. Backend host: add `AEGIS_FIREWALL_SECRET=<secret>` to `backend/.env`, then
   `pm2 restart cayde6-api --update-env`.
3. Agent host: put the same value in an env file the unit reads, e.g.
   `sudo install -m 600 /dev/null /etc/aegis/firewall.env` and add the line
   `AEGIS_FIREWALL_SECRET=<secret>` (the repo unit has
   `EnvironmentFile=-/etc/aegis/firewall.env`; if the deployed unit predates
   that, add the line or an `Environment=` entry, then `sudo systemctl daemon-reload`).
   Optionally add `AEGIS_FIREWALL_PUBLIC_READ=/blocked`.
4. `sudo systemctl restart aegis-firewall`.
5. Verify from another host (no secret printed):
   - `curl -s -o /dev/null -w '%{http_code}\n' -X POST http://<agent>:8765/block -d '{}'` -> `401`
   - `curl -s -o /dev/null -w '%{http_code}\n' http://<agent>:8765/blocked` -> `200`
   - backend: trigger a block / `GET /api/v1/firewall/stats` and confirm
     `pi_reachable` is true; check `journalctl -u aegis-firewall` for unexpected
     `auth rejected` lines from the backend host.

Rollback: remove the line on the agent and restart it (back to compat mode).

Any other client of the agent must send `X-AEGIS-FW-Auth` after enforcement is
on, or be limited to the public-read paths.

## Tests

`cd firewall-agent && python3 -m pytest tests -q`
