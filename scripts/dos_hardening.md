# AEGIS DoS Netshield — Network Tier Operator Runbook

**Status: DEFAULT OFF. This is the network tier (Tier 2) of the DoS Shield and it runs on the
Raspberry Pi, which is the Mac Pro's network GATEWAY. A wrong `DROP` rule here can cut the Mac Pro
off the internet. Enable ONLY during a maintenance window, with a fallback path to the Pi (physical
console or a second SSH session you keep open the whole time).**

The automated Sonnet deploy MUST NOT enable this tier. It is deploy-as-code-only, activate-never
by automation. Enabling is an explicit human decision.

---

## What it does

- Creates a **dedicated** iptables chain `AEGIS_DOS` (separate from the block chain `AEGIS_BLOCK`).
- Per-source **SYN rate limiting** via `hashlimit` (default 50 SYN/s per source, burst 100).
- Per-source **concurrent-connection cap** via `connlimit` (default 100 conns per source IP).
- **SYN-flood sysctl hardening** (syncookies + backlog tuning), snapshotted for exact revert.
- A full `revert()` that flushes+deletes `AEGIS_DOS`, removes the INPUT/FORWARD jumps, and restores
  every sysctl value from the snapshot. `AEGIS_BLOCK` and persisted per-IP blocks are never touched.

## Host-safety interlock (why you won't lock yourself out)

Before ANY rate-limit/connlimit/DROP rule, the chain ALWAYS prepends `ACCEPT` rules for:

1. The Mac Pro Tailscale IP (from `AEGIS_MACPRO_IP` env on the Pi unit, optional).
2. The Tailscale CGNAT range `100.64.0.0/10` (covers the Mac Pro and all peers/SSH).
3. Loopback `127.0.0.0/8`.

So Mac Pro traffic, your Tailscale SSH session, and localhost short-circuit to `ACCEPT` before any
limit is evaluated. Even so — **keep a second session open** while enabling.

## Double gate (why it can't fire by accident)

The Pi `/dos/*` endpoints are no-ops unless BOTH are true:

1. Pi systemd unit has `AEGIS_DOS_NETSHIELD=1`.
2. The request carries header `X-AEGIS-Netshield: enable`.

On the Mac Pro side, `firewall_client.apply_dos_ratelimit()/harden_synflood()/revert_dos()` early-return
`{"success": False, "error": "netshield disabled"}` unless `AEGIS_DOS_NETSHIELD` is truthy in the
backend `settings`.

---

## Recommended sysctl values (research-grounded, conservative)

| Key | Value | Purpose |
|-----|-------|---------|
| `net.ipv4.tcp_syncookies` | `1` | Serve SYN cookies when the SYN backlog overflows (core SYN-flood defense). |
| `net.ipv4.tcp_max_syn_backlog` | `2048` | Larger half-open queue absorbs bursts before cookies kick in. |
| `net.ipv4.tcp_synack_retries` | `2` | Fewer SYN-ACK retransmits → half-open entries expire faster under flood. |
| `net.ipv4.tcp_syn_retries` | `3` | Bound outbound SYN retries. |
| `net.core.somaxconn` | `1024` | Larger accept queue so a legit burst isn't dropped at accept(). |

These are applied by `dos_netshield.harden_synflood()` and are the exact keys the snapshot/revert
covers. Do not hand-edit `/etc/sysctl.conf` for these while netshield manages them, or revert will
restore the pre-netshield runtime value and diverge from your file.

Recommended iptables limits (defaults, tune only from observed data):

- SYN hashlimit: `50/second` per source IP, burst `100`.
- connlimit: `100` concurrent conns per source IP (mask /32), on port `8000`.

---

## ENABLE PROCEDURE (maintenance window only)

Replace `<PI>`, `<MACPRO_IP>` with your Tailscale addresses. Keep a **separate** SSH session to the
Pi open the entire time as a fallback.

### 1. Pi: set the env gate (optionally the Mac Pro IP for an explicit ACCEPT)

```bash
# On the Pi, edit the systemd unit:
sudo systemctl edit --full aegis-firewall
#   Add under [Service]:
#     Environment="AEGIS_DOS_NETSHIELD=1"
#     Environment="AEGIS_MACPRO_IP=<MACPRO_IP>"     # optional; CGNAT already covers it
sudo systemctl daemon-reload
sudo systemctl restart aegis-firewall
```

### 2. Mac Pro: enable the backend gate

```bash
# In the AEGIS backend .env on the Mac Pro:
#   AEGIS_DOS_NETSHIELD=1
pm2 restart cayde6-api
```

### 3. Verify the module is reachable (no rules applied yet)

```bash
curl -sf http://<PI>:8765/dos/status | python3 -m json.tool
#   expect: "available": true, "env_gate": true, "chain_present": false
```

### 4. Apply hardening, then rate limiting

```bash
# sysctl hardening first (snapshots prior values):
curl -sf -X POST http://<PI>:8765/dos/harden -H 'X-AEGIS-Netshield: enable' | python3 -m json.tool

# then the iptables rate/conn limits:
curl -sf -X POST http://<PI>:8765/dos/ratelimit -H 'X-AEGIS-Netshield: enable' \
  -H 'Content-Type: application/json' \
  -d '{"rate":50,"burst":100,"connlimit":100,"port":8000}' | python3 -m json.tool
```

Or from the Mac Pro backend (a Python REPL in the venv):

```python
import asyncio
from app.core.firewall_client import firewall_client
asyncio.run(firewall_client.harden_synflood())
asyncio.run(firewall_client.apply_dos_ratelimit(rate=50, burst=100, connlimit=100, port=8000))
```

---

## VERIFY THE GATEWAY STILL WORKS (do this IMMEDIATELY, from a separate session)

```bash
# From the Mac Pro: can it still reach the internet through the Pi?
ping -c 3 1.1.1.1
ping -c 3 <PI>

# From your workstation / Tailscale peer: does the AEGIS API still answer?
curl -sf http://<MACPRO_IP>:8000/health

# Inspect the applied chain on the Pi — host-safety ACCEPTs MUST be at the top:
sudo /usr/sbin/iptables -L AEGIS_DOS -n --line-numbers
#   expect rows 1..N = ACCEPT for <MACPRO_IP>/100.64.0.0-10/127.0.0.0-8 BEFORE any DROP
```

If ping to `1.1.1.1` from the Mac Pro fails, or the API stops answering: **REVERT NOW** (next section).

---

## REVERT / ROLLBACK (fully reversible)

Preferred (graceful, restores sysctl from snapshot):

```bash
curl -sf -X POST http://<PI>:8765/dos/revert -H 'X-AEGIS-Netshield: enable' | python3 -m json.tool
```

From the Mac Pro backend:

```python
import asyncio
from app.core.firewall_client import firewall_client
asyncio.run(firewall_client.revert_dos())
```

Direct on the Pi (SSH fallback — no HTTP needed):

```bash
python3 -c "import sys; sys.path.insert(0,'/home/<user>/firewall-agent'); import dos_netshield as d; print(d.revert())"
```

Nuclear option (flush the dedicated chain only — leaves AEGIS_BLOCK intact):

```bash
sudo /usr/sbin/iptables -F AEGIS_DOS
sudo /usr/sbin/iptables -D INPUT   -j AEGIS_DOS  2>/dev/null
sudo /usr/sbin/iptables -D FORWARD -j AEGIS_DOS  2>/dev/null
sudo /usr/sbin/iptables -X AEGIS_DOS 2>/dev/null
# Then manually restore sysctl if needed (values from snapshot):
sudo /usr/sbin/sysctl -p   # or set the specific keys back
```

After reverting, unset the gate again:

```bash
# Pi: remove Environment="AEGIS_DOS_NETSHIELD=1" (systemctl edit --full), daemon-reload, restart.
# Mac Pro: remove AEGIS_DOS_NETSHIELD=1 from .env, pm2 restart cayde6-api.
```

---

## Notes

- The `AEGIS_DOS` chain is intentionally **separate** from `AEGIS_BLOCK`; per-IP block enforcement
  (the existing `/block` path + `firewall_sync`) is unaffected by enabling/reverting netshield.
- Everything is idempotent: re-running `/dos/harden` or `/dos/ratelimit` rebuilds the chain from
  safety-first and does not stack duplicate jumps or double-snapshot sysctl.
- Persisted state on the Pi: `/etc/aegis/dos_netshield_rules.json` (applied rules) and
  `/etc/aegis/dos_netshield_sysctl_backup.json` (revert snapshot). Deleting the snapshot before a
  revert means sysctl won't be restored — don't.
