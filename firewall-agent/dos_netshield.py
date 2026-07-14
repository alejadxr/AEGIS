"""
AEGIS DoS Netshield — Pi gateway network-tier DoS mitigation (DEFAULT OFF).

This module is the NETWORK TIER (Tier 2) of the AEGIS DoS Shield. It runs on the
Raspberry Pi 5, which is the Mac Pro's network GATEWAY. Because a wrong DROP rule
here can cut the Mac Pro off from the internet, EVERYTHING in this module is:

  * DEFAULT OFF — nothing is applied at import or startup. All state-changing
    functions must be called explicitly (through gated firewall-agent endpoints).
  * IDEMPOTENT — re-applying is a no-op; the dedicated AEGIS_DOS chain is created
    idempotently and flushed before re-population.
  * REVERSIBLE — revert() tears down the entire chain and restores every sysctl
    value that was changed, from a saved snapshot.
  * HOST-SAFE — before ANY rate-limit / connlimit / DROP rule is inserted, the
    chain ALWAYS prepends ACCEPT rules for the Mac Pro Tailscale IP and the
    Tailscale CGNAT range 100.64.0.0/10 (plus loopback), so the gateway can never
    lock out its own protected host or the operator's SSH session.

Design:
  * A DEDICATED iptables chain named "AEGIS_DOS" (separate from AEGIS_BLOCK) holds
    all netshield rules. INPUT/FORWARD jump into it. Tearing down = flush chain,
    delete the jumps, delete the chain — the block-enforcement chain (AEGIS_BLOCK)
    is never touched.
  * Per-source SYN rate limiting via iptables `hashlimit`.
  * Per-source concurrent-connection cap via iptables `connlimit`.
  * SYN-flood hardening via sysctl: tcp_syncookies + backlog/synack tuning. All
    changed keys are snapshotted first so revert() restores the exact prior value.

All subprocess calls use an argv list (NEVER shell=True). Every IP / CIDR is
validated with the `ipaddress` module before use.

--------------------------------------------------------------------------------
MANUAL ENABLE PROCEDURE (operator only, maintenance window, keep console/physical
access to the Pi as a fallback):

  1. On the Mac Pro, set AEGIS_DOS_NETSHIELD=1 and restart cayde6-api.
  2. Confirm firewall_client.list_ratelimit style call is reachable (GET the Pi
     /dos/status endpoint).
  3. Trigger enable (POST /dos/harden then POST /dos/ratelimit on the Pi via the
     gated firewall-agent endpoints, or apply_dos_ratelimit()/harden_synflood()
     from the Mac Pro). The chain ALWAYS prepends the host-safety ACCEPT rules
     BEFORE any limit rule.
  4. IMMEDIATELY, from a SEPARATE session, verify the Mac Pro still reaches the
     internet through the Pi and the API still responds:
         ping -c3 <mac_pro_tailscale_ip>
         curl -sf http://<mac_pro_ip>:8000/api/v1/dos/status
  5. If ANYTHING degrades, revert immediately:
         POST /dos/revert            (via firewall-agent, gated)
     or, as a plain SSH fallback on the Pi:
         python3 -c "import dos_netshield as d; d.revert()"
     or the nuclear option:
         sudo /usr/sbin/iptables -F AEGIS_DOS

FULL ROLLBACK: revert() flushes+deletes the AEGIS_DOS chain, removes the
INPUT/FORWARD jumps, and restores every sysctl key from the snapshot saved in
/etc/aegis/dos_netshield_sysctl_backup.json. AEGIS_BLOCK is never affected.
--------------------------------------------------------------------------------
"""

import ipaddress
import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aegis-firewall.dos_netshield")

# ---------------------------------------------------------------------------
# Constants / configuration
# ---------------------------------------------------------------------------

IPTABLES = "/usr/sbin/iptables"
SYSCTL = "/usr/sbin/sysctl"

# Dedicated chain — kept strictly separate from AEGIS_BLOCK.
DOS_CHAIN = "AEGIS_DOS"

# Persistence for netshield rule state and the sysctl snapshot used for revert().
STATE_DIR = Path("/etc/aegis")
SYSCTL_BACKUP_FILE = STATE_DIR / "dos_netshield_sysctl_backup.json"
RULES_FILE = STATE_DIR / "dos_netshield_rules.json"

# Tailscale CGNAT — the Mac Pro and all peers live here. NEVER limited/dropped.
_TAILSCALE_CGNAT = "100.64.0.0/10"

# The Mac Pro protected-host Tailscale IP is provided via env so no IP is
# hardcoded in-repo. If unset, only the CGNAT + loopback safety rules apply
# (which already covers the Mac Pro since it is inside 100.64.0.0/10).
_MAC_PRO_IP = os.getenv("AEGIS_MACPRO_IP", "").strip()

# sysctl keys we tune for SYN-flood hardening. Values are conservative and
# reversible. Snapshotted before change so revert restores the exact prior state.
_SYNFLOOD_SYSCTL: dict[str, str] = {
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.tcp_max_syn_backlog": "2048",
    "net.ipv4.tcp_synack_retries": "2",
    "net.ipv4.tcp_syn_retries": "3",
    "net.core.somaxconn": "1024",
}

# Default network-tier limits (overridable per-call). Generous by design to
# avoid tripping legitimate shared-IP / proxy traffic.
DEFAULT_SYN_RATE = 50       # SYN packets/sec per source
DEFAULT_SYN_BURST = 100     # burst allowance
DEFAULT_CONNLIMIT = 100     # max concurrent conns per source IP
DEFAULT_PORT = 8000         # AEGIS API port to protect


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _validate_ip(ip: str) -> str:
    """Validate and normalize an IP or CIDR. Raises ValueError on failure."""
    ip = (ip or "").strip()
    if "/" in ip:
        return str(ipaddress.ip_network(ip, strict=False))
    return str(ipaddress.ip_address(ip))


def _validate_int(value, name: str, lo: int, hi: int) -> int:
    """Validate an integer argument is within [lo, hi]. Raises ValueError."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer, got {value!r}")
    if not (lo <= n <= hi):
        raise ValueError(f"{name} must be between {lo} and {hi}, got {n}")
    return n


def _validate_rate(rate) -> int:
    return _validate_int(rate, "rate", 1, 100000)


def _validate_burst(burst) -> int:
    return _validate_int(burst, "burst", 1, 1000000)


def _validate_limit(limit) -> int:
    return _validate_int(limit, "connlimit", 1, 100000)


def _validate_port(port) -> int:
    return _validate_int(port, "port", 1, 65535)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Low-level iptables / sysctl runners (argv-list only, never shell=True)
# ---------------------------------------------------------------------------


def _run_iptables(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run an iptables command with sudo. argv-list, never shell=True."""
    cmd = ["sudo", IPTABLES] + list(args)
    logger.debug("dos_netshield iptables: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=10)


def _run_sysctl_get(key: str) -> Optional[str]:
    """Read a single sysctl key. Returns its value string, or None on failure."""
    try:
        result = subprocess.run(
            ["sudo", SYSCTL, "-n", key],
            capture_output=True, text=True, check=True, timeout=10,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        logger.warning("sysctl read %s failed: %s", key, e)
        return None


def _run_sysctl_set(key: str, value: str) -> bool:
    """Set a single sysctl key. argv-list, never shell=True."""
    try:
        subprocess.run(
            ["sudo", SYSCTL, "-w", f"{key}={value}"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        logger.info("sysctl set %s=%s", key, value)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        logger.error("sysctl set %s=%s failed: %s", key, value, e)
        return False


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _save_json(path: Path, data: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2))
    except OSError as e:
        logger.error("Failed to persist %s: %s", path, e)


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load %s: %s", path, e)
        return {}


# ---------------------------------------------------------------------------
# Chain management
# ---------------------------------------------------------------------------


def _chain_exists() -> bool:
    result = _run_iptables("-L", DOS_CHAIN, "-n", check=False)
    return result.returncode == 0


def _ensure_chain() -> None:
    """Create the dedicated AEGIS_DOS chain and INPUT/FORWARD jumps idempotently.

    ALWAYS (re)prepends host-safety ACCEPT rules at the TOP of the chain so the
    Mac Pro / Tailscale / loopback traffic short-circuits before any limit rule.
    """
    if not _chain_exists():
        _run_iptables("-N", DOS_CHAIN, check=False)
        logger.info("Created dedicated chain %s", DOS_CHAIN)

    # Flush the chain so re-apply is idempotent, then rebuild from safety-first.
    _run_iptables("-F", DOS_CHAIN, check=False)

    # --- HOST-SAFETY ACCEPT rules FIRST (order matters: these must precede any
    #     hashlimit/connlimit/DROP added later) ---
    safe_sources = ["127.0.0.0/8", _TAILSCALE_CGNAT]
    if _MAC_PRO_IP:
        try:
            safe_sources.insert(0, _validate_ip(_MAC_PRO_IP))
        except ValueError:
            logger.warning("AEGIS_MACPRO_IP %r invalid, skipping", _MAC_PRO_IP)
    for src in safe_sources:
        _run_iptables("-A", DOS_CHAIN, "-s", src, "-j", "ACCEPT", check=False)
    logger.info("AEGIS_DOS host-safety ACCEPT rules applied: %s", safe_sources)

    # Ensure INPUT/FORWARD jump into the chain exactly once.
    for parent in ("INPUT", "FORWARD"):
        check = _run_iptables("-C", parent, "-j", DOS_CHAIN, check=False)
        if check.returncode != 0:
            # Insert jump at the top so netshield is evaluated early.
            _run_iptables("-I", parent, "-j", DOS_CHAIN, check=False)
            logger.info("Linked %s -> %s", parent, DOS_CHAIN)


# ---------------------------------------------------------------------------
# Public API — apply
# ---------------------------------------------------------------------------


def apply_ratelimit(
    rate: int = DEFAULT_SYN_RATE,
    burst: int = DEFAULT_SYN_BURST,
    connlimit: int = DEFAULT_CONNLIMIT,
    port: int = DEFAULT_PORT,
) -> dict:
    """Apply per-source SYN hashlimit + concurrent-connection connlimit.

    Rules are added to the DEDICATED AEGIS_DOS chain, AFTER the host-safety
    ACCEPT rules (which are (re)prepended by _ensure_chain). Idempotent.
    """
    rate = _validate_rate(rate)
    burst = _validate_burst(burst)
    connlimit = _validate_limit(connlimit)
    port = _validate_port(port)

    try:
        _ensure_chain()

        # Per-source SYN rate limit (new TCP SYNs to the protected port).
        # Packets ABOVE the hashlimit fall through; matching (under-limit) SYNs
        # are ACCEPTed. Over-limit SYNs get DROPped by the trailing rule.
        _run_iptables(
            "-A", DOS_CHAIN,
            "-p", "tcp", "--syn", "--dport", str(port),
            "-m", "hashlimit",
            "--hashlimit-name", "aegis_dos_syn",
            "--hashlimit-mode", "srcip",
            "--hashlimit-above", f"{rate}/second",
            "--hashlimit-burst", str(burst),
            "-j", "DROP",
        )

        # Per-source concurrent connection cap on the protected port.
        _run_iptables(
            "-A", DOS_CHAIN,
            "-p", "tcp", "--syn", "--dport", str(port),
            "-m", "connlimit",
            "--connlimit-above", str(connlimit),
            "--connlimit-mask", "32",
            "-j", "DROP",
        )

        state = _load_json(RULES_FILE)
        state["ratelimit"] = {
            "rate": rate, "burst": burst, "connlimit": connlimit,
            "port": port, "enabled": True, "applied_at": _now_iso(),
        }
        _save_json(RULES_FILE, state)

        logger.info(
            "AEGIS_DOS ratelimit applied: %d/s burst %d, connlimit %d, port %d",
            rate, burst, connlimit, port,
        )
        return {
            "success": True, "chain": DOS_CHAIN, "rate": rate,
            "burst": burst, "connlimit": connlimit, "port": port,
        }
    except subprocess.CalledProcessError as e:
        logger.error("apply_ratelimit failed: %s", e.stderr)
        return {"success": False, "error": (e.stderr or str(e)).strip()}
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.error("apply_ratelimit error: %s", e)
        return {"success": False, "error": str(e)}


def harden_synflood() -> dict:
    """Enable SYN cookies + tune backlog via sysctl. Snapshots prior values first."""
    try:
        # Snapshot current values so revert() restores exactly (only snapshot
        # once — don't overwrite an existing snapshot with already-tuned values).
        snapshot = _load_json(SYSCTL_BACKUP_FILE)
        if not snapshot.get("values"):
            prior = {}
            for key in _SYNFLOOD_SYSCTL:
                val = _run_sysctl_get(key)
                if val is not None:
                    prior[key] = val
            snapshot = {"values": prior, "saved_at": _now_iso()}
            _save_json(SYSCTL_BACKUP_FILE, snapshot)
            logger.info("Snapshotted %d sysctl keys before hardening", len(prior))

        applied = {}
        for key, value in _SYNFLOOD_SYSCTL.items():
            if _run_sysctl_set(key, value):
                applied[key] = value

        state = _load_json(RULES_FILE)
        state["synflood_hardening"] = {
            "enabled": True, "applied": applied, "applied_at": _now_iso(),
        }
        _save_json(RULES_FILE, state)

        return {"success": True, "applied": applied}
    except OSError as e:
        logger.error("harden_synflood error: %s", e)
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Public API — status / revert
# ---------------------------------------------------------------------------


def status() -> dict:
    """Return current netshield state (chain existence, rules, sysctl snapshot)."""
    chain_present = _chain_exists()
    rules = []
    if chain_present:
        result = _run_iptables("-L", DOS_CHAIN, "-n", "--line-numbers", check=False)
        rules = [ln for ln in result.stdout.splitlines()[2:] if ln.strip()]
    state = _load_json(RULES_FILE)
    return {
        "chain": DOS_CHAIN,
        "chain_present": chain_present,
        "rule_count": len(rules),
        "rules_raw": rules,
        "ratelimit": state.get("ratelimit", {}),
        "synflood_hardening": state.get("synflood_hardening", {}),
        "sysctl_snapshot_present": SYSCTL_BACKUP_FILE.exists(),
        "generated_at": _now_iso(),
    }


def _remove_chain() -> None:
    """Flush + unlink + delete the AEGIS_DOS chain. AEGIS_BLOCK untouched."""
    if not _chain_exists():
        return
    # Remove all INPUT/FORWARD jumps into the chain.
    for parent in ("INPUT", "FORWARD"):
        while True:
            result = _run_iptables("-D", parent, "-j", DOS_CHAIN, check=False)
            if result.returncode != 0:
                break
    _run_iptables("-F", DOS_CHAIN, check=False)
    _run_iptables("-X", DOS_CHAIN, check=False)
    logger.info("Removed chain %s and its INPUT/FORWARD jumps", DOS_CHAIN)


def _restore_sysctl() -> dict:
    """Restore all snapshotted sysctl values. Returns the restored map."""
    snapshot = _load_json(SYSCTL_BACKUP_FILE)
    restored = {}
    for key, value in (snapshot.get("values") or {}).items():
        if _run_sysctl_set(key, value):
            restored[key] = value
    if restored:
        try:
            SYSCTL_BACKUP_FILE.unlink()
        except OSError:
            pass
    return restored


def revert() -> dict:
    """FULL rollback: tear down the AEGIS_DOS chain and restore sysctl.

    Idempotent and safe to call even if netshield was never enabled. Never
    touches the AEGIS_BLOCK chain or persisted per-IP blocks.
    """
    try:
        _remove_chain()
        restored = _restore_sysctl()

        # Clear persisted netshield rule state (block state lives elsewhere).
        try:
            if RULES_FILE.exists():
                RULES_FILE.unlink()
        except OSError:
            pass

        logger.info("AEGIS_DOS netshield reverted; %d sysctl keys restored", len(restored))
        return {"success": True, "chain_removed": True, "sysctl_restored": restored}
    except subprocess.CalledProcessError as e:
        logger.error("revert failed: %s", e.stderr)
        return {"success": False, "error": (e.stderr or str(e)).strip()}
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.error("revert error: %s", e)
        return {"success": False, "error": str(e)}
