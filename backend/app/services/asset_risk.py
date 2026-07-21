"""
Deterministic, service-aware asset risk scoring — model ``service_weighted_v1``.

Pure stdlib (``ipaddress`` only). No DB access, no I/O, no AI calls — fully
unit-testable in isolation. Called from both ``scheduled_scanner`` (to
persist a coarse floor after each scan) and ``app.api.surface``
(``list_assets`` / ``get_asset``, to compute the number actually shown in
the UI), so the displayed number and the stored number can never drift for
long: the API always recomputes fresh, with fleet-wide host-share damping
that the single-asset scan path cannot see.

Model summary (see AEGIS product notes for the full derivation):
  1. Normalise ``asset.ports`` into deduped, open-only port dicts.
  2. Classify each port into a risk class + weight (exact port map, then
     service-name substrings, then a port-range fallback).
  3. Damp host-wide "ports" that are actually whole-host nmap noise merged
     into every asset sharing an IP (see ``build_host_index``).
  4. Multiply by a network-exposure factor (loopback vs LAN vs tailnet vs
     public).
  5. Add a vulnerability term (from nuclei findings) on top, unscaled by
     exposure — a confirmed finding is confirmed regardless of bind address.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable, Optional

MODEL_VERSION = "service_weighted_v1"

# --------------------------------------------------------------------------- #
# Step 2(a) — exact port -> (class, weight) map
# --------------------------------------------------------------------------- #
PORT_CLASS: dict[int, tuple[str, float]] = {}


def _register_ports(klass: str, weight: float, ports: Iterable[int]) -> None:
    for p in ports:
        PORT_CLASS[p] = (klass, weight)


_register_ports("cleartext_remote", 9.0, [21, 23, 512, 513, 514])
_register_ports("unauth_datastore", 9.0, [2375, 2379, 5984, 6379, 9200, 11211, 27017])
_register_ports("lateral_smb", 8.0, [135, 139, 445])
_register_ports("remote_desktop", 8.0, [3389, 5900, 5901, 5902, 5903, 5904, 5905])
_register_ports("database", 7.0, [1433, 1521, 3306, 5432, 5433, 9042, 50000])
_register_ports("snmp_mgmt", 6.0, [161, 162])
_register_ports("remote_admin", 6.0, [623, 3031, 5988, 5989])
_register_ports("admin_panel", 5.0, [7443, 8443, 8800, 8834, 9000, 9090, 10000, 15672, 5601])
_register_ports("ssh", 3.0, [22, 2200, 2222])
_register_ports("app_http", 3.0, [80, 443, 3000, 8000, 8080, 8090, 8888])
_register_ports("mail", 2.0, [24, 25, 110, 143, 465, 587, 993, 995])
_register_ports("printing", 1.0, [515, 631, 9100])


# --------------------------------------------------------------------------- #
# Step 2(b) — service substring -> (class, weight) map, longest key first.
# --------------------------------------------------------------------------- #
_SERVICE_GROUPS: list[tuple[tuple[str, ...], str, float]] = [
    (("telnet", "ftp"), "cleartext_remote", 9.0),
    (("redis", "memcach", "mongo", "elastic"), "unauth_datastore", 9.0),
    (("microsoft-ds", "netbios", "smb", "msrpc"), "lateral_smb", 8.0),
    (("vnc", "rdp", "ms-wbt"), "remote_desktop", 8.0),
    (("postgres", "mysql", "oracle", "mssql", "ms-sql"), "database", 7.0),
    (("eppc",), "remote_admin", 6.0),
    (("snmp",), "snmp_mgmt", 6.0),
    (("webadmin", "webmin", "nessus", "portainer", "grafana", "kibana"), "admin_panel", 5.0),
    (("ssh",), "ssh", 3.0),
    # NOTE: "ppp" is nmap's known mislabel of TCP/3000 in its services file
    # (nmap-services lists 3000/tcp as "ppp"); it is mapped to app_http
    # deliberately — it is not a real PPP dial-up service on these hosts.
    (("http", "https", "web app", "python", "node", "nginx", "apache", "ppp"), "app_http", 3.0),
    (("smtp", "submission", "imap", "pop3"), "mail", 2.0),
    (("ipp", "printer", "jetdirect"), "printing", 1.0),
]

# Flatten to (substring, class, weight) and sort longest-substring-first so
# more specific matches are always tried before shorter, more general ones.
SERVICE_CLASS: list[tuple[str, str, float]] = sorted(
    (
        (substr, klass, weight)
        for group, klass, weight in _SERVICE_GROUPS
        for substr in group
    ),
    key=lambda row: len(row[0]),
    reverse=True,
)

CLASS_LABEL: dict[str, str] = {
    "cleartext_remote": "Cleartext remote access",
    "unauth_datastore": "Unauthenticated datastore",
    "lateral_smb": "SMB / lateral movement",
    "remote_desktop": "Remote desktop",
    "database": "Database",
    "snmp_mgmt": "SNMP management",
    "remote_admin": "Remote admin / exec",
    "admin_panel": "Admin panel",
    "ssh": "SSH",
    "app_http": "HTTP application",
    "mail": "Mail",
    "printing": "Printing",
    "ephemeral": "Ephemeral / OS RPC",
    "unknown": "Unclassified",
}

EXPOSURE_MULT: dict[str, float] = {
    "local": 0.25,
    "lan": 1.0,
    "tailnet": 1.0,
    "public": 1.4,
    "unknown": 0.6,
}

# (exclusive upper bound, band key) — first bound the score is strictly below
# wins. Human labels/colors live in the frontend; this module only names the
# band key.
BANDS: list[tuple[float, str]] = [
    (2.0, "contained"),
    (4.0, "watch"),
    (6.0, "elevated"),
    (8.0, "exposed"),
    (10.1, "critical"),
]

_TAILNET = ipaddress.ip_network("100.64.0.0/10")
_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}

HOST_WIDE_MIN_ASSETS = 5
HOST_WIDE_MIN_SHARE = 0.60
HOST_WIDE_DAMPING = 0.35
BASE_TAIL_CAP = 1.5
BASE_TAIL_FACTOR = 0.12
VULN_TERM_CAP = 4.0


def normalize_ports(raw: Optional[list]) -> list[dict]:
    """Normalise a raw ``asset.ports`` list into deduped, open-only port dicts.

    Entries are dicts in one of two known shapes (registration-time vs
    nmap-scan-time) — always ``.get()``, never index. Entries with no
    integer ``port`` are skipped. Entries carrying a ``state`` field that is
    not ``"open"`` are skipped; entries with no ``state`` key at all are
    treated as open (that is the registration shape). Deduped on
    ``(port, protocol or "tcp")``.
    """
    seen: set[tuple[int, str]] = set()
    out: list[dict] = []
    for entry in raw or []:
        if not isinstance(entry, dict):
            continue
        port = entry.get("port")
        if not isinstance(port, int) or isinstance(port, bool):
            continue
        state = entry.get("state")
        if state is not None and state != "open":
            continue
        protocol = entry.get("protocol") or "tcp"
        key = (port, protocol)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "port": port,
            "protocol": protocol,
            "service": entry.get("service"),
            "version": entry.get("version"),
            "state": state or "open",
        })
    return out


def classify_port(port: int, service: Optional[str]) -> tuple[str, float]:
    """Classify a port into ``(class_key, weight)``.

    Ordered, first hit wins: (a) exact port map, (b) service substring map
    (longest key first) on ``str(service).strip().lower()``, (c) port-range
    rule, (d) ``unknown``.
    """
    hit = PORT_CLASS.get(port)
    if hit:
        return hit

    if service:
        svc = str(service).strip().lower()
        if svc:
            for substr, klass, weight in SERVICE_CLASS:
                if substr in svc:
                    return (klass, weight)

    if port >= 32768:
        return ("ephemeral", 0.5)
    if 3000 <= port <= 3999 or 8000 <= port <= 8999:
        return ("app_http", 3.0)
    return ("unknown", 1.0)


def exposure_for(ip_address: Optional[str], hostname: Optional[str]) -> tuple[str, float]:
    """Classify an asset's network exposure from its IP (preferred) or hostname.

    Parses ``ip_address`` first; if it is null/unparseable, tries
    ``hostname``. Loopback (or the literal strings "localhost"/"127.0.0.1"/
    "::1") -> local ×0.25. 100.64.0.0/10 -> tailnet ×1.0. RFC1918/link-local
    -> lan ×1.0. Global/public -> public ×1.4. Unparseable/absent -> unknown
    ×0.6.
    """
    for candidate in (ip_address, hostname):
        if not candidate:
            continue
        text = str(candidate).strip()
        if not text:
            continue
        if text.lower() in _LOCAL_HOSTNAMES:
            return ("local", EXPOSURE_MULT["local"])
        try:
            ip_obj = ipaddress.ip_address(text)
        except ValueError:
            continue  # not parseable as an IP — try the next candidate
        if ip_obj.is_loopback:
            return ("local", EXPOSURE_MULT["local"])
        if ip_obj in _TAILNET:
            return ("tailnet", EXPOSURE_MULT["tailnet"])
        if ip_obj.is_private:
            return ("lan", EXPOSURE_MULT["lan"])
        if ip_obj.is_global:
            return ("public", EXPOSURE_MULT["public"])
        return ("unknown", EXPOSURE_MULT["unknown"])
    return ("unknown", EXPOSURE_MULT["unknown"])


def _ip_key(asset) -> str:
    return getattr(asset, "ip_address", None) or getattr(asset, "hostname", None) or ""


def build_host_index(assets: Iterable) -> dict:
    """Build the fleet-wide host-share index used for Step 3 damping.

    ``assets`` must expose ``.ip_address``, ``.hostname`` and ``.ports``
    (either full ORM ``Asset`` rows or lightweight
    ``select(Asset.id, Asset.ip_address, Asset.hostname, Asset.ports)`` Row
    results — both support attribute access).

    Rationale: ``_run_quick_scan_all`` used to merge whole-host nmap results
    into every asset sharing an IP, so on a dev box the vast majority of
    assets converge on one shared port set (e.g. 81 assets all showing
    22/25/445/587/3000/5432/5900/8000/8080 because they all live on
    127.0.0.1). Treating every one of those as independently dangerous would
    massively over-count; damping restores the per-asset signal without
    mutating any stored data.

    Returns ``{"asset_counts": {ip_key: int}, "port_counts": {(ip_key, port): int}}``.
    """
    asset_counts: dict[str, int] = {}
    port_counts: dict[tuple[str, int], int] = {}
    for asset in assets:
        key = _ip_key(asset)
        asset_counts[key] = asset_counts.get(key, 0) + 1
        for p in normalize_ports(getattr(asset, "ports", None)):
            port_key = (key, p["port"])
            port_counts[port_key] = port_counts.get(port_key, 0) + 1
    return {"asset_counts": asset_counts, "port_counts": port_counts}


def band_for(score: float) -> str:
    """Map a 0-10 risk score to its band key."""
    for upper, key in BANDS:
        if score < upper:
            return key
    return BANDS[-1][1]


def score_asset(
    *,
    ports: Optional[list],
    ip_address: Optional[str],
    hostname: Optional[str],
    critical_vulns: int = 0,
    high_vulns: int = 0,
    total_vulns: int = 0,
    host_index: Optional[dict] = None,
) -> dict:
    """Compute the full ``service_weighted_v1`` risk breakdown for one asset.

    Deterministic — no AI, no I/O. ``host_index`` (from ``build_host_index``)
    is optional; when omitted, host-share damping is skipped entirely
    (every contribution equals its raw weight) — this is the single-asset
    scan write path, which has no fleet context. The read path (surface API)
    always supplies a fresh, client-scoped ``host_index``, which is what
    makes it the authoritative number.
    """
    normalized = normalize_ports(ports)
    key = ip_address or hostname or ""
    asset_counts = (host_index or {}).get("asset_counts", {})
    port_counts = (host_index or {}).get("port_counts", {})
    owned_count = len(normalized)

    host_n = asset_counts.get(key, 0)
    dampable = host_n >= HOST_WIDE_MIN_ASSETS

    drivers: list[dict] = []
    class_totals: dict[str, dict] = {}
    host_wide_count = 0

    for p in normalized:
        port = p["port"]
        klass, weight = classify_port(port, p.get("service"))
        label = CLASS_LABEL.get(klass, klass)

        host_wide = False
        if dampable:
            share = port_counts.get((key, port), 0) / host_n
            host_wide = share >= HOST_WIDE_MIN_SHARE
        if host_wide:
            host_wide_count += 1
        # Round to kill binary-float noise (e.g. 8.0*0.35 == 2.7999999999999994)
        # so the arithmetic an operator reconstructs by hand matches exactly.
        contribution = round(weight * (HOST_WIDE_DAMPING if host_wide else 1.0), 3)

        drivers.append({
            "port": port,
            "protocol": p["protocol"],
            "service": p.get("service") or "",
            "klass": klass,
            "label": label,
            "weight": weight,
            "host_wide": host_wide,
            "contribution": contribution,
        })

        bucket = class_totals.setdefault(
            klass, {"klass": klass, "label": label, "weight": weight, "count": 0}
        )
        bucket["count"] += 1

    drivers.sort(key=lambda d: (-d["contribution"], d["port"]))
    service_classes = sorted(class_totals.values(), key=lambda c: -c["weight"])

    contributions = [d["contribution"] for d in drivers]  # already desc-sorted
    if not contributions:
        base_score = 0.0
    else:
        base_score = contributions[0] + min(BASE_TAIL_CAP, BASE_TAIL_FACTOR * sum(contributions[1:]))

    exposure, exposure_multiplier = exposure_for(ip_address, hostname)

    vuln_term = min(
        VULN_TERM_CAP,
        2.0 * critical_vulns + 1.0 * high_vulns + 0.25 * max(0, total_vulns - critical_vulns - high_vulns),
    )

    # vuln_term is added AFTER the exposure multiplier and is not scaled by
    # it: nuclei only fires on a service it could actually reach, so a
    # confirmed finding is confirmed regardless of bind address.
    raw = base_score * exposure_multiplier + vuln_term
    risk_score = round(min(10.0, max(0.0, raw)), 1)

    return {
        "risk_score": risk_score,
        "risk_band": band_for(risk_score),
        "risk_method": MODEL_VERSION,
        "risk_ai_used": False,
        "exposure": exposure,
        "exposure_multiplier": exposure_multiplier,
        "base_score": round(base_score, 3),
        "vuln_term": round(vuln_term, 3),
        "drivers": drivers,
        "service_classes": service_classes,
        "host_wide_count": host_wide_count,
        "owned_count": owned_count,
    }
