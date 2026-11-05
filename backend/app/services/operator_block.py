"""Operator-initiated IP block: one function, used by the API and the assistant.

It runs the SAME execution path the detector's approved actions use
(``active_responder.execute_action`` -> Pi agent with ``force: true``, the 403
blocklist, and the system firewall), so the three layers cannot drift apart the
way they did when the owner's Swift dashboard called the Pi directly.

What differs from an automated block is only the decision, and the decision is
the operator's:

* permanence: an operator block is permanent unless a duration is given. The
  CONFIRMED/AMBIGUOUS split in ``block_policy`` exists to stop *heuristics*
  from handing out life sentences; a human who typed the address is the
  strongest evidence there is. ``block_policy.force_permanent()`` still wins
  (AEGIS_BLOCKS_PERMANENT=1 means "nothing ever auto-releases"), and
  ``block_policy.classify`` is recorded so the Action reads like every other.
* the safelist is NOT overridable. A typo or a copied-wrong address must not be
  able to lock the owner out of his own office, his customers, or the 100.x
  Tailscale hosts that run this platform; ``safelist.protection_reason`` says
  which kind of protection stopped it.
"""
import ipaddress
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.action import Action
from app.models.incident import Incident
from app.modules.response.responder import active_responder
from app.services import block_policy
from app.services import safelist

logger = logging.getLogger("aegis.operator_block")

MAX_DURATION_S = 30 * 24 * 3600   # the Pi agent's MAX_BLOCK_DURATION
MIN_DURATION_S = 60


class BlockRefused(Exception):
    """The block was not attempted. `status` is the HTTP status the API uses."""

    def __init__(self, code: str, message: str, status: int = 409):
        self.code = code
        self.message = message
        self.status = status
        super().__init__(message)


def normalize_target(raw: str) -> str:
    """A single address only.

    The Pi agent validates with ``ipaddress.ip_address`` and its block listing
    parses iptables output with the same call (firewall-agent/main.py:
    ``_validate_ip``), so a CIDR would be rejected there and could never be
    listed back. Refuse it here with the reason instead of half-applying it.
    """
    text = (raw or "").strip()
    if "/" in text:
        raise BlockRefused(
            "cidr_unsupported",
            "Blocking a CIDR range is not supported: the Pi firewall agent accepts single IP addresses "
            "only. Block the individual addresses.", 400)
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        raise BlockRefused("invalid_ip", f"{text!r} is not a valid IP address.", 400)
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback or addr.is_link_local:
        raise BlockRefused("invalid_ip", f"{addr} is not a routable unicast address.", 400)
    return str(addr)


async def operator_block(
    db: AsyncSession,
    *,
    client_id: str,
    actor: str,
    ip: str,
    reason: str,
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    duration_s: Optional[int] = None,
    incident_id: Optional[str] = None,
) -> dict:
    target = normalize_target(ip)

    protected = safelist.protection_reason(target)
    if protected:
        code, message = protected
        raise BlockRefused(code, f"Refusing to block: {message}")

    if duration_s is not None and not (MIN_DURATION_S <= duration_s <= MAX_DURATION_S):
        raise BlockRefused(
            "invalid_duration",
            f"duration_s must be between {MIN_DURATION_S} and {MAX_DURATION_S} seconds.", 400)

    now = datetime.utcnow()
    forced = block_policy.force_permanent()
    permanent = duration_s is None or forced
    cls = block_policy.classify(reason, threat_type=threat_type)

    if incident_id:
        incident = await db.get(Incident, incident_id)
        if incident is None or incident.client_id != client_id:
            raise BlockRefused("incident_not_found", "Incident not found.", 404)
    else:
        # Action.incident_id is NOT NULL, and the expiry/audit machinery works
        # off Action rows, so a block with no incident gets a closed stub that
        # records who asked and why. "resolved" keeps it out of the active
        # incident counters; source "operator" keeps it out of detection stats.
        incident = Incident(
            client_id=client_id,
            title=f"Operator block: {target}"[:500],
            description=reason[:2000],
            severity=severity or "medium",
            status="resolved",
            source="operator",
            source_ip=target,
            ai_analysis={"operator_block": {"by": actor, "at": now.isoformat(), "reason": reason[:500]}},
            detected_at=now,
            resolved_at=now,
        )
        db.add(incident)
        await db.flush()

    params = {
        "source": "operator", "operator": actor, "reason": reason[:500],
        "block_class": cls.kind,
    }
    if threat_type:
        params["threat_type"] = threat_type
    if severity:
        params["severity"] = severity
    expires_at = None
    if permanent:
        params.update({"permanent": True,
                       "block_class_reason": "AEGIS_BLOCKS_PERMANENT" if forced else "operator"})
        tag = "[PERMANENT: operator]"
    else:
        expires_at = now + timedelta(seconds=duration_s)
        # Same keys ai_engine writes, so retention's expiry sweep handles it.
        # `duration_explicit` is not `provisional`: provisional is AEGIS's own
        # unconfident guess and retention may upgrade it on probe evidence; this
        # is a length a human (or the assistant, on his words) asked for, and it
        # must expire as asked. Retention reads this marker and never promotes.
        params.update({"provisional": True, "expires_at": expires_at.isoformat(),
                       "ttl_hours": round(duration_s / 3600, 2),
                       "duration_explicit": True, "requested_by": actor})
        tag = f"[PROVISIONAL: auto-expires {expires_at.isoformat()}Z]"

    action = Action(
        incident_id=incident.id, client_id=client_id, action_type="block_ip", target=target,
        parameters=params,
        status="approved",
        requires_approval=False,
        # approved_by is what makes the responder treat this as operator-approved:
        # force=true to the Pi, and shared-egress guard lifted (we refused that above).
        approved_by=actor,
        ai_reasoning=f"Operator block by {actor}: {reason[:500]} {tag}",
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)

    result = await active_responder.execute_action(action, db)
    ok = bool(result.get("success"))
    logger.warning(f"OPERATOR_BLOCK {target} by {actor}: ok={ok} permanent={permanent}")
    return {
        "ip": target, "blocked": ok, "permanent": permanent,
        "expires_at": expires_at.isoformat() + "Z" if expires_at else None,
        "action_id": str(action.id), "incident_id": str(incident.id),
        "layers": {"pi": result.get("firewall"), "local": result.get("local"),
                   "system_fw": result.get("system_fw")},
        "message": (
            ("Blocked permanently." if permanent else f"Blocked until {expires_at.isoformat()}Z.")
            + (" (duration ignored: AEGIS_BLOCKS_PERMANENT=1)" if forced and duration_s is not None else "")
            if ok else "The block failed on every layer; see `layers`."
        ),
    }
