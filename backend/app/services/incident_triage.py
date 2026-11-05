"""Human triage of incidents: the verdict an operator sets by hand.

AEGIS also changes incident status on its own (retention's stuck-incident
closer -> ``auto_closed``, firewall_sync / ip_investigator -> ``resolved``). The
two must never be confused: a person who marked an incident ``false_positive``
or parked it as ``investigating`` made a decision, and a background job closing
it "for inactivity" would erase that. So a human verdict is recorded in
``ai_analysis["human_triage"]``, and every automated closer calls
``is_human_triaged`` and leaves such an incident alone.

``incidents.status`` is VARCHAR(20); every value here is far below that.
"""
from datetime import datetime
from typing import Optional

HUMAN_STATUSES = ("open", "investigating", "resolved", "false_positive")
CLOSING_STATUSES = ("resolved", "false_positive")
KEY = "human_triage"
HISTORY_LIMIT = 20


def is_human_triaged(incident) -> bool:
    analysis = getattr(incident, "ai_analysis", None)
    return isinstance(analysis, dict) and isinstance(analysis.get(KEY), dict)


def apply(incident, status: str, actor: str, note: Optional[str] = None,
          extra: Optional[dict] = None, now: Optional[datetime] = None) -> dict:
    """Set a human verdict on `incident` (caller commits). Returns the record."""
    if status not in HUMAN_STATUSES:
        raise ValueError(f"status must be one of {HUMAN_STATUSES}")
    now = now or datetime.utcnow()
    analysis = dict(incident.ai_analysis or {})   # copy + reassign: SQLAlchemy sees the JSON change
    prior = analysis.get(KEY) if isinstance(analysis.get(KEY), dict) else {}
    history = list(prior.get("history") or [])
    history.append({"from": incident.status, "to": status, "by": actor, "at": now.isoformat(),
                    **({"note": note} if note else {})})
    record = {
        "status": status, "by": actor, "at": now.isoformat(),
        "previous_status": incident.status,
        "history": history[-HISTORY_LIMIT:],
        **({"note": note} if note else {}),
        **(extra or {}),
    }
    analysis[KEY] = record
    incident.ai_analysis = analysis
    incident.status = status
    if status in CLOSING_STATUSES:
        incident.resolved_at = now
    else:
        incident.resolved_at = None     # reopened
    return record
