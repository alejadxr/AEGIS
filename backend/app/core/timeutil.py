"""Timestamp helpers for agent-supplied times.

DB columns are naive (timestamp without time zone, UTC by convention) while
agents send RFC3339 with an offset. asyncpg refuses to bind an aware datetime
to a naive column, so normalise at the ingestion boundary.
"""
from datetime import datetime, timezone


def to_naive_utc(dt: datetime) -> datetime:
    """Aware -> UTC with tzinfo dropped; naive is returned unchanged."""
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def parse_agent_ts(value: str | None, default: datetime | None = None) -> datetime:
    """Parse an agent ISO/RFC3339 string into naive UTC.

    Falls back to `default` (or now, naive UTC) when empty or unparseable.
    """
    if value:
        try:
            return to_naive_utc(datetime.fromisoformat(value.strip().replace("Z", "+00:00")))
        except ValueError:
            pass
    return default if default is not None else datetime.utcnow()
