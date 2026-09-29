"""Hand endpoint-agent telemetry to the correlation engine.

The ingest routes persist agent events, but persisting is not detecting: the
Sigma engine only sees what arrives on the event bus. Both routes call
`publish_agent_batch` so every stored event also reaches
CorrelationEngine._on_edr_event, one bus message per batch.
"""
from __future__ import annotations

import logging
from typing import Iterable

from app.core.events import event_bus

logger = logging.getLogger("aegis.edr")

# Must match correlation_engine._EDR_BATCH_TOPIC.
EDR_BATCH_TOPIC = "edr.event_batch"


async def publish_agent_batch(
    *,
    client_id: str,
    agent_id: str,
    hostname: str | None,
    events: Iterable[dict],
) -> int:
    """Publish a batch of endpoint events for detection. Returns the count.

    Every event is stamped with the agent's identity so the engine can attribute
    a detection to the host. `hostname` is the agent's registered hostname;
    the engine falls back to agent_id when it is missing.
    """
    payloads = [
        {**ev, "client_id": client_id, "agent_id": agent_id, "hostname": hostname or agent_id}
        for ev in events
    ]
    if not payloads:
        return 0
    try:
        await event_bus.publish(EDR_BATCH_TOPIC, {"events": payloads})
    except Exception as exc:  # pragma: no cover - detection must not fail ingest
        logger.warning("edr batch publish for detection failed: %s", exc)
        return 0
    return len(payloads)
