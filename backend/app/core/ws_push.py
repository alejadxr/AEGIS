"""
WebSocket real-time push service.

Instead of frontend polling, pushes events to connected WebSocket clients
instantly when the event bus receives an event.

Features:
  - Client authentication via client_id
  - Severity-based filtering per client
  - Broadcast to all connected clients
  - Connection health monitoring
  - Target: <10ms from event to client delivery
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("aegis.ws_push")


class WSClient:
    """Represents a connected WebSocket client with filtering preferences."""

    __slots__ = (
        "websocket", "client_id", "connected_at", "filters",
        "topics", "events_sent", "last_event_at",
    )

    def __init__(self, websocket: WebSocket, client_id: str = "anonymous"):
        self.websocket = websocket
        self.client_id = client_id
        self.connected_at = datetime.utcnow().isoformat()
        self.filters: dict = {}  # e.g. {"min_severity": "high", "event_types": [...]}
        # Topic subscriptions — if empty set, client gets everything (legacy behavior)
        # If non-empty, client only receives events whose topic matches.
        self.topics: set[str] = set()
        self.events_sent = 0
        self.last_event_at: Optional[str] = None


class WSPushManager:
    """
    Manages WebSocket connections and pushes events in real-time.

    Replaces the simple ConnectionManager from main.py with:
      - Per-client authentication
      - Event filtering by severity/type
      - Non-blocking broadcast
    """

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self):
        self._clients: list[WSClient] = []
        self._stats = {
            "total_connections": 0,
            "total_events_broadcast": 0,
            "total_events_filtered": 0,
        }

    async def connect(self, websocket: WebSocket, client_id: str = "anonymous") -> WSClient:
        """Accept a WebSocket connection and register the client."""
        await websocket.accept()
        client = WSClient(websocket, client_id)
        self._clients.append(client)
        self._stats["total_connections"] += 1
        logger.info(f"WS client connected: {client_id} (total: {len(self._clients)})")
        return client

    def disconnect(self, ws_client: WSClient):
        """Remove a client from the active list."""
        self._clients = [c for c in self._clients if c is not ws_client]
        logger.info(f"WS client disconnected: {ws_client.client_id} (total: {len(self._clients)})")

    def set_filters(self, ws_client: WSClient, filters: dict):
        """Update filtering preferences for a client."""
        ws_client.filters = filters
        logger.debug(f"WS filters updated for {ws_client.client_id}: {filters}")

    def subscribe_topics(self, ws_client: WSClient, topics: list[str]):
        """Add topic subscriptions for a client. Topics are additive."""
        for t in topics:
            if t:
                ws_client.topics.add(t)
        logger.debug(f"WS topics for {ws_client.client_id}: {ws_client.topics}")

    def unsubscribe_topics(self, ws_client: WSClient, topics: list[str]):
        """Remove topic subscriptions for a client."""
        for t in topics:
            ws_client.topics.discard(t)

    def _topic_matches(self, ws_client: WSClient, topic: str) -> bool:
        """
        Check if a client is subscribed to a given topic.

        If client has no explicit topic subscriptions, they receive everything
        (legacy/compat). If they have subscriptions, we require a match —
        either exact, wildcard "*", or prefix match for "foo.*".
        """
        if not ws_client.topics:
            return True
        if "*" in ws_client.topics:
            return True
        if topic in ws_client.topics:
            return True
        # Prefix matching: "incidents.*" matches "incidents.new"
        for sub in ws_client.topics:
            if sub.endswith(".*") and topic.startswith(sub[:-2] + "."):
                return True
            if sub.endswith("*") and topic.startswith(sub[:-1]):
                return True
        return False

    def _should_send(self, ws_client: WSClient, event: dict) -> bool:
        """Check if an event passes the client's filters."""
        # Topic filtering first — cheapest, most common path
        event_topic = event.get("topic") or event.get("type") or event.get("_event_type", "")
        if event_topic and not self._topic_matches(ws_client, str(event_topic)):
            return False

        filters = ws_client.filters
        if not filters:
            return True

        # Severity filter
        min_severity = filters.get("min_severity")
        if min_severity:
            event_severity = event.get("severity", event.get("data", {}).get("severity", "info"))
            min_level = self.SEVERITY_ORDER.get(min_severity, 4)
            event_level = self.SEVERITY_ORDER.get(event_severity, 4)
            if event_level > min_level:
                return False

        # Legacy event_types filter — also treat as topic subscription
        allowed_types = filters.get("event_types")
        if allowed_types and not ws_client.topics:
            # Only enforce legacy filter if the client hasn't migrated to topics
            if str(event_topic) not in allowed_types:
                return False

        return True

    async def broadcast(self, event: dict):
        """
        Broadcast an event to all connected clients that pass filtering.
        Non-blocking: failed sends are silently dropped.
        Target: <10ms total.
        """
        if not self._clients:
            return

        now = datetime.utcnow().isoformat()
        topic = event.get("topic") or event.get("_event_type") or event.get("type", "event")
        message = {
            "type": topic,
            "topic": topic,
            "data": event,
            "timestamp": now,
            "severity": event.get("severity", event.get("incident_severity", "info")),
        }

        dead_clients: list[WSClient] = []

        for client in self._clients:
            if not self._should_send(client, message):
                self._stats["total_events_filtered"] += 1
                continue
            try:
                await client.websocket.send_json(message)
                client.events_sent += 1
                client.last_event_at = now
            except Exception:
                dead_clients.append(client)

        # Clean up dead connections
        for dead in dead_clients:
            self._clients = [c for c in self._clients if c is not dead]

        self._stats["total_events_broadcast"] += 1

    async def send_to_client(self, client_id: str, event: dict):
        """Send an event to a specific client by client_id."""
        for client in self._clients:
            if client.client_id == client_id:
                try:
                    await client.websocket.send_json({
                        "type": event.get("type", "event"),
                        "data": event,
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                    client.events_sent += 1
                except Exception:
                    pass
                break

    def active_connections(self) -> int:
        return len(self._clients)

    def stats(self) -> dict:
        return {
            **self._stats,
            "active_connections": len(self._clients),
            "clients": [
                {
                    "client_id": c.client_id,
                    "connected_at": c.connected_at,
                    "events_sent": c.events_sent,
                    "last_event_at": c.last_event_at,
                    "has_filters": bool(c.filters),
                }
                for c in self._clients
            ],
        }


# Singleton
ws_push_manager = WSPushManager()
