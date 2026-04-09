"""
Embedded RAG (Retrieval-Augmented Generation) service for AEGIS.

Uses Qdrant embedded (local disk, no server) + sentence-transformers for
embeddings. Provides semantic search over incidents, scan results, threat
intel, and security knowledge.

Graceful degradation: if dependencies are missing, RAG_ENABLED=False and
Ask AI continues to work without historical context.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("aegis.rag")

# ---------------------------------------------------------------------------
# Dependency availability flags
# ---------------------------------------------------------------------------

_QDRANT_AVAILABLE = False
_SBERT_AVAILABLE = False

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import (
        Distance,
        FieldCondition,
        Filter,
        MatchValue,
        PointStruct,
        VectorParams,
    )

    _QDRANT_AVAILABLE = True
except ImportError:
    logger.warning("qdrant-client not installed -- RAG disabled")

try:
    from sentence_transformers import SentenceTransformer

    _SBERT_AVAILABLE = True
except ImportError:
    logger.warning("sentence-transformers not installed -- RAG disabled")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COLLECTION_NAME = "aegis_knowledge"
EMBEDDING_DIM = 384  # all-MiniLM-L6-v2 produces 384-dim vectors
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
CHUNK_SIZE = 500  # tokens (approx chars / 4)
CHUNK_OVERLAP = 50
QDRANT_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "qdrant_data",
)


def _chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Split text into overlapping chunks by approximate token count.

    Uses a simple word-based splitter. Each chunk targets ``chunk_size``
    *words* (a reasonable proxy for tokens) with ``overlap`` words shared
    between consecutive chunks.
    """
    words = text.split()
    if len(words) <= chunk_size:
        return [text]

    chunks: list[str] = []
    start = 0
    while start < len(words):
        end = start + chunk_size
        chunk = " ".join(words[start:end])
        chunks.append(chunk)
        if end >= len(words):
            break
        start = end - overlap
    return chunks


class RAGService:
    """Embedded RAG service -- singleton pattern via module-level instance."""

    def __init__(self):
        self._enabled = False
        self._client: Optional[Any] = None
        self._model: Optional[Any] = None
        self._started = False
        self._stats = {
            "documents_ingested": 0,
            "queries_served": 0,
            "last_ingest_at": None,
            "last_query_at": None,
            "model_name": EMBEDDING_MODEL_NAME,
            "collection_name": COLLECTION_NAME,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Initialize Qdrant + embedding model. Non-blocking wrapper."""
        if self._started:
            return

        if not _QDRANT_AVAILABLE or not _SBERT_AVAILABLE:
            logger.warning(
                "RAG dependencies missing (qdrant=%s, sbert=%s) -- RAG disabled",
                _QDRANT_AVAILABLE,
                _SBERT_AVAILABLE,
            )
            return

        try:
            # Run the blocking initialization in a thread so we don't block
            # the async event loop (model download can take time on first run).
            await asyncio.get_event_loop().run_in_executor(None, self._init_sync)
            self._enabled = True
            self._started = True
            logger.info(
                "RAG service started (collection=%s, dim=%d, path=%s)",
                COLLECTION_NAME,
                EMBEDDING_DIM,
                QDRANT_DATA_DIR,
            )
        except Exception as exc:
            logger.error("RAG service failed to start: %s", exc, exc_info=True)

    def _init_sync(self) -> None:
        """Blocking initialization -- called inside executor."""
        Path(QDRANT_DATA_DIR).mkdir(parents=True, exist_ok=True)

        self._client = QdrantClient(path=QDRANT_DATA_DIR)

        # Create collection if it doesn't exist
        collections = [c.name for c in self._client.get_collections().collections]
        if COLLECTION_NAME not in collections:
            self._client.create_collection(
                collection_name=COLLECTION_NAME,
                vectors_config=VectorParams(
                    size=EMBEDDING_DIM,
                    distance=Distance.COSINE,
                ),
            )
            logger.info("Created Qdrant collection '%s'", COLLECTION_NAME)

        # Load embedding model (downloads ~80 MB on first run)
        self._model = SentenceTransformer(EMBEDDING_MODEL_NAME)
        logger.info("Embedding model '%s' loaded", EMBEDDING_MODEL_NAME)

    async def stop(self) -> None:
        """Graceful shutdown."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
        self._started = False
        self._enabled = False
        logger.info("RAG service stopped")

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def ensure_started(self) -> bool:
        """Lazy initialization -- called automatically on first use.

        On first successful start, registers with the event bus and seeds
        knowledge if the collection is empty.

        Returns True if the service is ready, False otherwise.
        """
        if self._started:
            return self._enabled
        await self.start()
        if self._enabled:
            await self._post_start()
        return self._enabled

    async def _post_start(self) -> None:
        """One-time post-start setup: event bus registration and knowledge seeding."""
        # Register with event bus for auto-ingestion
        try:
            from app.core.events import event_bus
            self.register_event_bus(event_bus)
        except Exception as exc:
            logger.debug("Could not register RAG with event bus: %s", exc)

        # Seed knowledge if collection is empty
        try:
            info = self._client.get_collection(COLLECTION_NAME)
            if info.points_count == 0:
                from app.services.rag_seed import seed_knowledge
                await seed_knowledge(self)
        except Exception as exc:
            logger.debug("RAG auto-seed failed (non-fatal): %s", exc)

    # ------------------------------------------------------------------
    # Embeddings
    # ------------------------------------------------------------------

    def _embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings synchronously (called inside executor)."""
        if self._model is None:
            raise RuntimeError("Embedding model not loaded")
        embeddings = self._model.encode(texts, show_progress_bar=False, normalize_embeddings=True)
        return embeddings.tolist()

    async def _async_embed(self, texts: list[str]) -> list[list[float]]:
        """Non-blocking embedding generation."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._embed, texts)

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    async def ingest(
        self,
        text: str,
        metadata: dict,
        doc_type: str = "generic",
        doc_id: Optional[str] = None,
    ) -> dict:
        """Ingest a document into the knowledge base.

        Long texts are automatically chunked. Each chunk gets its own vector
        point but shares the same ``doc_group_id`` for grouping.

        Returns a summary dict with the number of chunks ingested.
        """
        if not self._enabled:
            return {"status": "disabled", "chunks": 0}

        chunks = _chunk_text(text)
        doc_group_id = doc_id or str(uuid.uuid4())

        vectors = await self._async_embed(chunks)

        points = []
        for idx, (chunk, vector) in enumerate(zip(chunks, vectors)):
            point_id = str(uuid.uuid4())
            payload = {
                **metadata,
                "doc_group_id": doc_group_id,
                "doc_type": doc_type,
                "chunk_index": idx,
                "total_chunks": len(chunks),
                "text": chunk,
                "ingested_at": datetime.utcnow().isoformat(),
            }
            points.append(PointStruct(id=point_id, vector=vector, payload=payload))

        # Qdrant upsert is sync -- run in executor
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._client.upsert(collection_name=COLLECTION_NAME, points=points),
        )

        self._stats["documents_ingested"] += 1
        self._stats["last_ingest_at"] = datetime.utcnow().isoformat()

        logger.debug(
            "Ingested doc_type=%s chunks=%d group=%s",
            doc_type,
            len(chunks),
            doc_group_id,
        )
        return {"status": "ok", "doc_group_id": doc_group_id, "chunks": len(chunks)}

    # -- convenience helpers --

    async def ingest_incident(self, incident: dict) -> dict:
        """Ingest an incident record."""
        parts = [
            f"Incident: {incident.get('title', 'N/A')}",
            f"Severity: {incident.get('severity', 'N/A')}",
            f"Status: {incident.get('status', 'N/A')}",
            f"Source: {incident.get('source', 'N/A')}",
            f"Source IP: {incident.get('source_ip', 'N/A')}",
            f"MITRE: {incident.get('mitre_technique', 'N/A')} / {incident.get('mitre_tactic', 'N/A')}",
        ]
        description = incident.get("description")
        if description:
            parts.append(f"Description: {description}")
        ai_analysis = incident.get("ai_analysis")
        if ai_analysis:
            parts.append(f"AI Analysis: {json.dumps(ai_analysis, default=str)[:1000]}")

        text = "\n".join(parts)
        metadata = {
            "incident_id": str(incident.get("id", "")),
            "severity": incident.get("severity", ""),
            "source_ip": incident.get("source_ip", ""),
            "mitre_technique": incident.get("mitre_technique", ""),
        }
        return await self.ingest(text, metadata, doc_type="incident", doc_id=str(incident.get("id", "")))

    async def ingest_scan_result(self, scan: dict) -> dict:
        """Ingest scan results."""
        parts = [
            f"Scan Target: {scan.get('target', 'N/A')}",
            f"Scan Type: {scan.get('scan_type', 'N/A')}",
            f"Status: {scan.get('status', 'N/A')}",
        ]
        findings = scan.get("findings") or scan.get("results")
        if findings:
            if isinstance(findings, list):
                for f in findings[:20]:  # cap at 20 findings
                    if isinstance(f, dict):
                        parts.append(
                            f"- [{f.get('severity', 'info')}] {f.get('name', f.get('title', 'finding'))}: "
                            f"{f.get('description', '')[:200]}"
                        )
                    else:
                        parts.append(f"- {str(f)[:200]}")
            else:
                parts.append(f"Findings: {json.dumps(findings, default=str)[:2000]}")

        text = "\n".join(parts)
        metadata = {
            "scan_id": str(scan.get("id", "")),
            "target": scan.get("target", ""),
            "scan_type": scan.get("scan_type", ""),
        }
        return await self.ingest(text, metadata, doc_type="scan_result")

    async def ingest_threat_intel(self, ioc: dict) -> dict:
        """Ingest threat intelligence / IOC data."""
        parts = [
            f"Threat Intel: {ioc.get('type', 'indicator')}",
            f"Value: {ioc.get('value', 'N/A')}",
            f"Source: {ioc.get('source', 'N/A')}",
            f"Confidence: {ioc.get('confidence', 'N/A')}",
        ]
        context = ioc.get("context") or ioc.get("description")
        if context:
            parts.append(f"Context: {context}")
        tags = ioc.get("tags")
        if tags:
            parts.append(f"Tags: {', '.join(tags) if isinstance(tags, list) else tags}")

        text = "\n".join(parts)
        metadata = {
            "ioc_type": ioc.get("type", ""),
            "ioc_value": ioc.get("value", ""),
            "source": ioc.get("source", ""),
        }
        return await self.ingest(text, metadata, doc_type="threat_intel")

    async def ingest_text(self, text: str, metadata: Optional[dict] = None) -> dict:
        """Generic text ingestion."""
        return await self.ingest(text, metadata or {}, doc_type="generic")

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    async def query(self, question: str, top_k: int = 5, doc_type: Optional[str] = None) -> list[dict]:
        """Semantic search. Returns list of results with scores."""
        if not self._enabled:
            return []

        vectors = await self._async_embed([question])
        query_vector = vectors[0]

        query_filter = None
        if doc_type:
            query_filter = Filter(
                must=[FieldCondition(key="doc_type", match=MatchValue(value=doc_type))]
            )

        response = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._client.query_points(
                collection_name=COLLECTION_NAME,
                query=query_vector,
                query_filter=query_filter,
                limit=top_k,
                with_payload=True,
            ),
        )
        results = response.points

        self._stats["queries_served"] += 1
        self._stats["last_query_at"] = datetime.utcnow().isoformat()

        output = []
        for hit in results:
            payload = hit.payload or {}
            output.append({
                "id": hit.id,
                "score": round(hit.score, 4),
                "text": payload.get("text", ""),
                "doc_type": payload.get("doc_type", ""),
                "doc_group_id": payload.get("doc_group_id", ""),
                "metadata": {
                    k: v
                    for k, v in payload.items()
                    if k not in ("text", "doc_type", "doc_group_id", "chunk_index", "total_chunks", "ingested_at")
                },
                "ingested_at": payload.get("ingested_at", ""),
            })

        return output

    async def query_with_context(self, question: str, top_k: int = 5) -> str:
        """Returns a formatted context string suitable for injection into an LLM prompt."""
        results = await self.query(question, top_k=top_k)
        if not results:
            return ""

        lines = ["RELEVANT CONTEXT FROM KNOWLEDGE BASE:"]
        for i, r in enumerate(results, 1):
            score_pct = int(r["score"] * 100)
            doc_type = r["doc_type"]
            ingested = r.get("ingested_at", "")[:10]  # date only
            text_preview = r["text"][:500]
            lines.append(f"[Doc {i} | {doc_type} | relevance {score_pct}% | {ingested}]")
            lines.append(text_preview)
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Document management
    # ------------------------------------------------------------------

    async def list_documents(self, offset: int = 0, limit: int = 20, doc_type: Optional[str] = None) -> dict:
        """List ingested documents (paginated). Returns unique doc groups."""
        if not self._enabled:
            return {"documents": [], "total": 0}

        scroll_filter = None
        if doc_type:
            scroll_filter = Filter(
                must=[FieldCondition(key="doc_type", match=MatchValue(value=doc_type))]
            )

        # Scroll through all points to get unique doc groups
        all_points, _next = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._client.scroll(
                collection_name=COLLECTION_NAME,
                scroll_filter=scroll_filter,
                limit=1000,  # reasonable upper bound
                with_payload=True,
            ),
        )

        # Group by doc_group_id
        groups: dict[str, dict] = {}
        for point in all_points:
            payload = point.payload or {}
            gid = payload.get("doc_group_id", point.id)
            if gid not in groups:
                groups[gid] = {
                    "doc_group_id": gid,
                    "doc_type": payload.get("doc_type", ""),
                    "text_preview": payload.get("text", "")[:200],
                    "chunks": 0,
                    "ingested_at": payload.get("ingested_at", ""),
                    "metadata": {
                        k: v
                        for k, v in payload.items()
                        if k not in ("text", "doc_type", "doc_group_id", "chunk_index", "total_chunks", "ingested_at")
                    },
                    "point_ids": [],
                }
            groups[gid]["chunks"] += 1
            groups[gid]["point_ids"].append(str(point.id))

        docs = list(groups.values())
        docs.sort(key=lambda d: d.get("ingested_at", ""), reverse=True)
        total = len(docs)
        paged = docs[offset : offset + limit]

        # Remove point_ids from response (internal only)
        for d in paged:
            d.pop("point_ids", None)

        return {"documents": paged, "total": total, "offset": offset, "limit": limit}

    async def delete_document(self, doc_group_id: str) -> dict:
        """Delete all chunks belonging to a doc group."""
        if not self._enabled:
            return {"status": "disabled", "deleted": 0}

        # Find all point IDs for this group
        points, _ = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._client.scroll(
                collection_name=COLLECTION_NAME,
                scroll_filter=Filter(
                    must=[FieldCondition(key="doc_group_id", match=MatchValue(value=doc_group_id))]
                ),
                limit=500,
                with_payload=False,
            ),
        )

        if not points:
            return {"status": "not_found", "deleted": 0}

        point_ids = [str(p.id) for p in points]
        from qdrant_client.models import PointIdsList

        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._client.delete(
                collection_name=COLLECTION_NAME,
                points_selector=PointIdsList(points=point_ids),
            ),
        )

        return {"status": "ok", "deleted": len(point_ids)}

    # ------------------------------------------------------------------
    # Rebuild
    # ------------------------------------------------------------------

    async def rebuild_index(self) -> dict:
        """Rebuild the entire index by re-ingesting from PostgreSQL."""
        if not self._enabled:
            return {"status": "disabled"}

        try:
            from app.database import async_session
            from app.models.incident import Incident
            from sqlalchemy import select

            # Clear existing collection
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._client.delete_collection(COLLECTION_NAME),
            )
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._client.create_collection(
                    collection_name=COLLECTION_NAME,
                    vectors_config=VectorParams(
                        size=EMBEDDING_DIM,
                        distance=Distance.COSINE,
                    ),
                ),
            )

            ingested = 0

            # Re-ingest incidents
            async with async_session() as db:
                result = await db.execute(select(Incident).order_by(Incident.detected_at.desc()).limit(500))
                incidents = result.scalars().all()
                for inc in incidents:
                    await self.ingest_incident({
                        "id": inc.id,
                        "title": inc.title,
                        "description": inc.description,
                        "severity": inc.severity,
                        "status": inc.status,
                        "source": inc.source,
                        "source_ip": inc.source_ip,
                        "mitre_technique": inc.mitre_technique,
                        "mitre_tactic": inc.mitre_tactic,
                        "ai_analysis": inc.ai_analysis,
                    })
                    ingested += 1

            # Seed built-in knowledge
            from app.services.rag_seed import seed_knowledge

            seed_count = await seed_knowledge(self)
            ingested += seed_count

            logger.info("RAG index rebuilt: %d documents ingested", ingested)
            return {"status": "ok", "documents_ingested": ingested}

        except Exception as exc:
            logger.error("RAG rebuild failed: %s", exc, exc_info=True)
            return {"status": "error", "error": str(exc)}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return service statistics."""
        collection_info = {}
        if self._enabled and self._client:
            try:
                info = self._client.get_collection(COLLECTION_NAME)
                collection_info = {
                    "points_count": info.points_count,
                    "indexed_vectors_count": getattr(info, "indexed_vectors_count", None),
                    "segments_count": info.segments_count,
                    "status": str(info.status),
                }
            except Exception:
                collection_info = {"error": "could not read collection info"}

        return {
            "enabled": self._enabled,
            "started": self._started,
            "qdrant_available": _QDRANT_AVAILABLE,
            "sbert_available": _SBERT_AVAILABLE,
            "embedding_model": EMBEDDING_MODEL_NAME,
            "embedding_dim": EMBEDDING_DIM,
            "data_dir": QDRANT_DATA_DIR,
            "collection": collection_info,
            **self._stats,
        }

    # ------------------------------------------------------------------
    # Event bus handlers (auto-ingestion)
    # ------------------------------------------------------------------

    def register_event_bus(self, event_bus) -> None:
        """Subscribe to event bus for automatic ingestion of new data."""
        event_bus.subscribe("alert_processed", self._on_alert_processed)
        event_bus.subscribe("scan_completed", self._on_scan_completed)
        event_bus.subscribe("correlation_triggered", self._on_correlation_triggered)
        event_bus.subscribe("honeypot_interaction", self._on_honeypot_interaction)
        logger.info("RAG service registered with event bus for auto-ingestion")

    async def _on_alert_processed(self, data: dict) -> None:
        """Auto-ingest when an alert is processed."""
        try:
            await self.ingest_incident({
                "id": data.get("incident_id", ""),
                "title": data.get("incident_title", "Alert"),
                "severity": data.get("incident_severity", "medium"),
                "status": data.get("incident_status", "open"),
                "source": "alert_processed",
                "source_ip": data.get("source_ip", ""),
                "description": data.get("summary", ""),
            })
        except Exception as exc:
            logger.debug("RAG auto-ingest alert failed (non-fatal): %s", exc)

    async def _on_scan_completed(self, data: dict) -> None:
        """Auto-ingest when a scan completes."""
        try:
            await self.ingest_scan_result(data)
        except Exception as exc:
            logger.debug("RAG auto-ingest scan failed (non-fatal): %s", exc)

    async def _on_correlation_triggered(self, data: dict) -> None:
        """Auto-ingest correlation events."""
        try:
            text = (
                f"Correlation triggered: {data.get('rule_id', 'unknown')}\n"
                f"Events correlated: {data.get('event_count', 'N/A')}\n"
                f"Severity: {data.get('severity', 'medium')}\n"
                f"Details: {json.dumps(data, default=str)[:1500]}"
            )
            await self.ingest(
                text,
                {"rule_id": data.get("rule_id", ""), "severity": data.get("severity", "")},
                doc_type="correlation",
            )
        except Exception as exc:
            logger.debug("RAG auto-ingest correlation failed (non-fatal): %s", exc)

    async def _on_honeypot_interaction(self, data: dict) -> None:
        """Auto-ingest honeypot interaction data."""
        try:
            text = (
                f"Honeypot interaction detected\n"
                f"Attacker IP: {data.get('source_ip', 'N/A')}\n"
                f"Service: {data.get('service', 'N/A')}\n"
                f"Commands: {json.dumps(data.get('commands', []), default=str)[:1000]}\n"
                f"Payload: {json.dumps(data.get('payload', {}), default=str)[:1000]}"
            )
            await self.ingest(
                text,
                {"source_ip": data.get("source_ip", ""), "service": data.get("service", "")},
                doc_type="honeypot",
            )
        except Exception as exc:
            logger.debug("RAG auto-ingest honeypot failed (non-fatal): %s", exc)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

rag_service = RAGService()
