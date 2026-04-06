"""
RAG (Retrieval-Augmented Generation) API endpoints.

Provides semantic search, document ingestion, and knowledge base management
for the AEGIS embedded RAG service.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from app.core.auth import get_current_client, require_admin
from app.models.client import Client
from app.services.rag_service import rag_service

router = APIRouter(prefix="/rag", tags=["rag"])

# NOTE: This router is included by ask_ai.py so endpoints are accessible at
# /ask/rag/* (since ask_ai has prefix="/ask"). This avoids modifying main.py.


async def init_rag_service():
    """Initialize RAG service and register with event bus.

    Call this during app startup or it will lazy-init on first API call.
    """
    ready = await rag_service.ensure_started()
    if ready:
        try:
            from app.core.events import event_bus
            rag_service.register_event_bus(event_bus)
        except Exception as exc:
            import logging
            logging.getLogger("aegis.rag").debug(
                "Could not register RAG with event bus: %s", exc
            )

        # Seed knowledge if collection is empty
        stats = rag_service.get_stats()
        collection = stats.get("collection", {})
        if collection.get("points_count", 0) == 0:
            try:
                from app.services.rag_seed import seed_knowledge
                await seed_knowledge(rag_service)
            except Exception as exc:
                import logging
                logging.getLogger("aegis.rag").debug(
                    "RAG seed failed (non-fatal): %s", exc
                )


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class RAGQueryRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)
    top_k: int = Field(default=5, ge=1, le=20)
    doc_type: Optional[str] = None


class RAGQueryResult(BaseModel):
    id: str
    score: float
    text: str
    doc_type: str
    doc_group_id: str
    metadata: dict
    ingested_at: str


class RAGQueryResponse(BaseModel):
    results: list[RAGQueryResult]
    question: str
    total: int


class RAGIngestRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)
    doc_type: str = Field(default="generic", max_length=50)
    metadata: dict = Field(default_factory=dict)


class RAGIngestResponse(BaseModel):
    status: str
    doc_group_id: str = ""
    chunks: int = 0


class RAGDocumentListResponse(BaseModel):
    documents: list[dict]
    total: int
    offset: int
    limit: int


class RAGDeleteResponse(BaseModel):
    status: str
    deleted: int = 0


class RAGRebuildResponse(BaseModel):
    status: str
    documents_ingested: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/status")
async def rag_status(client: Client = Depends(get_current_client)):
    """Get RAG service status and collection statistics."""
    await rag_service.ensure_started()
    return rag_service.get_stats()


@router.post("/query", response_model=RAGQueryResponse)
async def rag_query(
    req: RAGQueryRequest,
    client: Client = Depends(get_current_client),
):
    """Semantic search across the knowledge base."""
    if not rag_service.enabled:
        raise HTTPException(
            status_code=503,
            detail="RAG service is not available. Install qdrant-client and sentence-transformers.",
        )

    results = await rag_service.query(
        question=req.question,
        top_k=req.top_k,
        doc_type=req.doc_type,
    )

    return RAGQueryResponse(
        results=[RAGQueryResult(**r) for r in results],
        question=req.question,
        total=len(results),
    )


@router.post("/ingest", response_model=RAGIngestResponse)
async def rag_ingest(
    req: RAGIngestRequest,
    client: Client = Depends(get_current_client),
):
    """Manually ingest a document into the knowledge base."""
    if not rag_service.enabled:
        raise HTTPException(
            status_code=503,
            detail="RAG service is not available.",
        )

    result = await rag_service.ingest(
        text=req.text,
        metadata=req.metadata,
        doc_type=req.doc_type,
    )

    return RAGIngestResponse(**result)


@router.post("/rebuild", response_model=RAGRebuildResponse)
async def rag_rebuild(
    background_tasks: BackgroundTasks,
    auth=Depends(require_admin),
):
    """Rebuild the RAG index from the database. Admin only. Runs in background."""
    if not rag_service.enabled:
        raise HTTPException(
            status_code=503,
            detail="RAG service is not available.",
        )

    # Run rebuild in background since it can take a while
    background_tasks.add_task(_do_rebuild)

    return RAGRebuildResponse(
        status="rebuilding",
        documents_ingested=0,
    )


async def _do_rebuild():
    """Background task for index rebuild."""
    await rag_service.rebuild_index()


@router.get("/documents", response_model=RAGDocumentListResponse)
async def rag_list_documents(
    offset: int = 0,
    limit: int = 20,
    doc_type: Optional[str] = None,
    client: Client = Depends(get_current_client),
):
    """List ingested documents (paginated)."""
    if not rag_service.enabled:
        return RAGDocumentListResponse(documents=[], total=0, offset=offset, limit=limit)

    result = await rag_service.list_documents(offset=offset, limit=limit, doc_type=doc_type)
    return RAGDocumentListResponse(**result)


@router.delete("/documents/{doc_group_id}", response_model=RAGDeleteResponse)
async def rag_delete_document(
    doc_group_id: str,
    auth=Depends(require_admin),
):
    """Delete a document (all chunks) by its group ID. Admin only."""
    if not rag_service.enabled:
        raise HTTPException(status_code=503, detail="RAG service is not available.")

    result = await rag_service.delete_document(doc_group_id)

    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail="Document not found")

    return RAGDeleteResponse(**result)
