import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings
from app.database import engine, async_session
from app.models import Base
from app.core.auth import seed_demo_client, seed_default_admin
from app.core.events import event_bus
from app.core.event_stream import EventStream
from app.core.ws_push import ws_push_manager
from app.core.openrouter import openrouter_client
from app.services.notifier import notifier
from app.services.correlation_engine import correlation_engine
from app.services.counter_attack import counter_attack_engine
from app.services.threat_feeds import threat_feed_manager
from app.services.report_scheduler import report_scheduler
from app.services.playbook_engine import playbook_engine
from app.services.intel_cloud import intel_cloud
from app.services.behavioral_ml import behavioral_engine
from app.core.ai_manager import ai_manager, init_default_providers
from app.models.client import Client

from app.modules.response.responder import active_responder
from app.modules.phantom.ssh_honeypot import ssh_honeypot
from app.modules.phantom.http_honeypot import http_honeypot
from app.modules.phantom.processor import interaction_processor
from app.models.action import Action
from app.services.log_watcher import log_watcher

from app.api import auth, dashboard, surface, response, phantom, threats, correlation, admin
from app.api import feeds, reports, ai_providers as ai_providers_router
from app.api import ask_ai as ask_ai_router
from app.api import intel_cloud as intel_cloud_router
from app.api import behavioral as behavioral_router
from app.api import network as network_router
from app.api import setup as setup_router
from app.api import settings as settings_router
from app.api import agents as agents_router
from app.api import infra as infra_router
from app.api import nodes as nodes_router
from app.api import sbom as sbom_router
from app.api import quantum as quantum_router
from app.api import onboarding as onboarding_router
from app.api import payments as payments_router
from app.api import compliance as compliance_router
from app.api import updates as updates_router
from app.api import firewall as firewall_router
from app.api import ransomware as ransomware_router
from app.api import deception as deception_router
from app.api import edr as edr_router
from app.api import antivirus as antivirus_router
from app.services.signature_updater import signature_updater

# MongoDB threat intel hub
from app.core.mongo_client import connect_mongo, close_mongo
from app.services.threat_intel_hub import threat_intel_hub
from app.api import threat_intel_hub as threat_intel_hub_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("cayde6")


# --- Event Stream (Redis or in-memory) ---

event_stream = EventStream(
    redis_url=settings.REDIS_URL,
    use_redis=not settings.USE_MEMORY_BUS,
)


# --- WebSocket push handler (replaces old ConnectionManager) ---

# Map internal event_bus event names to Live-dashboard topic names.
# Multiple topics per event are allowed so a single incident event
# can fan out to several widgets at once (e.g. attack feed AND top-10 refresh).
EVENT_TO_TOPICS: dict[str, tuple[str, ...]] = {
    "alert_processed": ("incidents.new", "metrics.top_attackers", "metrics.top_attack_types"),
    "correlation_triggered": ("incidents.new",),
    "fast_triage_completed": ("incidents.new",),
    "playbook_executed": ("incidents.new",),
    "action_executed": ("actions.new", "metrics.blocked"),
    "action_requires_approval": ("actions.new",),
    "honeypot_interaction": ("honeypot.interactions", "attackers.geo"),
    "honeypot_deployed": ("honeypot.status",),
    "scan_completed": ("scans.completed",),
    "node_status": ("nodes.status",),
    "log_line": ("logs.stream",),
}


async def ws_event_handler(data):
    """Forward events to WebSocket clients via WSPushManager with topic routing."""
    payload = data if isinstance(data, dict) else {"data": data}
    event_type = payload.get("_event_type") or payload.get("type") or "event"
    topics = EVENT_TO_TOPICS.get(event_type, (event_type,))
    # Emit one broadcast per topic so each widget-subscriber gets a clean,
    # topic-tagged message.
    for topic in topics:
        msg = {**payload, "topic": topic, "_event_type": event_type}
        await ws_push_manager.broadcast(msg)


async def _get_client(client_id: str | None) -> Client | None:
    if not client_id:
        return None
    async with async_session() as db:
        return await db.get(Client, client_id)


async def notify_alert_processed(data):
    client = await _get_client(data.get("client_id"))
    if not client:
        return
    severity = (data.get("incident_severity") or "").lower()
    settings_map = client.settings or {}
    notify_critical = settings_map.get("notify_on_critical", True)
    notify_high = settings_map.get("notify_on_high", True)

    if severity == "critical" and notify_critical:
        await notifier.notify(client, {
            "platform": "Cayde-6",
            "event_type": "incident_critical",
            "title": data.get("incident_title", "Critical incident"),
            "severity": severity,
            "incident_id": data.get("incident_id"),
            "message": data.get("summary") or "Critical incident detected.",
            "source_ip": data.get("source_ip"),
        })
    elif severity == "high" and notify_high:
        await notifier.notify(client, {
            "platform": "Cayde-6",
            "event_type": "incident_high",
            "title": data.get("incident_title", "High severity incident"),
            "severity": severity,
            "incident_id": data.get("incident_id"),
            "message": data.get("summary") or "High severity incident detected.",
            "source_ip": data.get("source_ip"),
        })


async def notify_action_executed(data):
    client = await _get_client(data.get("client_id"))
    if not client:
        return
    settings_map = client.settings or {}
    if not settings_map.get("notify_on_actions", True):
        return
    await notifier.notify(client, {
        "platform": "Cayde-6",
        "event_type": "action_executed",
        "title": "Action executed",
        "incident_id": data.get("incident_id"),
        "action_type": data.get("action_type"),
        "target": data.get("target"),
        "message": f"Action '{data.get('action_type')}' executed on '{data.get('target')}'.",
    })


async def handle_auto_approved_action(data):
    """Fetch auto-approved Action from DB and execute it immediately."""
    action_id = data.get("action_id")
    if not action_id:
        logger.error("action_auto_approved event missing action_id")
        return
    try:
        async with async_session() as db:
            action = await db.get(Action, action_id)
            if not action:
                logger.error(f"Action {action_id} not found for auto-execution")
                return
            if action.status != "approved":
                logger.warning(f"Action {action_id} status is '{action.status}', skipping auto-execution")
                return
            logger.info(f"AUTO-EXECUTING action {action.action_type} on {action.target}")
            result = await active_responder.execute_action(action, db)
            logger.info(f"Auto-execution result for {action_id}: success={result.get('success')}")
    except Exception as e:
        logger.error(f"Auto-execution failed for action {action_id}: {e}")


async def notify_action_requires_approval(data):
    client = await _get_client(data.get("client_id"))
    if not client:
        return
    settings_map = client.settings or {}
    if not settings_map.get("notify_on_actions", True):
        return
    await notifier.notify(client, {
        "platform": "Cayde-6",
        "event_type": "action_requires_approval",
        "title": "Action approval required",
        "incident_id": data.get("incident_id"),
        "action_type": data.get("action_type"),
        "target": data.get("target"),
        "message": f"Action '{data.get('action_type')}' on '{data.get('target')}' requires approval.",
    })


# --- Lifespan ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Cayde-6 starting up...")

    # --- Secret key check ---
    if (
        settings.AEGIS_SECRET_KEY == "aegis-dev-secret-key-change-in-production"
        and settings.AEGIS_ENV != "development"
    ):
        logger.critical(
            "!!! AEGIS_SECRET_KEY is still the default value. "
            "Set a strong random key via AEGIS_SECRET_KEY env var before running in production. !!!"
        )

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created")

    # Seed demo client and default admin user
    async with async_session() as db:
        demo = await seed_demo_client(db)
        logger.info(f"Demo client ready: slug='{demo.slug}' api_key='{demo.api_key}'")
        await seed_default_admin(db, demo)
        logger.info("Default admin user seeded (admin@cayde6.local)")

    # Auto-discover localhost services on every startup.
    # Uses upsert logic: updates existing assets, creates new ones.
    # Runs in background so it never blocks startup.
    async def _auto_discover_localhost(client_id: str):
        try:
            from sqlalchemy import select as _sel
            from app.models.asset import Asset
            from app.services.auto_discovery import auto_discovery
            from datetime import datetime

            logger.info("Running localhost auto-discovery (upsert mode)...")
            result = await auto_discovery.discover_host("127.0.0.1")

            if result.error:
                logger.warning(f"Auto-discovery error: {result.error}")
                return

            created = 0
            updated = 0
            async with async_session() as db:
                # Load all existing assets for this client+IP for matching
                existing_result = await db.execute(
                    _sel(Asset).where(
                        Asset.client_id == client_id,
                        Asset.ip_address == "127.0.0.1",
                    )
                )
                existing_assets = list(existing_result.scalars().all())

                for host in result.hosts:
                    for svc in host.services:
                        # Match: find existing asset with same IP that has this port
                        matched_asset = None
                        for asset in existing_assets:
                            asset_ports = asset.ports or []
                            for p in asset_ports:
                                if isinstance(p, dict) and p.get("port") == svc.port:
                                    matched_asset = asset
                                    break
                            if matched_asset:
                                break

                        port_data = [{"port": svc.port, "protocol": svc.protocol, "service": svc.service}]
                        risk = round(float(svc.risk_estimate) / 10.0, 1)

                        if matched_asset:
                            # Update existing asset with fresh scan data
                            matched_asset.hostname = svc.hostname
                            matched_asset.asset_type = svc.asset_type
                            matched_asset.ports = port_data
                            matched_asset.technologies = svc.technologies
                            matched_asset.risk_score = risk
                            matched_asset.last_scan_at = datetime.utcnow()
                            updated += 1
                        else:
                            # Create new asset
                            asset = Asset(
                                client_id=client_id,
                                hostname=svc.hostname,
                                ip_address=host.ip,
                                asset_type=svc.asset_type,
                                ports=port_data,
                                technologies=svc.technologies,
                                status="active",
                                risk_score=risk,
                                last_scan_at=datetime.utcnow(),
                            )
                            db.add(asset)
                            created += 1

                await db.commit()
            logger.info(f"Auto-discovery complete: {created} created, {updated} updated")
        except Exception as e:
            logger.error(f"Auto-discovery failed (non-fatal): {e}")

    asyncio.create_task(_auto_discover_localhost(demo.id))

    # Start event stream (Redis or in-memory)
    await event_stream.start()
    logger.info(f"Event stream started (backend={'redis' if event_stream.is_redis else 'memory'})")

    # Wire event stream to event bus for dual publishing
    event_bus.set_event_stream(event_stream)

    # Start event bus
    await event_bus.start()
    event_bus.subscribe("alert_processed", ws_event_handler)
    event_bus.subscribe("scan_completed", ws_event_handler)
    event_bus.subscribe("action_executed", ws_event_handler)
    event_bus.subscribe("action_requires_approval", ws_event_handler)
    event_bus.subscribe("honeypot_deployed", ws_event_handler)
    event_bus.subscribe("honeypot_interaction", ws_event_handler)
    event_bus.subscribe("correlation_triggered", ws_event_handler)
    event_bus.subscribe("agent_registered", ws_event_handler)
    event_bus.subscribe("agent_alert", ws_event_handler)
    event_bus.subscribe("forensic_captured", ws_event_handler)
    event_bus.subscribe("fast_triage_completed", ws_event_handler)
    event_bus.subscribe("playbook_executed", ws_event_handler)
    event_bus.subscribe("alert_processed", notify_alert_processed)
    event_bus.subscribe("action_executed", notify_action_executed)
    event_bus.subscribe("action_requires_approval", notify_action_requires_approval)
    event_bus.subscribe("action_auto_approved", handle_auto_approved_action)
    event_bus.subscribe("action_auto_approved", ws_event_handler)
    event_bus.subscribe("log_line", ws_event_handler)
    logger.info("Event bus started with WebSocket forwarding + auto-execution wired")

    # Start counter-attack engine (active defense)
    counter_attack_engine.register_event_bus()
    event_bus.subscribe("counter_attack_analysis", ws_event_handler)
    event_bus.subscribe("counter_attack_executed", ws_event_handler)
    logger.info("Counter-attack engine registered (active defense)")

    # Start playbook engine
    playbook_engine.register_event_bus(event_bus)
    logger.info("Playbook engine registered with event bus")

    # Start correlation engine
    correlation_engine.register_event_bus(event_bus)
    await correlation_engine.start()
    logger.info("Sigma correlation engine started (with chain rules)")

    # Start threat feeds
    await threat_feed_manager.start()
    logger.info("Threat feed manager started")

    # Start report scheduler
    report_scheduler.start()
    logger.info("Report scheduler started")

    # Init multi-provider AI
    init_default_providers(
        openrouter_api_key=settings.OPENROUTER_API_KEY,
        openrouter_base_url=settings.OPENROUTER_BASE_URL,
    )
    openrouter_client.bind_ai_manager(ai_manager)
    logger.info("Multi-provider AI manager initialized")

    # Start intel cloud
    await intel_cloud.start()
    logger.info("Threat intel cloud started")

    # Start behavioral ML
    await behavioral_engine.start()
    logger.info("Behavioral ML engine started")

    # Task #6: Start antivirus signature updater (daily YARA + MalwareBazaar pull)
    await signature_updater.start()
    logger.info("Antivirus signature updater started")

    # Start MongoDB threat intel hub (conditional on AEGIS_MONGODB_URI)
    mongo_ok = await connect_mongo()
    if mongo_ok:
        await threat_intel_hub.start()
        logger.info("MongoDB threat intel hub started")
    else:
        logger.info("MongoDB not configured - threat intel hub disabled")

    logger.info(f"Cayde-6 ready on port {settings.AEGIS_API_PORT}")

    # Prime configurable firewall rule cache for all tenants
    try:
        from sqlalchemy import select as _sa_select
        from app.services.firewall_engine import firewall_engine
        async with async_session() as db:
            result = await db.execute(_sa_select(Client).limit(50))
            for c in result.scalars().all():
                try:
                    await firewall_engine.load_rules(c.id, force=True)
                except Exception as exc:
                    logger.debug(f"firewall_engine warm for {c.id} failed: {exc}")
        logger.info("Configurable firewall rule cache primed")
    except Exception as e:
        logger.error(f"Failed to prime firewall engine cache: {e}")

    # Start honeypots (SSH on 2222, HTTP on 8888)
    honeypot_queue = asyncio.Queue()
    try:
        await ssh_honeypot.start(honeypot_queue)
        logger.info('SSH honeypot started on port 2222')
    except Exception as e:
        logger.error(f'Failed to start SSH honeypot: {e}')
    try:
        await http_honeypot.start(honeypot_queue)
        logger.info('HTTP honeypot started on port 8888')
    except Exception as e:
        logger.error(f'Failed to start HTTP honeypot: {e}')
    await interaction_processor.start(honeypot_queue)
    logger.info('Honeypot interaction processor started')

    # Start log watcher (tails PM2 logs for security patterns + feeds Raw Log Stream)
    await log_watcher.start()
    logger.info('Log watcher started')

    # Start auto-updater (background GitHub release checker)
    try:
        from app.services.auto_updater import auto_updater
        await auto_updater.start()
    except Exception as e:
        logger.error(f'Failed to start auto-updater: {e}')

    yield

    # Shutdown
    try:
        from app.services.auto_updater import auto_updater
        await auto_updater.stop()
    except Exception:
        pass
    await log_watcher.stop()
    await behavioral_engine.stop()
    await threat_intel_hub.stop()
    await close_mongo()
    await intel_cloud.stop()
    report_scheduler.stop()
    await threat_feed_manager.stop()
    await event_bus.stop()
    await event_stream.stop()
    await openrouter_client.close()
    await interaction_processor.stop()
    await ssh_honeypot.stop()
    await http_honeypot.stop()
    await engine.dispose()
    logger.info("Cayde-6 shut down")


# --- App ---

# --- Rate limiter (shared instance used by route decorators) ---
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Cayde-6 Defense Platform",
    description="AI-powered autonomous cybersecurity defense platform",
    version="1.1.0",
    lifespan=lifespan,
)

# Attach limiter to app state so route files can import it
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attack detection middleware (runs before every request)
from app.core.attack_detector import AttackDetectorMiddleware
app.add_middleware(AttackDetectorMiddleware)

# Register API routes
app.include_router(auth.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(surface.router, prefix="/api/v1")
app.include_router(response.router, prefix="/api/v1")
app.include_router(phantom.router, prefix="/api/v1")
app.include_router(threats.router, prefix="/api/v1")
app.include_router(settings_router.router, prefix="/api/v1")
app.include_router(correlation.router, prefix="/api/v1")
app.include_router(feeds.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")
app.include_router(ai_providers_router.router, prefix="/api/v1")
app.include_router(ask_ai_router.router)
app.include_router(agents_router.router, prefix="/api/v1")
app.include_router(intel_cloud_router.router, prefix="/api/v1")
app.include_router(behavioral_router.router, prefix="/api/v1")
app.include_router(network_router.router, prefix="/api/v1")
app.include_router(setup_router.router, prefix="/api/v1")
app.include_router(infra_router.router, prefix="/api/v1")
app.include_router(nodes_router.router, prefix="/api/v1")
app.include_router(sbom_router.router, prefix="/api/v1")
app.include_router(quantum_router.router, prefix="/api/v1")
app.include_router(onboarding_router.router, prefix="/api/v1")
app.include_router(payments_router.router, prefix="/api/v1")
app.include_router(compliance_router.router, prefix="/api/v1")
app.include_router(updates_router.router, prefix="/api/v1")
app.include_router(firewall_router.router, prefix="/api/v1")
app.include_router(ransomware_router.router, prefix="/api/v1")
app.include_router(deception_router.router, prefix="/api/v1")
app.include_router(edr_router.router, prefix="/api/v1")
app.include_router(antivirus_router.router, prefix="/api/v1")
app.include_router(threat_intel_hub_router.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")


# --- WebSocket endpoint (enhanced with WSPushManager) ---

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Accept query param for client identification
    client_id = websocket.query_params.get("client_id", "anonymous")
    ws_client = await ws_push_manager.connect(websocket, client_id)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                elif msg.get("type") == "set_filters":
                    ws_push_manager.set_filters(ws_client, msg.get("filters", {}))
                    await websocket.send_json({"type": "filters_updated", "filters": msg.get("filters", {})})
                elif msg.get("type") == "subscribe":
                    # Topic subscription — supports "topics" (preferred) or "event_types" (legacy)
                    new_topics = msg.get("topics") or msg.get("event_types") or []
                    ws_push_manager.subscribe_topics(ws_client, new_topics)
                    await websocket.send_json({
                        "type": "subscribed",
                        "topics": sorted(ws_client.topics),
                    })
                elif msg.get("type") == "unsubscribe":
                    rm_topics = msg.get("topics") or msg.get("event_types") or []
                    ws_push_manager.unsubscribe_topics(ws_client, rm_topics)
                    await websocket.send_json({
                        "type": "unsubscribed",
                        "topics": sorted(ws_client.topics),
                    })
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_push_manager.disconnect(ws_client)


# --- Health endpoint ---

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "cayde-6",
        "version": "1.0.0",
        "environment": settings.AEGIS_ENV,
    }


@app.get("/api/v1/health")
async def api_health():
    return {
        "status": "healthy",
        "service": "cayde-6",
        "version": "1.0.0",
    }


# --- Pipeline stats endpoint ---

@app.get("/api/v1/pipeline/stats")
async def pipeline_stats():
    from app.services.ai_engine import ai_engine
    return {
        "event_bus": event_bus.stats(),
        "event_stream": event_stream.stats(),
        "ws_push": ws_push_manager.stats(),
        "correlation": correlation_engine.stats(),
        "playbook": playbook_engine.stats(),
        "fast_triage": ai_engine.fast_triage_stats(),
    }
