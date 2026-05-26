"""
SID-Wilab Backend
API FastAPI - PostgreSQL local + JWT Auth + Route Optimization (QIGA)

Puerto: 8800
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
import logging
import os
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

from optimizer import optimize_route
from traffic_service import build_traffic_matrix, get_traffic_status
from coords_store import (
    get_client_coords, set_client_coords, get_all_coords,
    enrich_clients_with_coords, delete_client_coords
)
from database import init_db, close_db, get_db
from routers import auth_router, users_router, files_router, hr_router, messaging_router, control_procesos_router, attendance_router, notification_router, employee_portal_router, printserver_router

# Configuracion de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup
    await init_db()
    # Create uploads directories
    uploads_base = os.path.join(os.path.dirname(__file__), "uploads")
    for bucket in ("hr-documents", "messaging-evidence"):
        os.makedirs(os.path.join(uploads_base, bucket), exist_ok=True)
    logger.info("Uploads directories ready.")
    yield
    # Shutdown
    await close_db()


# Crear aplicacion FastAPI
app = FastAPI(
    title="SID-Wilab Backend",
    description="API completa: Auth, CRUD, Optimizacion de rutas (QIGA)",
    version="2.0.0",
    lifespan=lifespan,
)

# Configurar CORS - dominios permitidos desde variable de entorno
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# === AEGIS unified-feed middleware ===
# Emits one JSON line per HTTP request to /Users/alejandxr/web-logs/aegis-feed.jsonl
# so AEGIS log_watcher gets HTTP-layer visibility with real client IPs.
# Requires uvicorn to be launched with --proxy-headers --forwarded-allow-ips=127.0.0.1
# AND for the upstream proxy (web-server-logger.py) to inject X-Forwarded-For.
import json as _aegis_json
import time as _aegis_time
from datetime import datetime as _aegis_dt, timezone as _aegis_tz
_AEGIS_FEED = os.environ.get(
    "AEGIS_FEED_PATH", "/Users/alejandxr/web-logs/aegis-feed.jsonl"
)

@app.middleware("http")
async def _aegis_access_log(request, call_next):
    _start = _aegis_time.time()
    response = await call_next(request)
    try:
        _hdr = request.headers
        _src_ip = (
            _hdr.get("cf-connecting-ip")
            or (_hdr.get("x-forwarded-for") or "").split(",")[0].strip()
            or _hdr.get("x-real-ip")
            or (request.client.host if request.client else "unknown")
        )
        _now = _aegis_dt.now(_aegis_tz.utc)
        _record = {
            "ts": _now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{_now.microsecond // 1000:03d}Z",
            "app": "sid-backend",
            "src_ip": _src_ip,
            "method": request.method,
            "path": str(request.url.path) + ("?" + request.url.query if request.url.query else ""),
            "status": response.status_code,
            "rt_ms": int((_aegis_time.time() - _start) * 1000),
        }
        for _k, _hk in (
            ("ua", "user-agent"),
            ("ref", "referer"),
            ("host", "host"),
            ("country", "cf-ipcountry"),
            ("fwd_chain", "x-forwarded-for"),
            ("cf_ray", "cf-ray"),
        ):
            _v = _hdr.get(_hk)
            if _v:
                _record[_k] = _v
        with open(_AEGIS_FEED, "a", buffering=1) as _fh:
            _fh.write(_aegis_json.dumps(_record, ensure_ascii=False) + "\n")
    except Exception:
        pass  # never let logging break the request
    return response


# Include all routers
app.include_router(auth_router.router)
app.include_router(users_router.router)
app.include_router(files_router.router)
app.include_router(hr_router.router)
app.include_router(messaging_router.router)
app.include_router(control_procesos_router.router)
app.include_router(attendance_router.router)
app.include_router(notification_router.router)
app.include_router(employee_portal_router.router)
app.include_router(printserver_router.router)

# Serve static files (logo, etc.)
app.mount("/api/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


# Origen fijo: LAB Wilab
ORIGIN = {
    "name": "LAB Wilab",
    "lat": 18.4861,   # Av. San Martin 62, Santo Domingo
    "lng": -69.9312
}


# Modelos Pydantic (route optimization)
class OptimizeRequest(BaseModel):
    client_ids: List[str]

class OptimizeResponse(BaseModel):
    optimized_order: List[str]
    total_distance: float
    success: bool = True
    message: str = "Ruta optimizada exitosamente"
    used_traffic_data: bool = False

class ClientCoords(BaseModel):
    id: str
    latitude: float
    longitude: float

class GeocodeRequest(BaseModel):
    client_id: str
    latitude: float
    longitude: float

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


# Directorio de archivos estaticos
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Endpoints

@app.get("/")
async def root():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="healthy",
        service="SID-Wilab Backend",
        version="2.0.0"
    )


@app.post("/optimize", response_model=OptimizeResponse)
async def optimize_route_endpoint(request: OptimizeRequest):
    try:
        if not request.client_ids:
            return OptimizeResponse(
                optimized_order=[], total_distance=0.0,
                success=True, message="No hay clientes para optimizar", used_traffic_data=False
            )

        logger.info(f"Optimizando ruta para {len(request.client_ids)} clientes")
        all_coords = get_all_coords()
        clients = []

        for client_id in request.client_ids:
            if client_id in all_coords:
                coord_data = all_coords[client_id]
                clients.append({
                    'id': client_id,
                    'name': coord_data.get('name', 'Cliente'),
                    'latitude': coord_data.get('latitude'),
                    'longitude': coord_data.get('longitude'),
                    'address': coord_data.get('address', '')
                })
            else:
                clients.append({
                    'id': client_id,
                    'name': f'Cliente {client_id[:8]}',
                    'latitude': None, 'longitude': None
                })

        if not clients:
            return OptimizeResponse(
                optimized_order=request.client_ids, total_distance=0.0,
                success=True, message="Sin datos de clientes, usando orden original", used_traffic_data=False
            )

        clients = enrich_clients_with_coords(clients)
        time_matrix, traffic_source = await build_traffic_matrix(clients, ORIGIN)
        used_traffic = "estimacion" not in traffic_source
        optimization_result = optimize_route(ORIGIN, clients, time_matrix)
        unit = "min"

        return OptimizeResponse(
            optimized_order=optimization_result["optimized_order"],
            total_distance=optimization_result["total_distance"],
            success=True,
            message=f"Ruta optimizada: {optimization_result['total_distance']:.1f} {unit} ({traffic_source})",
            used_traffic_data=used_traffic
        )
    except Exception as e:
        logger.error(f"Error en optimizacion: {str(e)}")
        return OptimizeResponse(
            optimized_order=request.client_ids, total_distance=0.0,
            success=False, message=f"Error en optimizacion, usando orden original: {str(e)}",
            used_traffic_data=False
        )


@app.post("/geocode")
async def update_client_coordinates(request: GeocodeRequest):
    try:
        success = set_client_coords(request.client_id, request.latitude, request.longitude)
        if success:
            return {"success": True, "message": f"Coordenadas guardadas para cliente {request.client_id}"}
        return {"success": False, "message": "Error guardando coordenadas"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/clients/without-coords")
async def get_clients_without_coordinates():
    """List clients without saved coordinates. Uses local PostgreSQL."""
    try:
        from database import get_db as _get_db
        pool = await _get_db()
        rows = await pool.fetch("SELECT id, name, address, city FROM clients")
        all_clients = [dict(r) for r in rows]
        for c in all_clients:
            if c.get("id") and not isinstance(c["id"], str):
                c["id"] = str(c["id"])

        saved_coords = get_all_coords()
        without_coords = [c for c in all_clients if c.get('id') not in saved_coords]

        return {
            "count": len(without_coords),
            "clients": without_coords,
            "total_clients": len(all_clients),
            "clients_with_coords": len(saved_coords)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/coords")
async def get_saved_coordinates():
    coords = get_all_coords()
    return {"count": len(coords), "coordinates": coords}


@app.get("/origin")
async def get_origin():
    return ORIGIN


@app.get("/traffic-status")
async def get_traffic_service_status():
    return get_traffic_status()


@app.get("/here-status")
async def get_here_maps_status():
    status = get_traffic_status()
    here_configured = status["here_maps"]["configured"]
    tomtom_configured = status["tomtom"]["configured"]
    return {
        "here_maps": status["here_maps"],
        "tomtom": status["tomtom"],
        "traffic_enabled": here_configured or tomtom_configured,
        "local_estimation": status["local_estimation"],
        "message": status["recommendation"]
    }


# Punto de entrada para desarrollo
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8800, reload=True, log_level="info")
