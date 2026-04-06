# ============================================================
# Cayde-6 Backend - Multi-stage Docker build
# ============================================================

# --- Stage 1: Builder (install deps, compile wheels) ---
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build-time system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Stage 2: Runtime ---
FROM python:3.12-slim AS runtime

LABEL maintainer="Wilab <admin@somoswilab.com>"
LABEL description="Cayde-6 Autonomous Defense Platform - API"
LABEL version="1.0.0"

WORKDIR /app

# Install runtime system deps (nmap for scanning, curl for healthcheck, libpq for postgres)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r cayde6 && useradd -r -g cayde6 -d /app -s /sbin/nologin cayde6

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY ./app ./app

# Create data directory for SQLite fallback
RUN mkdir -p /app/data && chown -R cayde6:cayde6 /app

USER cayde6

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
