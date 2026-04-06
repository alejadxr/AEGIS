#!/usr/bin/env bash
# AEGIS Local Setup Script
# One-command setup for macOS development
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

info()  { echo -e "${CYAN}[AEGIS]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

echo -e "${CYAN}"
echo "  ___   _   ___ ___ ___     __  "
echo " / __| /_\\ |_  ) __|_  )   / /  "
echo "| (__ / _ \\ / /| _| / / _ / _ \\ "
echo " \\___/_/ \\_\\___|___/___(_)\\___/ "
echo ""
echo "  Autonomous Defense Platform"
echo -e "${NC}"

# --- Check Python ---
info "Checking Python..."
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
        ok "Python $PY_VERSION"
    else
        fail "Python 3.11+ required (found $PY_VERSION). Install with: brew install python@3.11"
    fi
else
    fail "Python3 not found. Install with: brew install python@3.11"
fi

# --- Check Node ---
info "Checking Node.js..."
if command -v node &>/dev/null; then
    NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_VERSION" -ge 18 ]; then
        ok "Node.js $(node -v)"
    else
        fail "Node.js 18+ required (found v$NODE_VERSION). Install with: brew install node"
    fi
else
    fail "Node.js not found. Install with: brew install node"
fi

# --- Setup .env ---
info "Setting up environment..."
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
    ok "Created .env from .env.example"
    warn "Edit .env to add your OPENROUTER_API_KEY"
else
    ok ".env already exists"
fi

# Also ensure backend has .env
if [ ! -f "$PROJECT_ROOT/backend/.env" ]; then
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/backend/.env"
    ok "Created backend/.env"
fi

# --- Python Virtual Environment ---
info "Setting up Python virtual environment..."
cd "$PROJECT_ROOT/backend"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    ok "Created virtual environment"
else
    ok "Virtual environment exists"
fi

source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
ok "Backend dependencies installed"

# --- Frontend Dependencies ---
info "Installing frontend dependencies..."
cd "$PROJECT_ROOT/frontend"
if [ -f "package.json" ]; then
    npm install --silent 2>/dev/null || npm install
    ok "Frontend dependencies installed"
else
    warn "No package.json found in frontend/ - frontend agent may still be building"
fi

# --- Initialize Database ---
info "Initializing database..."
cd "$PROJECT_ROOT/backend"
source venv/bin/activate
python3 -c "
import asyncio
from app.database import engine
from app.models import Base

async def init():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print('Database tables created')

asyncio.run(init())
" 2>/dev/null && ok "Database initialized" || warn "Database init deferred (models may still be building)"

deactivate

# --- Done ---
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  AEGIS setup complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "  Start development:"
echo "    ./scripts/dev.sh"
echo ""
echo "  Seed demo data:"
echo "    cd backend && source venv/bin/activate"
echo "    cd .. && python scripts/seed.py"
echo ""
echo "  URLs:"
echo "    Backend API:  http://localhost:8000"
echo "    Frontend:     http://localhost:3000"
echo "    API Docs:     http://localhost:8000/docs"
echo ""
