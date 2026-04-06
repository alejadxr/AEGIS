#!/usr/bin/env bash
# AEGIS Development Server
# Starts backend and frontend in parallel
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CYAN='\033[0;36m'
NC='\033[0m'

cleanup() {
    echo ""
    echo "Shutting down AEGIS..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    wait $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    echo "Stopped."
}
trap cleanup EXIT INT TERM

echo -e "${CYAN}[AEGIS]${NC} Starting development servers..."

# Start backend
cd "$PROJECT_ROOT/backend"
if [ ! -d "venv" ]; then
    echo "Run ./scripts/setup.sh first"
    exit 1
fi
source venv/bin/activate
echo -e "${CYAN}[BACKEND]${NC} http://localhost:8000"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Start frontend
cd "$PROJECT_ROOT/frontend"
if [ -f "package.json" ]; then
    echo -e "${CYAN}[FRONTEND]${NC} http://localhost:3000"
    npm run dev &
    FRONTEND_PID=$!
else
    echo "[WARN] No package.json in frontend/ - skipping frontend"
    FRONTEND_PID=$$
fi

echo ""
echo -e "${CYAN}[AEGIS]${NC} Both servers running. Press Ctrl+C to stop."
echo ""

wait
