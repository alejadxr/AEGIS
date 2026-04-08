"""Generate AEGIS complete architecture diagram."""
from PIL import Image, ImageDraw, ImageFont
import math

W, H = 1800, 2200
img = Image.new("RGB", (W, H), (8, 9, 10))
draw = ImageDraw.Draw(img)

try:
    title_font = ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", 36)
    heading_font = ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", 20)
    body_font = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 14)
    small_font = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 12)
    label_font = ImageFont.truetype("C:/Windows/Fonts/calibrib.ttf", 13)
except Exception:
    title_font = ImageFont.load_default()
    heading_font = title_font
    body_font = title_font
    small_font = title_font
    label_font = title_font

cyan = (34, 211, 238)
orange = (249, 115, 22)
green = (52, 211, 153)
red = (248, 113, 113)
purple = (167, 139, 250)
amber = (251, 191, 36)
white = (247, 248, 248)
muted = (138, 143, 152)
dim = (82, 82, 91)
surface = (17, 17, 20)
border = (39, 39, 42)


def box(x, y, w, h, color, title_text, items=None, accent=None):
    draw.rounded_rectangle([x, y, x + w, y + h], radius=10, fill=surface, outline=color, width=1)
    if accent:
        draw.rectangle([x + 1, y + 1, x + w - 1, y + 4], fill=accent)
    draw.text((x + 14, y + 10), title_text, fill=color, font=heading_font)
    if items:
        for i, item in enumerate(items):
            draw.text((x + 14, y + 38 + i * 18), item, fill=muted, font=body_font)


def section(y, text):
    draw.text((60, y), text, fill=dim, font=small_font)


# TITLE
draw.text((W // 2 - 180, 20), "AEGIS v1.1.0", fill=cyan, font=title_font)
draw.text((W // 2 - 260, 65), "Complete Architecture Diagram", fill=muted, font=heading_font)
draw.line([(80, 100), (W - 80, 100)], fill=border, width=1)

# === ROW 1: CLIENTS ===
section(110, "CLIENT LAYER")
box(60, 130, 270, 115, cyan, "Dashboard", ["16 pages + WebSocket", "Tailwind + Recharts", "Light/Dark theme", "Real-time threat map"])
box(350, 130, 270, 115, cyan, "Setup Wizard", ["7-step onboarding", "AI scan + honeypot picker", "Upgrade modals", "Skip links"])
box(640, 130, 270, 115, purple, "Desktop Manager", ["Tauri v2 native app", "Connects to server", "Embedded Rust agent", "Win + macOS"])
box(930, 130, 270, 115, purple, "Node Agent", ["EDR ~7MB installer", "Process/registry/FIM", "Network + LOTL detect", "30s heartbeat"])
box(1220, 130, 270, 115, orange, "Landing Page", ["GitHub Pages", "JSON-LD + FAQ (GEO)", "OG image + favicon", "Funnel optimized"])
box(1510, 130, 230, 115, green, "PayPal", ["Create order", "Capture payment", "Tier upgrade"])

# === ROW 2: API GATEWAY ===
section(260, "API GATEWAY")
draw.rounded_rectangle([60, 280, W - 60, 355], radius=10, fill=surface, outline=cyan, width=2)
draw.text((80, 290), "FastAPI Backend  |  Port 8000  |  140+ endpoints  |  21 routers", fill=cyan, font=heading_font)
draw.text((80, 318), "Attack Detector (18us)  |  JWT+API Key Auth  |  Rate Limiting (slowapi)  |  CORS  |  Audit Log", fill=muted, font=body_font)
draw.text((80, 338), "Breadcrumb Detection  |  Auto-block 3 strikes  |  Safe IPs whitelist  |  RBAC (admin/analyst/viewer)", fill=orange, font=body_font)

# === ROW 3: CORE MODULES ===
section(370, "CORE MODULES")
box(60, 390, 310, 155, green, "Surface (ASM)", [
    "Asset discovery (nmap -sV)", "Vulnerability scan (Nuclei)",
    "SBOM analysis [PRO]", "AI risk scoring",
    "Scheduled scans", "Hardening checks"], accent=green)
box(390, 390, 310, 155, red, "Response (SOAR)", [
    "AI triage (2-5s full)", "Fast path <300ms (no AI)",
    "10 playbooks", "Guardrails system",
    "Dual-layer blocking", "Audit trail"], accent=red)
box(720, 390, 310, 155, orange, "Phantom (Deception)", [
    "SSH honeypot (2222)", "HTTP honeypot (8888)",
    "Smart HTTP mimic [PRO]", "Smart API mimic [PRO]",
    "Smart DB mimic [PRO]", "Breadcrumbs + profiler"], accent=orange)
box(1050, 390, 310, 155, amber, "Threats (TIP)", [
    "5 threat feeds", "STIX 2.1 export",
    "Intel Cloud hub", "Campaign tracking",
    "IOC database", "Community sharing"], accent=amber)
box(1380, 390, 360, 155, purple, "Quantum [PRO/ENT]", [
    "Renyi entropy (C2 detect)", "Grover calculator",
    "Adversarial ML [ENT]", "Steganography detect",
    "Post-quantum assessment", "Readiness score (all tiers)"], accent=purple)

# === ROW 4: AI + DETECTION ===
section(560, "AI + DETECTION ENGINE")
box(60, 580, 410, 135, cyan, "AI Engine (13 model routes)", [
    "OpenRouter / Ollama / OpenAI / Anthropic",
    "Triage > Classify > Decide > Execute > Verify",
    "Counter-attack AI (uncensored model)",
    "Cost tracking per query"])
box(490, 580, 410, 135, green, "Correlation Engine", [
    "122 Sigma rules + 5 chain rules",
    "Campaign tracker (recon>exploit>persist>exfil)",
    "10K event sliding window",
    "Group-by aggregation + time windows"])
box(920, 580, 410, 135, amber, "Behavioral ML", [
    "Isolation Forest anomaly detection",
    "User/host baselining",
    "Drift detection + auto-retrain",
    "Confidence scoring"])
box(1350, 580, 390, 135, red, "Log Watcher + Scanner", [
    "PM2/syslog real-time tail",
    "7 security patterns",
    "Brute force + rate limiting",
    "nmap/nuclei subprocess"])

# === ROW 5: SERVICES ===
section(730, "BACKGROUND SERVICES (15)")
svcs = [
    ("Scheduler", green), ("Notifier", amber), ("Firewall Sync", red),
    ("Intel Hub", cyan), ("Report Gen", purple), ("RAG Service", green),
    ("Playbook Engine", red), ("Subscription", orange),
]
sx = 60
for name, color in svcs:
    draw.rounded_rectangle([sx, 755, sx + 200, 790], radius=6, fill=surface, outline=color)
    draw.text((sx + 10, 762), name, fill=white, font=label_font)
    sx += 210

# === ROW 6: DATA LAYER ===
section(805, "DATA LAYER")
box(60, 825, 400, 135, cyan, "PostgreSQL 16", [
    "14 models (async SQLAlchemy)",
    "clients, users, assets, incidents",
    "honeypots, attacker_profiles, audit_log",
    "Pool: 20 + overflow 10"])
box(480, 825, 350, 135, red, "Redis 7", [
    "Event bus (pub/sub)",
    "Rate limit counters (slowapi)",
    "WebSocket push state",
    "Background job queue"])
box(850, 825, 380, 135, amber, "MongoDB Atlas (optional)", [
    "Shared threat intel hub",
    "aegis_threats collection",
    "external_feeds collection",
    "Opt-in community IOC sharing"])
box(1250, 825, 340, 135, green, "File System", [
    "Sigma rules (YAML)",
    "PDF reports", "blocked_ips.txt",
    "Honeypot templates"])

# === ROW 7: SECURITY ===
section(975, "SECURITY + AUTH")
box(60, 995, 520, 110, red, "Authentication + RBAC", [
    "JWT (HS256) + issuer/audience validation  |  API Key (X-API-Key)",
    "Roles: admin / analyst / viewer  |  24h token expiry",
    "Audit on: login, signup, settings, actions, honeypot deploy"])
box(600, 995, 520, 110, orange, "Rate Limiting + Validation", [
    "slowapi: signup 5/min, login 10/min, discover 3/min, agents 20/min",
    "Pydantic constraints + regex patterns + max lengths",
    "Honeypot config whitelist  |  SQL injection safe (ORM)"])
box(1140, 995, 400, 110, green, "Secrets + Hardening", [
    "Startup warning if default key",
    "Zero secrets in git (verified)",
    "HTTPS ready  |  CORS configured"])

# === ROW 8: DETECTION PIPELINE ===
section(1120, "5-LAYER DETECTION PIPELINE")
layers = [
    ("L1", "Attack Detector", "18us regex + decode", cyan),
    ("L2", "Log Watcher", "PM2/syslog patterns", green),
    ("L3", "Sigma Engine", "122 rules + chains", amber),
    ("L4", "AI Triage", "Classify + MITRE", purple),
    ("L5", "Auto-Response", "Playbooks + guard", red),
]
lx = 60
for code, name, desc, color in layers:
    w = 320
    draw.rounded_rectangle([lx, 1145, lx + w, 1200], radius=8, fill=surface, outline=color, width=2)
    draw.text((lx + 12, 1150), code, fill=color, font=heading_font)
    draw.text((lx + 48, 1150), name, fill=white, font=label_font)
    draw.text((lx + 12, 1175), desc, fill=muted, font=small_font)
    if lx + w + 20 < W - 100:
        draw.text((lx + w + 5, 1165), ">", fill=color, font=heading_font)
    lx += 340

# === ROW 9: TIERS ===
section(1220, "PRICING TIERS")
box(60, 1245, 530, 170, green, "FREE - $0", [
    "Full 5-layer detection (18us)", "122 Sigma rules + 10 playbooks",
    "SSH + HTTP honeypots + breadcrumbs", "Counter-attack AI + threat intel sharing",
    "Behavioral ML + dashboard + RBAC", "AI triage (free models via OpenRouter)",
    "3 nodes | 25 assets | 3 users"], accent=green)
box(620, 1245, 530, 170, cyan, "PRO - $29/mo per node", [
    "Everything in Free +",
    "Smart Honeypots (HTTP/API/DB mimics)", "Quantum entropy + Grover calculator",
    "SBOM scanner", "Advanced PDF reports",
    "Priority threat feeds",
    "25 nodes | 500 assets | 15 users"], accent=cyan)
box(1180, 1245, 530, 170, purple, "ENTERPRISE - $99/mo per node", [
    "Everything in Pro +",
    "Adversarial ML detection", "Compliance dashboard (ISO/NIS2/SOC2)",
    "SSO (SAML/OIDC)", "Custom Sigma rules",
    "SLA + dedicated support",
    "Unlimited"], accent=purple)

# === ROW 10: DEPLOY ===
section(1435, "DEPLOYMENT OPTIONS")
box(60, 1460, 530, 100, cyan, "Docker Compose (recommended)", [
    "docker compose up -d  |  aegis-api + frontend + PostgreSQL + Redis",
    "Zero-config with .env.example  |  Health checks included"])
box(620, 1460, 530, 100, green, "Manual / PM2", [
    "pip install + uvicorn  |  npm build + next start",
    "Bring your own PostgreSQL  |  PM2 process management"])
box(1180, 1460, 530, 100, orange, "Node Agent", [
    "Tauri .msi/.dmg installer  |  Enrollment code C6-XXXX",
    "30s heartbeat + hourly auto-scan  |  System tray"])

# === STATS BAR ===
draw.rectangle([(0, H - 55), (W, H)], fill=(11, 12, 14))
draw.line([(0, H - 55), (W, H - 55)], fill=border)
stats = [
    ("140+", "ENDPOINTS"), ("21", "ROUTERS"), ("14", "MODELS"),
    ("16", "PAGES"), ("122", "SIGMA"), ("15", "SERVICES"),
    ("11/11", "DETECTION"), ("18us", "RESPONSE"),
]
stx = 80
for val, lbl in stats:
    draw.text((stx, H - 48), val, fill=white, font=label_font)
    draw.text((stx, H - 30), lbl, fill=dim, font=small_font)
    stx += 205

# Corner brackets
bc = (34, 211, 238)
for cx, cy in [(30, 30), (W - 30, 30), (30, H - 30), (W - 30, H - 30)]:
    dx = 1 if cx < W // 2 else -1
    dy = 1 if cy < H // 2 else -1
    draw.line([(cx, cy), (cx + 25 * dx, cy)], fill=bc, width=2)
    draw.line([(cx, cy), (cx, cy + 25 * dy)], fill=bc, width=2)

out = "C:/Users/wilsd/RemoteProjects/Laboratorio/Cayde-6/docs/aegis-architecture.png"
img.save(out, "PNG", optimize=True)
print(f"Done: {out}")
