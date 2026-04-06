# ============================================================================
# AEGIS Autonomous Defense Platform - Windows Installer
# ============================================================================
# Usage:
#   powershell -ExecutionPolicy Bypass -File install-windows.ps1
#   powershell -ExecutionPolicy Bypass -File install-windows.ps1 -SkipDocker
#
# Prerequisites:
#   - Docker Desktop (or use -SkipDocker for native Python mode)
#   - Python 3.11+ (for native mode or agent install)
#   - nmap (optional, for scanning features)
# ============================================================================

param(
    [switch]$SkipDocker,
    [string]$ApiPort = "8000",
    [string]$FrontendPort = "3000",
    [string]$PostgresPort = "5432",
    [string]$PostgresPassword = "",
    [string]$JwtSecret = "",
    [string]$OpenRouterApiKey = "",
    [string]$InstallDir = "C:\Aegis"
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Banner {
    Write-Host ""
    Write-Host "  ========================================" -ForegroundColor Cyan
    Write-Host "   AEGIS Autonomous Defense Platform" -ForegroundColor Cyan
    Write-Host "   Windows Installer v1.0" -ForegroundColor Cyan
    Write-Host "  ========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "[aegis] " -ForegroundColor Cyan -NoNewline
    Write-Host $Message
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[aegis] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[aegis] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Err {
    param([string]$Message)
    Write-Host "[aegis] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Generate-Secret {
    param([int]$Length = 32)
    $bytes = New-Object byte[] $Length
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToBase64String($bytes).Substring(0, $Length)
}

function Test-CommandExists {
    param([string]$Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
function Test-Prerequisites {
    Write-Step "Checking prerequisites..."
    $allGood = $true

    # Python
    if (Test-CommandExists "python") {
        $pyVersion = python --version 2>&1
        Write-Ok "Python found: $pyVersion"
    }
    elseif (Test-CommandExists "python3") {
        $pyVersion = python3 --version 2>&1
        Write-Ok "Python found: $pyVersion"
    }
    else {
        Write-Warn "Python not found. Install from https://python.org or via: winget install Python.Python.3.12"
        $allGood = $false
    }

    # Docker (unless skipped)
    if (-not $SkipDocker) {
        if (Test-CommandExists "docker") {
            $dockerVersion = docker --version 2>&1
            Write-Ok "Docker found: $dockerVersion"

            # Check if Docker daemon is running
            $dockerInfo = docker info 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warn "Docker daemon is not running. Start Docker Desktop first."
                $allGood = $false
            }
        }
        else {
            Write-Warn "Docker not found. Install Docker Desktop or use -SkipDocker flag."
            Write-Warn "  Download: https://docs.docker.com/desktop/install/windows-install/"
            Write-Warn "  Or: winget install Docker.DockerDesktop"
            $allGood = $false
        }
    }

    # nmap (optional)
    if (Test-CommandExists "nmap") {
        $nmapVersion = nmap --version 2>&1 | Select-Object -First 1
        Write-Ok "nmap found: $nmapVersion"
    }
    else {
        Write-Warn "nmap not found (optional). Install via: winget install Insecure.Nmap"
    }

    # Git (optional but helpful)
    if (Test-CommandExists "git") {
        Write-Ok "git found"
    }
    else {
        Write-Warn "git not found (optional). Install via: winget install Git.Git"
    }

    return $allGood
}

# ---------------------------------------------------------------------------
# Generate secrets and .env
# ---------------------------------------------------------------------------
function New-EnvFile {
    param([string]$Path)

    Write-Step "Generating configuration..."

    if ([string]::IsNullOrEmpty($PostgresPassword)) {
        $PostgresPassword = Generate-Secret -Length 24
    }
    if ([string]::IsNullOrEmpty($JwtSecret)) {
        $JwtSecret = Generate-Secret -Length 48
    }

    $apiKey = "c6_" + (Generate-Secret -Length 32)

    $envContent = @"
# ============================================================
# AEGIS Configuration - Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# ============================================================

# --- Platform ---
AEGIS_PLATFORM=windows

# --- Database ---
POSTGRES_DB=aegis
POSTGRES_USER=aegis
POSTGRES_PASSWORD=$PostgresPassword
POSTGRES_PORT=$PostgresPort
DATABASE_URL=postgresql+asyncpg://aegis:${PostgresPassword}@aegis-db:5432/aegis

# --- API ---
AEGIS_API_PORT=$ApiPort
AEGIS_SECRET_KEY=$JwtSecret
AEGIS_DEFAULT_API_KEY=$apiKey

# --- Frontend ---
FRONTEND_PORT=$FrontendPort
NEXT_PUBLIC_API_URL=http://localhost:${ApiPort}/api/v1
NEXT_PUBLIC_WS_URL=ws://localhost:${ApiPort}/ws

# --- LLM (OpenRouter) ---
OPENROUTER_API_KEY=$OpenRouterApiKey

# --- Ollama (local on Windows) ---
OLLAMA_BASE_URL=http://host.docker.internal:11434

# --- Redis (optional) ---
REDIS_PORT=6379
"@

    $envFile = Join-Path $Path ".env"
    Set-Content -Path $envFile -Value $envContent -Encoding UTF8
    Write-Ok "Configuration written to $envFile"
    Write-Step "Default API key: $apiKey"
    Write-Warn "Save this API key -- you will need it for agent registration."

    return @{
        ApiKey = $apiKey
        PostgresPassword = $PostgresPassword
    }
}

# ---------------------------------------------------------------------------
# Docker Compose install
# ---------------------------------------------------------------------------
function Install-WithDocker {
    Write-Step "Installing with Docker Compose..."

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Copy docker-compose.yml
    $sourceDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.ScriptName)
    $composeSource = Join-Path $sourceDir "docker-compose.yml"

    if (Test-Path $composeSource) {
        Copy-Item $composeSource -Destination $InstallDir -Force
        Write-Ok "docker-compose.yml copied"
    }
    else {
        Write-Err "docker-compose.yml not found at $composeSource"
        Write-Err "Please copy the AEGIS project files to $InstallDir manually."
        return
    }

    # Copy backend and frontend directories
    $backendSource = Join-Path $sourceDir "backend"
    $frontendSource = Join-Path $sourceDir "frontend"

    if (Test-Path $backendSource) {
        Copy-Item $backendSource -Destination $InstallDir -Recurse -Force
        Write-Ok "Backend files copied"
    }

    if (Test-Path $frontendSource) {
        Copy-Item $frontendSource -Destination $InstallDir -Recurse -Force
        Write-Ok "Frontend files copied"
    }

    # Generate .env
    $secrets = New-EnvFile -Path $InstallDir

    # Start services
    Write-Step "Starting AEGIS services..."
    Push-Location $InstallDir
    try {
        docker compose up -d --build
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Services started successfully."
        }
        else {
            Write-Err "Docker Compose failed. Check logs with: docker compose logs"
        }
    }
    finally {
        Pop-Location
    }

    Write-Host ""
    Write-Ok "AEGIS is running."
    Write-Step "Dashboard:  http://localhost:$FrontendPort"
    Write-Step "API:        http://localhost:$ApiPort"
    Write-Step "API Docs:   http://localhost:${ApiPort}/docs"
    Write-Step "API Key:    $($secrets.ApiKey)"
    Write-Host ""
    Write-Step "Useful commands:"
    Write-Step "  cd $InstallDir"
    Write-Step "  docker compose logs -f         # view logs"
    Write-Step "  docker compose down            # stop all"
    Write-Step "  docker compose up -d           # start all"
    Write-Step "  docker compose ps              # service status"
}

# ---------------------------------------------------------------------------
# Native install (no Docker)
# ---------------------------------------------------------------------------
function Install-Native {
    Write-Step "Installing natively (no Docker)..."
    Write-Warn "Native mode requires PostgreSQL installed separately."
    Write-Warn "For a simpler setup, install Docker Desktop and re-run without -SkipDocker."

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $sourceDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.ScriptName)

    # Copy backend
    $backendSource = Join-Path $sourceDir "backend"
    if (Test-Path $backendSource) {
        Copy-Item $backendSource -Destination $InstallDir -Recurse -Force
        Write-Ok "Backend files copied"
    }

    # Create virtual environment
    $venvPath = Join-Path $InstallDir "venv"
    Write-Step "Creating Python virtual environment..."
    python -m venv $venvPath

    $pipPath = Join-Path $venvPath "Scripts\pip.exe"
    $pythonPath = Join-Path $venvPath "Scripts\python.exe"

    # Install backend dependencies
    $backendReqs = Join-Path $InstallDir "backend\requirements.txt"
    if (Test-Path $backendReqs) {
        Write-Step "Installing backend dependencies..."
        & $pipPath install -r $backendReqs
    }

    # Generate .env
    New-EnvFile -Path $InstallDir

    Write-Host ""
    Write-Ok "Native installation complete."
    Write-Step "To start the backend:"
    Write-Step "  cd $InstallDir"
    Write-Step "  .\venv\Scripts\activate"
    Write-Step "  cd backend"
    Write-Step "  python -m uvicorn app.main:app --host 0.0.0.0 --port $ApiPort"
    Write-Host ""
    Write-Warn "You must set up PostgreSQL separately and update .env with the connection string."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Banner

$prereqOk = Test-Prerequisites
Write-Host ""

if (-not $prereqOk) {
    Write-Warn "Some prerequisites are missing. Install them and re-run this script."
    Write-Warn "Continue anyway? (y/N)"
    $response = Read-Host
    if ($response -ne "y" -and $response -ne "Y") {
        Write-Err "Installation aborted."
        exit 1
    }
}

if ($SkipDocker) {
    Install-Native
}
else {
    Install-WithDocker
}

Write-Host ""
Write-Ok "Installation complete."
Write-Step "Next step: Install the endpoint agent on this machine:"
Write-Step "  powershell -ExecutionPolicy Bypass -File install-windows-agent.ps1 -ApiKey <your-key>"
