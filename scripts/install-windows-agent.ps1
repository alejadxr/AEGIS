# ============================================================================
# AEGIS Endpoint Agent - Windows Installer
# ============================================================================
# Installs the AEGIS EDR-lite agent as a Windows service (via NSSM)
# or as a Scheduled Task (fallback).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File install-windows-agent.ps1 `
#       -ApiUrl "http://YOUR_SERVER_IP:8000/api/v1" `
#       -ApiKey "c6_your_api_key"
#
# To uninstall:
#   powershell -ExecutionPolicy Bypass -File install-windows-agent.ps1 -Uninstall
# ============================================================================

param(
    [string]$ApiUrl = "http://YOUR_SERVER_IP:8000/api/v1",
    [string]$ApiKey = "",
    [string]$InstallDir = "C:\ProgramData\AegisAgent",
    [string]$LogLevel = "INFO",
    [switch]$Uninstall,
    [switch]$UseTaskScheduler
)

$ErrorActionPreference = "Stop"
$ServiceName = "AegisAgent"
$TaskName = "AegisAgent"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step {
    param([string]$Message)
    Write-Host "[aegis-agent] " -ForegroundColor Cyan -NoNewline
    Write-Host $Message
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[aegis-agent] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[aegis-agent] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Err {
    param([string]$Message)
    Write-Host "[aegis-agent] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
function Uninstall-Agent {
    Write-Step "Uninstalling AEGIS Agent..."

    # Stop and remove scheduled task
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Ok "Scheduled task removed."
    }

    # Stop and remove NSSM service
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Write-Ok "Windows service removed."
    }

    # Remove install directory
    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Ok "Installation directory removed: $InstallDir"
    }

    Write-Ok "AEGIS Agent uninstalled."
    return
}

# ---------------------------------------------------------------------------
# Check and install Python
# ---------------------------------------------------------------------------
function Get-PythonPath {
    # Try common locations
    $candidates = @(
        "python",
        "python3",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"
    )

    foreach ($candidate in $candidates) {
        try {
            $result = & $candidate --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                # Get the full path
                $resolved = (Get-Command $candidate -ErrorAction SilentlyContinue).Source
                if ($resolved) { return $resolved }
                return $candidate
            }
        }
        catch {
            continue
        }
    }

    return $null
}

# ---------------------------------------------------------------------------
# Install agent files
# ---------------------------------------------------------------------------
function Install-AgentFiles {
    Write-Step "Installing agent files to $InstallDir..."

    # Create directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Determine source directory (relative to this script)
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    $projectDir = Split-Path -Parent $scriptDir
    $agentDir = Join-Path $projectDir "agent"

    # Copy agent files
    $filesToCopy = @(
        "aegis_agent.py",
        "config.py",
        "config_windows.py",
        "requirements.txt"
    )

    foreach ($file in $filesToCopy) {
        $source = Join-Path $agentDir $file
        if (Test-Path $source) {
            Copy-Item $source -Destination $InstallDir -Force
            Write-Ok "Copied: $file"
        }
        else {
            Write-Warn "File not found: $source"
        }
    }

    # Create .env file for the agent
    $envContent = @"
AEGIS_API_URL=$ApiUrl
AEGIS_API_KEY=$ApiKey
AEGIS_LOG_LEVEL=$LogLevel
AEGIS_BREADCRUMBS_ENABLED=true
AEGIS_PLATFORM=windows
"@
    $envFile = Join-Path $InstallDir ".env"
    Set-Content -Path $envFile -Value $envContent -Encoding UTF8
    Write-Ok "Agent .env created"

    # Create a launcher script
    $launcherContent = @"
@echo off
REM AEGIS Agent Launcher
cd /d "$InstallDir"
set AEGIS_API_URL=$ApiUrl
set AEGIS_API_KEY=$ApiKey
set AEGIS_LOG_LEVEL=$LogLevel
set AEGIS_BREADCRUMBS_ENABLED=true
set AEGIS_PLATFORM=windows
"$PythonPath" "$InstallDir\aegis_agent.py"
"@
    $launcherFile = Join-Path $InstallDir "run-agent.bat"
    Set-Content -Path $launcherFile -Value $launcherContent -Encoding ASCII
    Write-Ok "Launcher script created: $launcherFile"
}

# ---------------------------------------------------------------------------
# Install Python dependencies
# ---------------------------------------------------------------------------
function Install-Dependencies {
    param([string]$Python)

    Write-Step "Installing Python dependencies..."

    # Create a virtual environment in the install dir
    $venvDir = Join-Path $InstallDir "venv"

    if (-not (Test-Path $venvDir)) {
        & $Python -m venv $venvDir
        Write-Ok "Virtual environment created"
    }

    $venvPip = Join-Path $venvDir "Scripts\pip.exe"
    $reqsFile = Join-Path $InstallDir "requirements.txt"

    if (Test-Path $reqsFile) {
        & $venvPip install -r $reqsFile
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Dependencies installed"
        }
        else {
            Write-Err "Failed to install dependencies"
            exit 1
        }
    }

    # Also install pywin32 for Windows Event Log access
    & $venvPip install pywin32 wmi 2>$null
    Write-Ok "Windows-specific packages installed (pywin32, wmi)"

    # Return the venv python path
    return (Join-Path $venvDir "Scripts\python.exe")
}

# ---------------------------------------------------------------------------
# Register as Scheduled Task
# ---------------------------------------------------------------------------
function Register-AsScheduledTask {
    param([string]$VenvPython)

    Write-Step "Registering as Scheduled Task..."

    # Remove existing task if present
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    $agentScript = Join-Path $InstallDir "aegis_agent.py"

    # Build the action
    $action = New-ScheduledTaskAction `
        -Execute $VenvPython `
        -Argument "`"$agentScript`"" `
        -WorkingDirectory $InstallDir

    # Trigger: at startup
    $trigger = New-ScheduledTaskTrigger -AtStartup

    # Settings: restart on failure, run indefinitely
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Days 365) `
        -StartWhenAvailable

    # Register the task to run as SYSTEM
    if (Test-Administrator) {
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -User "SYSTEM" `
            -RunLevel Highest `
            -Description "AEGIS EDR-lite Endpoint Agent" `
            -Force
    }
    else {
        # Non-admin: run as current user
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Description "AEGIS EDR-lite Endpoint Agent" `
            -Force
    }

    # Set environment variables for the task
    # We rely on the .env file and the launcher script for env vars

    # Start the task now
    Start-ScheduledTask -TaskName $TaskName
    Write-Ok "Scheduled Task '$TaskName' registered and started."
}

# ---------------------------------------------------------------------------
# Test registration with API
# ---------------------------------------------------------------------------
function Test-Registration {
    Write-Step "Testing API connectivity..."

    try {
        $response = Invoke-WebRequest -Uri "$ApiUrl/health" -TimeoutSec 10 -UseBasicParsing -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Ok "API is reachable at $ApiUrl"
            return $true
        }
    }
    catch {
        Write-Warn "API not reachable at $ApiUrl -- the agent will retry on startup."
        Write-Warn "Error: $($_.Exception.Message)"
    }
    return $false
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "   AEGIS Endpoint Agent Installer" -ForegroundColor Cyan
Write-Host "   Windows Edition" -ForegroundColor Cyan
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host ""

# Handle uninstall
if ($Uninstall) {
    Uninstall-Agent
    exit 0
}

# Validate API key
if ([string]::IsNullOrEmpty($ApiKey)) {
    Write-Err "API key is required. Use -ApiKey parameter."
    Write-Err "Example: .\install-windows-agent.ps1 -ApiKey c6_your_key_here"
    exit 1
}

# Check admin privileges
if (-not (Test-Administrator)) {
    Write-Warn "Not running as Administrator. Some features may be limited."
    Write-Warn "For full monitoring capabilities, run as Administrator."
}

# Find Python
$PythonPath = Get-PythonPath
if (-not $PythonPath) {
    Write-Err "Python not found. Please install Python 3.11+ first."
    Write-Err "  winget install Python.Python.3.12"
    Write-Err "  -- or --"
    Write-Err "  Download from https://python.org"
    exit 1
}
Write-Ok "Python found: $PythonPath"

# Install agent files
Install-AgentFiles

# Install dependencies
$VenvPython = Install-Dependencies -Python $PythonPath

# Test API connectivity
Test-Registration

# Register as scheduled task
Register-AsScheduledTask -VenvPython $VenvPython

Write-Host ""
Write-Ok "AEGIS Agent installed successfully."
Write-Host ""
Write-Step "Agent directory: $InstallDir"
Write-Step "API endpoint:    $ApiUrl"
Write-Step "Log level:       $LogLevel"
Write-Host ""
Write-Step "Management commands:"
Write-Step "  Start:    Start-ScheduledTask -TaskName $TaskName"
Write-Step "  Stop:     Stop-ScheduledTask -TaskName $TaskName"
Write-Step "  Status:   Get-ScheduledTask -TaskName $TaskName"
Write-Step "  Uninstall: .\install-windows-agent.ps1 -Uninstall"
Write-Host ""
Write-Step "Manual run (for debugging):"
Write-Step "  cd $InstallDir"
Write-Step "  .\venv\Scripts\activate"
Write-Step "  python aegis_agent.py"
