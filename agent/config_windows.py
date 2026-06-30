"""
AEGIS Agent - Windows-Specific Configuration
================================================
Provides platform-appropriate paths and monitoring targets for Windows hosts.

This module is imported by config.py when running on Windows.
"""

import os
import platform

# Only define Windows config if actually on Windows
IS_WINDOWS = platform.system() == "Windows"

# ---------------------------------------------------------------------------
# File Integrity Monitoring paths (Windows equivalents)
# ---------------------------------------------------------------------------
if IS_WINDOWS:
    FIM_PATHS = [
        # System configuration files
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc"),
        # System registry hives (SAM, SECURITY, SYSTEM, SOFTWARE)
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "config"),
        # PowerShell profiles (system-wide)
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0"),
    ]

    FIM_USER_PATHS = [
        # SSH keys
        os.path.join(os.path.expanduser("~"), ".ssh"),
        # PowerShell profile (user)
        os.path.join(os.path.expanduser("~"), "Documents", "WindowsPowerShell"),
        # PowerShell 7 profile (user)
        os.path.join(os.path.expanduser("~"), "Documents", "PowerShell"),
        # Startup folder (persistence mechanism)
        os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    ]
else:
    FIM_PATHS = []
    FIM_USER_PATHS = []

# ---------------------------------------------------------------------------
# Deception breadcrumb paths (Windows)
# ---------------------------------------------------------------------------
if IS_WINDOWS:
    BREADCRUMB_PATHS = [
        # Fake credentials in user profile
        os.path.join(os.path.expanduser("~"), "passwords.txt"),
        # Fake .env in AppData
        os.path.join(os.environ.get("APPDATA", ""), ".env.production"),
        # Fake AWS credentials
        os.path.join(os.path.expanduser("~"), ".aws", "credentials"),
        # Fake KeePass database marker
        os.path.join(os.path.expanduser("~"), "Documents", "passwords.kdbx.bak"),
    ]
else:
    BREADCRUMB_PATHS = []

# ---------------------------------------------------------------------------
# Windows-specific sensitive file patterns (for FIM severity)
# ---------------------------------------------------------------------------
WINDOWS_SENSITIVE_PATTERNS = [
    "\\drivers\\etc\\hosts",
    "\\System32\\config\\SAM",
    "\\System32\\config\\SECURITY",
    "\\System32\\config\\SYSTEM",
    "authorized_keys",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
    "Startup\\",
]

# ---------------------------------------------------------------------------
# Windows Event Log IDs to monitor
# ---------------------------------------------------------------------------
WINDOWS_SECURITY_EVENTS = {
    # Authentication events
    4624: {"name": "Successful Logon", "severity": "info"},
    4625: {"name": "Failed Logon", "severity": "medium"},
    4634: {"name": "Logoff", "severity": "info"},
    4648: {"name": "Logon with Explicit Credentials", "severity": "medium"},
    4672: {"name": "Special Privileges Assigned", "severity": "low"},

    # Account management
    4720: {"name": "User Account Created", "severity": "high"},
    4722: {"name": "User Account Enabled", "severity": "medium"},
    4724: {"name": "Password Reset Attempt", "severity": "medium"},
    4726: {"name": "User Account Deleted", "severity": "high"},
    4732: {"name": "Member Added to Local Group", "severity": "high"},
    4735: {"name": "Local Group Changed", "severity": "medium"},

    # Policy changes
    4719: {"name": "Audit Policy Changed", "severity": "high"},
    4738: {"name": "User Account Changed", "severity": "medium"},

    # Process events
    4688: {"name": "New Process Created", "severity": "info"},
    4689: {"name": "Process Exited", "severity": "info"},

    # Object access
    4663: {"name": "Object Access Attempt", "severity": "low"},

    # Firewall
    5025: {"name": "Firewall Service Stopped", "severity": "critical"},
    5034: {"name": "Firewall Driver Stopped", "severity": "critical"},

    # RDP-specific
    4778: {"name": "RDP Session Reconnected", "severity": "medium"},
    4779: {"name": "RDP Session Disconnected", "severity": "info"},
}

# ---------------------------------------------------------------------------
# Logon type mappings (for Event 4624/4625)
# ---------------------------------------------------------------------------
LOGON_TYPES = {
    2: "Interactive (console)",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}

# ---------------------------------------------------------------------------
# Suspicious process names (Windows-specific additions)
# ---------------------------------------------------------------------------
WINDOWS_SUSPICIOUS_PROCESSES = [
    # Credential harvesting
    "mimikatz", "lazagne", "procdump",
    # Lateral movement
    "psexec", "paexec", "wmiexec",
    # Tunneling / proxy
    "plink", "chisel", "ligolo", "ngrok",
    # Remote access
    "anydesk", "teamviewer",
    # Reconnaissance
    "sharphound", "bloodhound", "adexplorer",
    # PowerShell abuse indicators
    "powershell -enc", "powershell -nop", "powershell -w hidden",
    "powershell -executionpolicy bypass",
    # LOLBins (Living off the Land Binaries)
    "certutil -urlcache",
    "bitsadmin /transfer",
    "mshta",
    "regsvr32 /s /n /u /i:",
    "rundll32.exe javascript:",
    "wscript.exe",
    "cscript.exe",
]

# ---------------------------------------------------------------------------
# Windows Defender status check helper
# ---------------------------------------------------------------------------
def get_defender_status() -> dict:
    """
    Query Windows Defender status via PowerShell.
    Returns a dict with defender status information.
    """
    import subprocess

    status = {
        "available": False,
        "real_time_protection": None,
        "definitions_up_to_date": None,
        "last_scan": None,
        "error": None,
    }

    if not IS_WINDOWS:
        status["error"] = "Not running on Windows"
        return status

    try:
        ps_cmd = (
            "Get-MpComputerStatus | "
            "Select-Object RealTimeProtectionEnabled, "
            "AntivirusSignatureLastUpdated, "
            "QuickScanEndTime, "
            "AntivirusEnabled | "
            "ConvertTo-Json"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            import json
            data = json.loads(result.stdout)
            status["available"] = True
            status["real_time_protection"] = data.get("RealTimeProtectionEnabled")
            status["definitions_up_to_date"] = data.get("AntivirusEnabled")
            status["last_scan"] = data.get("QuickScanEndTime")
        else:
            status["error"] = result.stderr.strip() or "No output from Get-MpComputerStatus"
    except subprocess.TimeoutExpired:
        status["error"] = "PowerShell command timed out"
    except FileNotFoundError:
        status["error"] = "PowerShell not found"
    except Exception as e:
        status["error"] = str(e)

    return status


# ---------------------------------------------------------------------------
# RDP session monitoring helper
# ---------------------------------------------------------------------------
def get_rdp_sessions() -> list:
    """
    List active RDP sessions via qwinsta.
    Returns a list of dicts with session info.
    """
    import subprocess

    sessions = []
    if not IS_WINDOWS:
        return sessions

    try:
        result = subprocess.run(
            ["qwinsta"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            # Skip header line
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    session = {
                        "session_name": parts[0].strip(">"),
                        "username": parts[1] if len(parts) > 1 else "",
                        "id": parts[2] if len(parts) > 2 else "",
                        "state": parts[3] if len(parts) > 3 else "",
                    }
                    sessions.append(session)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    return sessions


# ---------------------------------------------------------------------------
# Task Scheduler monitoring helper
# ---------------------------------------------------------------------------
def get_scheduled_tasks_summary() -> list:
    """
    Get recently created/modified scheduled tasks (potential persistence).
    Returns a list of suspicious tasks.
    """
    import subprocess

    tasks = []
    if not IS_WINDOWS:
        return tasks

    try:
        ps_cmd = (
            "Get-ScheduledTask | "
            "Where-Object { $_.Date -gt (Get-Date).AddDays(-7) -or $_.State -eq 'Running' } | "
            "Select-Object TaskName, TaskPath, State, Date, Author | "
            "ConvertTo-Json -Depth 2"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            import json
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            tasks = data
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    return tasks
