"""
AEGIS EDR-lite Agent Configuration.

All values can be overridden via environment variables prefixed with AEGIS_.
Supports Linux, macOS, and Windows platforms.
"""

import os
import uuid
import platform
import socket

IS_WINDOWS = platform.system() == "Windows"

# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------
AEGIS_API_URL: str = os.getenv("AEGIS_API_URL", "http://localhost:8000/api/v1")
AEGIS_API_KEY: str = os.getenv("AEGIS_API_KEY", "")

# ---------------------------------------------------------------------------
# Agent identity (auto-generated on first run, persisted to .agent_id file)
# ---------------------------------------------------------------------------
_AGENT_ID_FILE = os.path.join(os.path.dirname(__file__), ".agent_id")


def _load_or_create_agent_id() -> str:
    if os.path.exists(_AGENT_ID_FILE):
        with open(_AGENT_ID_FILE, "r") as f:
            stored = f.read().strip()
            if stored:
                return stored
    new_id = str(uuid.uuid4())
    try:
        with open(_AGENT_ID_FILE, "w") as f:
            f.write(new_id)
    except OSError:
        pass  # read-only filesystem; use ephemeral ID
    return new_id


AGENT_ID: str = os.getenv("AEGIS_AGENT_ID", _load_or_create_agent_id())
HOSTNAME: str = os.getenv("AEGIS_HOSTNAME", socket.gethostname())
OS_INFO: str = f"{platform.system()} {platform.release()} ({platform.machine()})"
AGENT_VERSION: str = "1.0.0"

# ---------------------------------------------------------------------------
# Monitoring intervals (seconds)
# ---------------------------------------------------------------------------
PROCESS_INTERVAL: int = int(os.getenv("AEGIS_PROCESS_INTERVAL", "10"))
NETWORK_INTERVAL: int = int(os.getenv("AEGIS_NETWORK_INTERVAL", "10"))
HEARTBEAT_INTERVAL: int = int(os.getenv("AEGIS_HEARTBEAT_INTERVAL", "30"))
EVENT_FLUSH_INTERVAL: int = int(os.getenv("AEGIS_EVENT_FLUSH_INTERVAL", "5"))

# ---------------------------------------------------------------------------
# File Integrity Monitoring (platform-aware)
# ---------------------------------------------------------------------------
if IS_WINDOWS:
    from config_windows import FIM_PATHS as _win_fim_paths, FIM_USER_PATHS as _win_fim_user_paths
    _default_fim_paths = ",".join(_win_fim_paths)
    FIM_PATHS: list[str] = os.getenv("AEGIS_FIM_PATHS", _default_fim_paths).split(",")
    FIM_PATHS = [p.strip() for p in FIM_PATHS if p.strip()]
    FIM_USER_PATHS: list[str] = _win_fim_user_paths
else:
    _default_fim_paths = "/etc/,/usr/bin/,/usr/sbin/"
    FIM_PATHS: list[str] = os.getenv("AEGIS_FIM_PATHS", _default_fim_paths).split(",")
    FIM_PATHS = [p.strip() for p in FIM_PATHS if p.strip()]
    FIM_USER_PATHS: list[str] = [
        os.path.expanduser("~/.ssh/"),
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.bash_profile"),
        os.path.expanduser("~/.zshrc"),
    ]

# ---------------------------------------------------------------------------
# Deception breadcrumbs (platform-aware)
# ---------------------------------------------------------------------------
BREADCRUMBS_ENABLED: bool = os.getenv("AEGIS_BREADCRUMBS_ENABLED", "true").lower() == "true"

if IS_WINDOWS:
    from config_windows import BREADCRUMB_PATHS as _win_breadcrumbs
    BREADCRUMB_PATHS: list[str] = _win_breadcrumbs
else:
    _default_breadcrumb_paths = "~/.aws/credentials,~/passwords.txt,~/.env.production"
    BREADCRUMB_PATHS: list[str] = [
        os.path.expanduser(p.strip())
        for p in os.getenv("AEGIS_BREADCRUMB_PATHS", _default_breadcrumb_paths).split(",")
        if p.strip()
    ]

# ---------------------------------------------------------------------------
# Suspicious process patterns
# ---------------------------------------------------------------------------
SUSPICIOUS_PROCESS_NAMES: list[str] = [
    "ncat", "nc", "netcat", "socat",
    "msfconsole", "msfvenom", "meterpreter",
    "mimikatz", "lazagne", "hashcat", "john",
    "hydra", "medusa", "ncrack",
    "chisel", "ligolo", "frp", "ngrok",
    "rclone", "mega-cmd",
    "xmrig", "cpuminer", "bfgminer",
    "crackmapexec", "impacket", "responder",
    "bloodhound", "sharphound",
    "cobaltstrike", "beacon",
    "reverse_tcp", "bind_tcp",
]

# Extend with Windows-specific suspicious processes
if IS_WINDOWS:
    from config_windows import WINDOWS_SUSPICIOUS_PROCESSES
    SUSPICIOUS_PROCESS_NAMES.extend(WINDOWS_SUSPICIOUS_PROCESSES)

# ---------------------------------------------------------------------------
# Network discovery
# ---------------------------------------------------------------------------
DISCOVERY_ENABLED: bool = os.getenv("AEGIS_DISCOVERY_ENABLED", "true").lower() == "true"
DISCOVERY_INTERVAL: int = int(os.getenv("AEGIS_DISCOVERY_INTERVAL", str(6 * 3600)))  # 6 hours
DISCOVERY_SCAN_PORTS: list[int] = [
    int(p) for p in os.getenv(
        "AEGIS_DISCOVERY_PORTS",
        "22,80,443,3306,5432,6379,8080,8443,9200,27017,5900,3389"
    ).split(",") if p.strip()
]
DISCOVERY_TIMEOUT: float = float(os.getenv("AEGIS_DISCOVERY_TIMEOUT", "1.0"))  # per-port timeout
DISCOVERY_MAX_THREADS: int = int(os.getenv("AEGIS_DISCOVERY_MAX_THREADS", "50"))

# ---------------------------------------------------------------------------
# Data sharing — opt-in only
# ---------------------------------------------------------------------------
DATA_SHARING_ENABLED: bool = os.getenv("AEGIS_DATA_SHARING", "false").lower() == "true"
DATA_SHARING_LEVEL: str = os.getenv("AEGIS_DATA_SHARING_LEVEL", "anonymous")  # anonymous, basic, detailed
DATA_SHARING_INTERVAL: int = int(os.getenv("AEGIS_DATA_SHARING_INTERVAL", str(3600)))  # 1 hour

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: str = os.getenv("AEGIS_LOG_LEVEL", "INFO")
