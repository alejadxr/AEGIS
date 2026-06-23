#!/usr/bin/env python3
"""
AEGIS Windows Server Connectivity Test
==========================================
Run from Mac (or any machine with Tailscale):
    python scripts/test-windows.py

Tests:
  1. Tailscale connectivity (ping)
  2. Ollama API on Windows
  3. Common ports (SSH, RDP)
  4. Agent status (if running)
  5. AEGIS API reachability from Windows perspective
"""

import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime

WINDOWS_IP = os.environ.get("WINDOWS_TARGET_IP", "YOUR_WINDOWS_IP")
WINDOWS_USER = os.environ.get("WINDOWS_USER", "your-username")

# Ports to check
PORTS_TO_CHECK = {
    22: "SSH",
    3389: "RDP",
    11434: "Ollama",
    8000: "AEGIS API (if running on Windows)",
    3000: "AEGIS Frontend (if running on Windows)",
    45876: "Beszel Agent",
}

# ANSI colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"


def log(msg):
    print(f"{CYAN}[aegis-test]{RESET} {msg}")


def ok(msg):
    print(f"{GREEN}[PASS]{RESET} {msg}")


def warn(msg):
    print(f"{YELLOW}[WARN]{RESET} {msg}")


def fail(msg):
    print(f"{RED}[FAIL]{RESET} {msg}")


def section(title):
    print(f"\n{BOLD}--- {title} ---{RESET}")


def test_ping():
    """Test basic ICMP connectivity via Tailscale."""
    section("1. Tailscale Connectivity (ping)")

    try:
        result = subprocess.run(
            ["ping", "-c", "3", "-W", "3", WINDOWS_IP],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            # Extract avg latency
            for line in result.stdout.split("\n"):
                if "avg" in line or "round-trip" in line:
                    ok(f"Ping to {WINDOWS_IP}: {line.strip()}")
                    return True
            ok(f"Ping to {WINDOWS_IP} succeeded")
            return True
        else:
            fail(f"Ping to {WINDOWS_IP} failed")
            return False
    except subprocess.TimeoutExpired:
        fail(f"Ping to {WINDOWS_IP} timed out")
        return False
    except FileNotFoundError:
        warn("ping command not found, skipping")
        return None


def test_port(ip, port, name, timeout=5):
    """Test TCP connectivity to a specific port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            ok(f"Port {port} ({name}) is OPEN")
            return True
        else:
            warn(f"Port {port} ({name}) is CLOSED or filtered")
            return False
    except socket.timeout:
        warn(f"Port {port} ({name}) connection timed out")
        return False
    except Exception as e:
        fail(f"Port {port} ({name}) error: {e}")
        return False


def test_ports():
    """Test all configured ports."""
    section("2. Port Connectivity")

    results = {}
    for port, name in PORTS_TO_CHECK.items():
        results[port] = test_port(WINDOWS_IP, port, name)
    return results


def test_ollama():
    """Test Ollama API on Windows."""
    section("3. Ollama API")

    try:
        import httpx
    except ImportError:
        warn("httpx not installed. Install with: pip install httpx")
        # Fall back to urllib
        import urllib.request
        try:
            url = f"http://{WINDOWS_IP}:11434/api/tags"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                models = data.get("models", [])
                ok(f"Ollama is running with {len(models)} model(s)")
                for m in models:
                    name = m.get("name", "unknown")
                    size_gb = m.get("size", 0) / (1024 ** 3)
                    log(f"  Model: {name} ({size_gb:.1f} GB)")
                return True
        except Exception as e:
            fail(f"Ollama API not reachable: {e}")
            return False

    try:
        with httpx.Client(timeout=10) as client:
            # Test /api/tags endpoint
            resp = client.get(f"http://{WINDOWS_IP}:11434/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                models = data.get("models", [])
                ok(f"Ollama is running with {len(models)} model(s)")
                for m in models:
                    name = m.get("name", "unknown")
                    size_gb = m.get("size", 0) / (1024 ** 3)
                    log(f"  Model: {name} ({size_gb:.1f} GB)")
            else:
                warn(f"Ollama returned status {resp.status_code}")

            # Test /api/version
            try:
                resp = client.get(f"http://{WINDOWS_IP}:11434/api/version")
                if resp.status_code == 200:
                    version = resp.json().get("version", "unknown")
                    ok(f"Ollama version: {version}")
            except Exception:
                pass

            return True

    except httpx.ConnectError:
        fail(f"Cannot connect to Ollama at {WINDOWS_IP}:11434")
        return False
    except Exception as e:
        fail(f"Ollama test error: {e}")
        return False


def test_ollama_inference():
    """Test a simple inference call to Ollama."""
    section("4. Ollama Inference Test")

    try:
        import httpx
    except ImportError:
        warn("httpx not installed, skipping inference test")
        return None

    try:
        with httpx.Client(timeout=60) as client:
            # Get available models first
            resp = client.get(f"http://{WINDOWS_IP}:11434/api/tags")
            if resp.status_code != 200:
                warn("Cannot list models")
                return False

            models = resp.json().get("models", [])
            if not models:
                warn("No models available on Ollama")
                return False

            model_name = models[0]["name"]
            log(f"Testing inference with model: {model_name}")

            start = time.time()
            resp = client.post(
                f"http://{WINDOWS_IP}:11434/api/generate",
                json={
                    "model": model_name,
                    "prompt": "Say 'AEGIS online' in exactly 3 words.",
                    "stream": False,
                    "options": {"num_predict": 20},
                },
                timeout=60,
            )
            elapsed = time.time() - start

            if resp.status_code == 200:
                data = resp.json()
                response_text = data.get("response", "").strip()
                ok(f"Inference succeeded in {elapsed:.1f}s")
                log(f"  Response: {response_text}")
                return True
            else:
                fail(f"Inference failed with status {resp.status_code}")
                return False

    except httpx.ReadTimeout:
        warn("Inference timed out (60s). Model may be loading.")
        return False
    except Exception as e:
        fail(f"Inference test error: {e}")
        return False


def test_agent_status():
    """Check if AEGIS agent is reporting from Windows."""
    section("5. AEGIS Agent Status")

    # Check if we can reach the main AEGIS API to look for agent
    api_url = os.environ.get("AEGIS_API_URL", "http://YOUR_SERVER_IP:8000/api/v1")

    try:
        import httpx
    except ImportError:
        warn("httpx not installed, skipping agent status check")
        return None

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(f"{api_url}/health")
            if resp.status_code == 200:
                ok(f"AEGIS API is reachable at {api_url}")
            else:
                warn(f"AEGIS API returned status {resp.status_code}")
                return False

            # Try to get agents list
            resp = client.get(f"{api_url}/agents")
            if resp.status_code == 200:
                agents = resp.json()
                if isinstance(agents, list):
                    win_agents = [a for a in agents if "windows" in str(a).lower() or WINDOWS_IP in str(a)]
                    if win_agents:
                        ok(f"Found Windows agent(s): {len(win_agents)}")
                        for a in win_agents:
                            agent_id = a.get("agent_id", "unknown")
                            status = a.get("status", "unknown")
                            log(f"  Agent: {agent_id} (status: {status})")
                    else:
                        warn("No Windows agent registered yet")
                return True
            elif resp.status_code == 401:
                warn("API requires authentication to list agents")
                return None

    except Exception as e:
        warn(f"Could not check agent status: {e}")
        return None


def test_nmap_reachability():
    """Quick nmap scan of Windows host (if nmap available)."""
    section("6. Nmap Quick Scan")

    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            warn("nmap not available")
            return None
    except FileNotFoundError:
        warn("nmap not installed, skipping")
        return None

    log(f"Quick scanning {WINDOWS_IP} (top 20 ports)...")
    try:
        result = subprocess.run(
            ["nmap", "-sT", "--top-ports", "20", "-T4", "--open", WINDOWS_IP],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            # Print open ports from output
            for line in result.stdout.split("\n"):
                line = line.strip()
                if "/tcp" in line and "open" in line:
                    ok(f"  {line}")
            return True
        else:
            warn(f"nmap scan returned non-zero: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        warn("nmap scan timed out (30s)")
        return False


def print_summary(results):
    """Print a summary of all tests."""
    section("SUMMARY")
    total = len(results)
    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)

    for name, result in results.items():
        if result is True:
            status = f"{GREEN}PASS{RESET}"
        elif result is False:
            status = f"{RED}FAIL{RESET}"
        else:
            status = f"{YELLOW}SKIP{RESET}"
        print(f"  [{status}] {name}")

    print(f"\n  Total: {total} | Passed: {passed} | Failed: {failed} | Skipped: {skipped}")

    if failed == 0:
        print(f"\n{GREEN}{BOLD}Windows server is ready for AEGIS deployment.{RESET}")
    else:
        print(f"\n{YELLOW}{BOLD}Some checks failed. Review and fix before deploying.{RESET}")


def main():
    print(f"\n{BOLD}AEGIS Windows Server Connectivity Test{RESET}")
    print(f"Target: {WINDOWS_IP} (user: {WINDOWS_USER})")
    print(f"Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    results = {}

    results["Tailscale Ping"] = test_ping()
    port_results = test_ports()
    for port, name in PORTS_TO_CHECK.items():
        results[f"Port {port} ({name})"] = port_results.get(port)
    results["Ollama API"] = test_ollama()
    results["Ollama Inference"] = test_ollama_inference()
    results["Agent Status"] = test_agent_status()
    results["Nmap Scan"] = test_nmap_reachability()

    print_summary(results)


if __name__ == "__main__":
    main()
