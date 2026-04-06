import asyncio
import json as _json
import logging
import socket
import threading
import time
from datetime import datetime
from pathlib import Path

import paramiko

logger = logging.getLogger("aegis.phantom.ssh_honeypot")

# Path to store the server host key
KEY_PATH = Path.home() / ".aegis" / "ssh_honeypot_key"

_SSH_CONFIG_PATH = Path.home() / "AEGIS" / "backend" / "honeypot_config.json"


def _get_ssh_cfg() -> dict:
    try:
        return _json.loads(_SSH_CONFIG_PATH.read_text()).get("ssh", {})
    except Exception:
        return {}


def _ensure_host_key() -> paramiko.RSAKey:
    """Generate or load the SSH server host key."""
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not KEY_PATH.exists():
        logger.info("Generating SSH honeypot host key...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(KEY_PATH))
        logger.info(f"Host key saved to {KEY_PATH}")
    return paramiko.RSAKey(filename=str(KEY_PATH))


class HoneypotServerInterface(paramiko.ServerInterface):
    """Paramiko server interface that accepts any credentials."""

    def __init__(self, client_ip: str, client_port: int, interaction_callback):
        self.client_ip = client_ip
        self.client_port = client_port
        self.interaction_callback = interaction_callback
        self.credentials_tried: list[dict] = []
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        logger.info(f"[SSH] Login attempt from {self.client_ip}: {username}:{password}")
        self.credentials_tried.append({"username": username, "password": password})
        if len(self.credentials_tried) >= 1:
            self.event.set()
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key) -> int:
        logger.info(f"[SSH] Pubkey auth from {self.client_ip}: user={username}")
        self.credentials_tried.append({"username": username, "key_type": key.get_name()})
        self.event.set()
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel) -> bool:
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        logger.info(f"[SSH] Exec request from {self.client_ip}: {command.decode(errors='replace')}")
        return True


def _handle_client(client_sock: socket.socket, client_addr: tuple, host_key: paramiko.RSAKey, interaction_queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
    """Handle a single SSH client connection in a thread."""
    client_ip, client_port = client_addr
    logger.info(f"[SSH] New connection from {client_ip}:{client_port}")

    transport = None
    credentials: list[dict] = []
    commands: list[str] = []
    start_time = time.time()

    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(host_key)
        transport.set_gss_host(socket.gethostname())

        server_iface = HoneypotServerInterface(client_ip, client_port, None)
        transport.start_server(server=server_iface)

        # Wait for auth
        server_iface.event.wait(timeout=30)
        credentials = server_iface.credentials_tried

        # Try to accept a channel
        channel = transport.accept(20)
        if channel is None:
            logger.info(f"[SSH] No channel opened from {client_ip}")
        else:
            channel.settimeout(60)
            # Send fake shell banner — hostname read from honeypot_config.json
            ssh_cfg = _get_ssh_cfg()
            hostname = ssh_cfg.get("hostname", "prod-server-01").encode()
            fake_banner = (
                b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n"
                b"\r\n * Documentation:  https://help.ubuntu.com\r\n"
                b"\r\nLast login: Mon Mar 17 09:12:44 2026 from 192.168.1.100\r\n\r\nroot@"
                + hostname + b":~$ "
            )
            channel.send(fake_banner)

            # Read commands
            cmd_buf = b""
            while True:
                try:
                    data = channel.recv(1024)
                    if not data:
                        break
                    channel.send(data)  # Echo back
                    cmd_buf += data
                    if b"\r" in data or b"\n" in data:
                        cmd_str = cmd_buf.decode(errors="replace").strip()
                        if cmd_str:
                            commands.append(cmd_str)
                            logger.info(f"[SSH] Command from {client_ip}: {cmd_str!r}")
                            if "ls" in cmd_str:
                                channel.send(b"\r\nDesktop  Documents  Downloads  etc  tmp\r\n")
                            elif "whoami" in cmd_str:
                                channel.send(b"\r\nroot\r\n")
                            elif "id" in cmd_str:
                                channel.send(b"\r\nuid=0(root) gid=0(root) groups=0(root)\r\n")
                            elif "uname" in cmd_str:
                                channel.send(b"\r\nLinux server 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 GNU/Linux\r\n")
                            elif "exit" in cmd_str or "logout" in cmd_str:
                                channel.send(b"\r\nlogout\r\n")
                                break
                            else:
                                channel.send(b"\r\n")
                            channel.send(b"root@" + hostname + b":~$ ")
                        cmd_buf = b""
                except socket.timeout:
                    break
                except Exception:
                    break
            channel.close()

    except Exception as e:
        logger.warning(f"[SSH] Error handling {client_ip}: {e}")
    finally:
        duration = int(time.time() - start_time)
        if transport:
            transport.close()
        client_sock.close()

        interaction_data = {
            "source_ip": client_ip,
            "source_port": client_port,
            "protocol": "ssh",
            "credentials_tried": credentials,
            "commands": commands,
            "session_duration": duration,
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            loop.call_soon_threadsafe(interaction_queue.put_nowait, interaction_data)
        except Exception as e:
            logger.error(f"[SSH] Failed to queue interaction: {e}")


class SSHHoneypot:
    """Real SSH honeypot on port 2222."""

    def __init__(self, port: int = 2222):
        self.port = port
        self._running = False
        self._server_sock: socket.socket | None = None
        self._host_key: paramiko.RSAKey | None = None
        self._interaction_queue: asyncio.Queue | None = None
        self._accept_task: asyncio.Task | None = None

    async def start(self, interaction_queue: asyncio.Queue):
        """Start the SSH honeypot."""
        self._interaction_queue = interaction_queue
        self._host_key = _ensure_host_key()

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("0.0.0.0", self.port))
        self._server_sock.listen(10)
        self._server_sock.setblocking(False)
        self._running = True

        logger.info(f"[SSH Honeypot] Listening on port {self.port}")

        loop = asyncio.get_event_loop()
        self._accept_task = asyncio.create_task(self._accept_loop(loop))

    async def _accept_loop(self, loop: asyncio.AbstractEventLoop):
        """Accept incoming SSH connections."""
        while self._running:
            try:
                try:
                    client_sock, client_addr = self._server_sock.accept()
                    t = threading.Thread(
                        target=_handle_client,
                        args=(client_sock, client_addr, self._host_key, self._interaction_queue, loop),
                        daemon=True,
                    )
                    t.start()
                except BlockingIOError:
                    await asyncio.sleep(0.1)
            except Exception as e:
                if self._running:
                    logger.error(f"[SSH Honeypot] Accept error: {e}")
                await asyncio.sleep(1)

    async def stop(self):
        """Stop the SSH honeypot."""
        self._running = False
        if self._accept_task:
            self._accept_task.cancel()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        logger.info("[SSH Honeypot] Stopped")


ssh_honeypot = SSHHoneypot(port=2222)
