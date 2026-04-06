"""
Smart Database Honeypot - Imitates MySQL protocol with fake databases.

Listens on a configurable port (default 3306), speaks enough MySQL wire
protocol to accept connections and handle queries.  Returns plausible fake
data for SELECT queries, detects injection attempts, and logs every query.
"""

import asyncio
import logging
import random
import re
import struct
import time
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("aegis.phantom.smart_db")


# ---------------------------------------------------------------------------
# Fake data for query results
# ---------------------------------------------------------------------------

FAKE_DATABASES = {
    "production": ["users", "orders", "products", "sessions", "audit_log"],
    "users": ["accounts", "roles", "permissions", "tokens", "profiles"],
    "billing": ["invoices", "payments", "subscriptions", "plans", "coupons"],
}

FAKE_USERS_DATA = [
    (1, "admin", "admin@internal.corp", "$2b$12$LJ3/eR...hashed", "admin", 1),
    (2, "john.smith", "john.smith@internal.corp", "$2b$12$Xk9/aQ...hashed", "user", 1),
    (3, "sarah.jones", "sarah.jones@internal.corp", "$2b$12$Mn4/bR...hashed", "editor", 1),
    (4, "mike.wilson", "mike.wilson@internal.corp", "$2b$12$Pq7/cT...hashed", "user", 0),
    (5, "emma.davis", "emma.davis@internal.corp", "$2b$12$Rs2/dU...hashed", "manager", 1),
]

FAKE_ORDERS_DATA = [
    (1001, 2, "completed", 299.99, "2026-03-15 10:30:00"),
    (1002, 3, "pending", 149.50, "2026-03-16 14:22:00"),
    (1003, 5, "completed", 599.00, "2026-03-17 09:15:00"),
    (1004, 2, "shipped", 89.99, "2026-03-18 11:45:00"),
    (1005, 4, "cancelled", 199.99, "2026-03-19 16:30:00"),
]

# SQL injection detection patterns
SQL_INJECTION_PATTERNS = [
    r"union\s+select",
    r"or\s+1\s*=\s*1",
    r"'\s*or\s+'",
    r";\s*(drop|delete|insert|update|create|alter|exec)",
    r"information_schema",
    r"load_file\s*\(",
    r"into\s+(outfile|dumpfile)",
    r"benchmark\s*\(",
    r"sleep\s*\(",
    r"concat\s*\(",
    r"group_concat",
    r"char\s*\(\d+",
    r"0x[0-9a-f]{6,}",
    r"/\*.*\*/",
]


def _detect_sql_injection(query: str) -> list[str]:
    detected = []
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            detected.append(pattern)
    return detected


# ---------------------------------------------------------------------------
# MySQL wire protocol helpers (simplified)
# ---------------------------------------------------------------------------

def _mysql_greeting(connection_id: int) -> bytes:
    """Build a MySQL server greeting packet (Protocol::Handshake)."""
    # Protocol version 10
    proto = b"\x0a"
    # Server version
    version = b"8.0.36-0ubuntu0.22.04.1\x00"
    # Connection ID
    conn_id = struct.pack("<I", connection_id)
    # Auth plugin data part 1 (8 bytes)
    auth1 = bytes(random.getrandbits(8) for _ in range(8))
    # Filler
    filler = b"\x00"
    # Capability flags (lower 2 bytes) — basic caps
    cap_low = struct.pack("<H", 0xF7FF)
    # Character set (utf8mb4 = 45)
    charset = b"\x2d"
    # Status flags
    status = struct.pack("<H", 0x0002)
    # Capability flags (upper 2 bytes)
    cap_high = struct.pack("<H", 0x807F)
    # Auth plugin data length
    auth_len = b"\x15"
    # Reserved 10 bytes
    reserved = b"\x00" * 10
    # Auth plugin data part 2 (13 bytes)
    auth2 = bytes(random.getrandbits(8) for _ in range(13))
    # Auth plugin name
    auth_plugin = b"mysql_native_password\x00"

    payload = proto + version + conn_id + auth1 + filler + cap_low + charset + status + cap_high + auth_len + reserved + auth2 + auth_plugin
    # Packet: length (3 bytes LE) + sequence (1 byte) + payload
    length = struct.pack("<I", len(payload))[:3]
    return length + b"\x00" + payload


def _mysql_ok() -> bytes:
    """Build a MySQL OK packet."""
    payload = b"\x00\x00\x00\x02\x00\x00\x00"
    length = struct.pack("<I", len(payload))[:3]
    return length + b"\x02" + payload


def _mysql_error(msg: str, seq: int = 2) -> bytes:
    """Build a MySQL error packet."""
    payload = b"\xff" + struct.pack("<H", 1045) + b"#28000" + msg.encode("utf-8")
    length = struct.pack("<I", len(payload))[:3]
    return length + bytes([seq]) + payload


def _mysql_result_set(columns: list[str], rows: list[tuple], seq_start: int = 1) -> bytes:
    """Build a simplified MySQL result set."""
    packets = []
    seq = seq_start

    # Column count
    col_count = _mysql_lenenc_int(len(columns))
    packets.append(_mysql_packet(col_count, seq))
    seq += 1

    # Column definitions (simplified)
    for col in columns:
        col_def = (
            _mysql_lenenc_str(b"def") +     # catalog
            _mysql_lenenc_str(b"") +         # schema
            _mysql_lenenc_str(b"") +         # table
            _mysql_lenenc_str(b"") +         # org_table
            _mysql_lenenc_str(col.encode()) + # name
            _mysql_lenenc_str(col.encode()) + # org_name
            b"\x0c" +                        # filler (length of fixed fields)
            b"\x21\x00" +                    # character set (utf8)
            struct.pack("<I", 255) +         # column length
            b"\xfd" +                        # column type (VAR_STRING)
            b"\x01\x00" +                    # flags
            b"\x00" +                        # decimals
            b"\x00\x00"                      # filler
        )
        packets.append(_mysql_packet(col_def, seq))
        seq += 1

    # EOF packet
    packets.append(_mysql_packet(b"\xfe\x00\x00\x02\x00", seq))
    seq += 1

    # Row data
    for row in rows:
        row_data = b""
        for val in row:
            val_bytes = str(val).encode()
            row_data += _mysql_lenenc_str(val_bytes)
        packets.append(_mysql_packet(row_data, seq))
        seq += 1

    # EOF packet
    packets.append(_mysql_packet(b"\xfe\x00\x00\x02\x00", seq))

    return b"".join(packets)


def _mysql_packet(payload: bytes, seq: int) -> bytes:
    length = struct.pack("<I", len(payload))[:3]
    return length + bytes([seq % 256]) + payload


def _mysql_lenenc_int(val: int) -> bytes:
    if val < 251:
        return bytes([val])
    elif val < 65536:
        return b"\xfc" + struct.pack("<H", val)
    elif val < 16777216:
        return b"\xfd" + struct.pack("<I", val)[:3]
    else:
        return b"\xfe" + struct.pack("<Q", val)


def _mysql_lenenc_str(val: bytes) -> bytes:
    return _mysql_lenenc_int(len(val)) + val


# ---------------------------------------------------------------------------
# Smart DB Honeypot
# ---------------------------------------------------------------------------

class SmartDBHoneypot:
    """MySQL protocol honeypot with fake databases and injection detection."""

    def __init__(self, port: int = 3306):
        self.port = port
        self._running = False
        self._server: Optional[asyncio.AbstractServer] = None
        self._interaction_queue: Optional[asyncio.Queue] = None
        self._connection_counter = 0

    async def start(self, interaction_queue: asyncio.Queue):
        """Start the MySQL honeypot."""
        self._interaction_queue = interaction_queue
        self._running = True

        self._server = await asyncio.start_server(
            self._handle_connection, "0.0.0.0", self.port,
        )
        logger.info(f"[Smart DB] MySQL honeypot listening on port {self.port}")

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        logger.info("[Smart DB] Stopped")

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a single MySQL client connection."""
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "unknown"
        client_port = peer[1] if peer and len(peer) > 1 else 0

        self._connection_counter += 1
        conn_id = self._connection_counter

        logger.info(f"[Smart DB] Connection from {client_ip}:{client_port}")

        queries: list[str] = []
        credentials: list[dict] = []
        injections_detected: list[str] = []
        start_time = time.time()

        try:
            # Send greeting
            greeting = _mysql_greeting(conn_id)
            writer.write(greeting)
            await writer.drain()

            # Read auth response
            auth_data = await asyncio.wait_for(reader.read(4096), timeout=30)
            if auth_data and len(auth_data) > 36:
                # Extract username from auth packet (starts at offset 36 after capabilities)
                try:
                    username_bytes = auth_data[36:]
                    username = username_bytes.split(b"\x00")[0].decode(errors="replace")
                    credentials.append({"username": username, "password": "(hashed)"})
                    logger.info(f"[Smart DB] Auth from {client_ip}: user={username}")
                except Exception:
                    pass

            # Send OK (accept any auth)
            writer.write(_mysql_ok())
            await writer.drain()

            # Query loop
            while self._running:
                try:
                    header = await asyncio.wait_for(reader.readexactly(4), timeout=120)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break

                pkt_len = struct.unpack("<I", header[:3] + b"\x00")[0]
                if pkt_len == 0 or pkt_len > 1048576:
                    break

                try:
                    pkt_data = await asyncio.wait_for(reader.readexactly(pkt_len), timeout=10)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break

                if not pkt_data:
                    break

                cmd = pkt_data[0]

                if cmd == 0x01:  # COM_QUIT
                    break
                elif cmd == 0x03:  # COM_QUERY
                    query = pkt_data[1:].decode(errors="replace").strip()
                    queries.append(query)
                    logger.info(f"[Smart DB] Query from {client_ip}: {query[:200]}")

                    # Detect injections
                    inj = _detect_sql_injection(query)
                    if inj:
                        injections_detected.extend(inj)

                    # Generate response
                    response = self._handle_query(query)
                    writer.write(response)
                    await writer.drain()
                elif cmd == 0x02:  # COM_INIT_DB (USE database)
                    db_name = pkt_data[1:].decode(errors="replace")
                    queries.append(f"USE {db_name}")
                    if db_name in FAKE_DATABASES:
                        writer.write(_mysql_ok())
                    else:
                        writer.write(_mysql_error(f"Unknown database '{db_name}'"))
                    await writer.drain()
                else:
                    # Unknown command, send OK
                    writer.write(_mysql_ok())
                    await writer.drain()

        except Exception as e:
            logger.debug(f"[Smart DB] Connection error from {client_ip}: {e}")
        finally:
            duration = int(time.time() - start_time)
            writer.close()

            capture = {
                "source_ip": client_ip,
                "source_port": client_port,
                "protocol": "mysql",
                "credentials_tried": credentials,
                "commands": queries,
                "session_duration": duration,
                "timestamp": datetime.utcnow().isoformat(),
                "honeypot_type": "smart_db",
                "injections_detected": list(set(injections_detected)),
            }
            self._queue_interaction(capture)

    def _handle_query(self, query: str) -> bytes:
        """Route a SQL query to the appropriate fake response."""
        q = query.strip().upper()

        if q.startswith("SHOW DATABASES"):
            return _mysql_result_set(
                ["Database"],
                [(db,) for db in FAKE_DATABASES.keys()],
            )

        if q.startswith("SHOW TABLES"):
            # Find which DB context
            for db_name, tables in FAKE_DATABASES.items():
                return _mysql_result_set(
                    [f"Tables_in_{db_name}"],
                    [(t,) for t in tables],
                )

        if q.startswith("SELECT") and "FROM" in q:
            # Try to match table
            table_match = re.search(r"FROM\s+[`]?(\w+)[`]?", query, re.IGNORECASE)
            if table_match:
                table = table_match.group(1).lower()
                if table in ("users", "accounts"):
                    return _mysql_result_set(
                        ["id", "username", "email", "password_hash", "role", "active"],
                        FAKE_USERS_DATA,
                    )
                if table in ("orders",):
                    return _mysql_result_set(
                        ["id", "user_id", "status", "amount", "created_at"],
                        FAKE_ORDERS_DATA,
                    )

            # Generic response for unrecognized SELECT
            return _mysql_result_set(["result"], [("OK",)])

        if any(q.startswith(kw) for kw in ("INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER")):
            # Log destructive queries but return OK
            return _mysql_ok()

        if q.startswith("SET") or q.startswith("SELECT @@") or q.startswith("SELECT VERSION"):
            return _mysql_result_set(["Value"], [("8.0.36",)])

        # Default: OK
        return _mysql_ok()

    def _queue_interaction(self, data: dict):
        if self._interaction_queue:
            try:
                self._interaction_queue.put_nowait(data)
            except Exception as e:
                logger.error(f"[Smart DB] Failed to queue interaction: {e}")
