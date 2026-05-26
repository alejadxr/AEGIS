"""AEGIS unified log feed writer (Python).

Append-only JSON-lines emitter. POSIX append is atomic up to PIPE_BUF
(~4 KB on macOS/Linux), so concurrent writers from multiple processes
do not corrupt lines as long as each line fits in one write.
"""

import json
import os
from datetime import datetime, timezone

DEFAULT_PATH = "/Users/alejandxr/web-logs/aegis-feed.jsonl"


def emit(*, app, src_ip, method, path, status, **optional):
    """Append one JSON line to the AEGIS feed.

    Mandatory fields: app, src_ip, method, path, status.
    Empty/None optional fields are dropped to keep records compact.
    Never raises — logging must not take down the calling app.
    """
    now = datetime.now(timezone.utc)
    record = {
        "ts": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
        "app": app,
        "src_ip": src_ip,
        "method": method,
        "path": path,
        "status": int(status),
    }
    for k, v in optional.items():
        if v not in ("", None):
            record[k] = v
    line = json.dumps(record, ensure_ascii=False) + "\n"
    target = os.environ.get("AEGIS_FEED_PATH", DEFAULT_PATH)
    try:
        with open(target, "a", buffering=1) as f:
            f.write(line)
    except OSError:
        pass
