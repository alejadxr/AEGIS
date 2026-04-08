"""
Signature updater (Task #6).

Pulls fresh signatures from upstream sources on a daily schedule and
caches a bundle that agents fetch via GET /antivirus/signatures:

  - YARA-Forge community ruleset (git pull of the mirror)
  - ClamAV main.cvd metadata (via freshclam — optional)
  - MalwareBazaar SHA256 daily hash list (abuse.ch)
  - VirusTotal API for unknown hashes (rate-limited, on-demand)

The bundle is cached in memory + on disk under
~/.aegis/backend/signatures/latest.json. Concurrency is safe because we
only write atomically via tempfile + rename.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import aiohttp

logger = logging.getLogger("aegis.av.signatures")

# Paths + URLs
MALWAREBAZAAR_RECENT = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
YARA_FORGE_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.yar"

DEFAULT_BUNDLE_DIR = Path.home() / ".aegis" / "backend" / "signatures"
BUNDLE_FILE = "latest.json"
UPDATE_INTERVAL_HOURS = 24


@dataclass
class SignatureBundle:
    version: str = "0"
    yara_rules: str = ""
    bad_hashes: list[str] = field(default_factory=list)
    generated_at: str = ""

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "yara_rules": self.yara_rules,
            "bad_hashes": self.bad_hashes,
            "generated_at": self.generated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SignatureBundle":
        return cls(
            version=d.get("version", "0"),
            yara_rules=d.get("yara_rules", ""),
            bad_hashes=list(d.get("bad_hashes", [])),
            generated_at=d.get("generated_at", ""),
        )


class SignatureUpdater:
    def __init__(self, bundle_dir: Path = DEFAULT_BUNDLE_DIR):
        self.bundle_dir = bundle_dir
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        self._bundle: Optional[SignatureBundle] = None
        self._task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    @property
    def bundle_path(self) -> Path:
        return self.bundle_dir / BUNDLE_FILE

    def current(self) -> SignatureBundle:
        """Return the in-memory bundle, loading from disk if needed."""
        if self._bundle is not None:
            return self._bundle
        if self.bundle_path.exists():
            try:
                with open(self.bundle_path, "r", encoding="utf-8") as f:
                    self._bundle = SignatureBundle.from_dict(json.load(f))
                    return self._bundle
            except Exception as e:
                logger.warning("couldn't load cached bundle: %s", e)
        # Empty fallback so agents can still boot
        self._bundle = SignatureBundle(
            version="bootstrap",
            yara_rules=_BUILTIN_YARA,
            bad_hashes=[],
            generated_at=datetime.utcnow().isoformat(),
        )
        return self._bundle

    async def start(self):
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self):
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    async def _loop(self):
        # Run immediately on start, then every 24h
        while True:
            try:
                await self.update_now()
            except Exception as e:
                logger.warning("signature update failed: %s", e)
            await asyncio.sleep(UPDATE_INTERVAL_HOURS * 3600)

    async def update_now(self) -> SignatureBundle:
        """Fetch fresh signatures from upstream and persist the bundle."""
        async with self._lock:
            bad_hashes: list[str] = []
            yara_rules: str = _BUILTIN_YARA

            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120),
            ) as sess:
                # MalwareBazaar recent hashes
                try:
                    async with sess.get(MALWAREBAZAAR_RECENT) as r:
                        if r.status == 200:
                            text = await r.text()
                            for line in text.splitlines():
                                line = line.strip()
                                if line and not line.startswith("#") and len(line) == 64:
                                    bad_hashes.append(line.lower())
                except Exception as e:
                    logger.debug("malwarebazaar pull failed: %s", e)

                # YARA-Forge core rules
                try:
                    async with sess.get(YARA_FORGE_URL, allow_redirects=True) as r:
                        if r.status == 200:
                            yara_rules = await r.text()
                except Exception as e:
                    logger.debug("yara-forge pull failed: %s", e)

            # Version = hash of everything so agents can trivially compare
            version_src = (yara_rules + "\n" + "\n".join(sorted(bad_hashes))).encode("utf-8")
            version = hashlib.sha256(version_src).hexdigest()[:16]

            bundle = SignatureBundle(
                version=version,
                yara_rules=yara_rules,
                bad_hashes=bad_hashes,
                generated_at=datetime.utcnow().isoformat(),
            )

            # Atomic write
            tmp = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(self.bundle_dir),
                delete=False,
                suffix=".tmp",
            )
            try:
                json.dump(bundle.to_dict(), tmp)
                tmp.flush()
                os.fsync(tmp.fileno())
            finally:
                tmp.close()
            os.replace(tmp.name, self.bundle_path)

            self._bundle = bundle
            logger.info(
                "signature bundle updated: version=%s yara=%d bytes hashes=%d",
                bundle.version,
                len(bundle.yara_rules),
                len(bundle.bad_hashes),
            )
            return bundle


# Fallback ruleset used until the first real pull lands. Catches EICAR and
# a few evergreen indicators so agents have something to work with.
_BUILTIN_YARA = r"""
rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
        author = "AEGIS"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "PowerShell with base64-encoded command"
        author = "AEGIS"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "-EncodedCommand" nocase
    condition:
        $a and ($b or $c)
}
"""


signature_updater = SignatureUpdater()
