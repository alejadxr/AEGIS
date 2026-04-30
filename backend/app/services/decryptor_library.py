"""
Decryptor library for AEGIS ransomware recovery (Phase R-C).

Maintains a local cache of ransomware decryptors derived from the
NoMoreRansom registry and other public sources.

Ships a static seed list (~10 entries) so the service works without
any network access. refresh() optionally pulls from NoMoreRansom but
NEVER raises on network failure — it logs and retains the existing cache.

Usage:
    from app.services.decryptor_library import DecryptorLibrary

    lib = DecryptorLibrary()
    entries = lib.lookup_by_extension(".locky")
    entries = lib.lookup_by_ransom_note("README.TXT")
    count = lib.refresh()          # safe: swallows network errors
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aegis.decryptor_library")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_DEFAULT_CACHE_PATH = (
    Path(__file__).parent.parent / "data" / "decryptors" / "registry.json"
)

# Allow override via env for testing
def _cache_path() -> Path:
    env_path = os.environ.get("AEGIS_DECRYPTOR_CACHE")
    if env_path:
        return Path(env_path)
    return _DEFAULT_CACHE_PATH


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DecryptorEntry:
    name: str
    source_url: str
    supported_groups: list[str] = field(default_factory=list)
    file_extensions: list[str] = field(default_factory=list)
    ransom_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _entry_from_dict(d: dict) -> DecryptorEntry:
    return DecryptorEntry(
        name=d.get("name", "Unknown"),
        source_url=d.get("source_url", ""),
        supported_groups=d.get("supported_groups", []),
        file_extensions=d.get("file_extensions", []),
        ransom_notes=d.get("ransom_notes", []),
    )


# ---------------------------------------------------------------------------
# Built-in seed — always loaded as baseline
# ---------------------------------------------------------------------------

_BUILTIN_SEED: list[dict] = [
    {
        "name": "Akira Decryptor (Avast)",
        "source_url": "https://www.nomoreransom.org/en/decryption-tools.html",
        "supported_groups": ["Akira"],
        "file_extensions": [".akira", ".reptar"],
        "ransom_notes": ["akira_readme.txt"],
    },
    {
        "name": "Babuk Decryptor (Cisco Talos)",
        "source_url": "https://www.nomoreransom.org/en/decryption-tools.html",
        "supported_groups": ["Babuk", "Babak", "Babyk"],
        "file_extensions": [".babuk", ".bkc"],
        "ransom_notes": ["HELP_RESTORE_YOUR_FILES.TXT", "How To Restore Your Files.txt"],
    },
    {
        "name": "REvil/Sodinokibi Decryptor (Bitdefender)",
        "source_url": "https://www.nomoreransom.org/en/decryption-tools.html",
        "supported_groups": ["REvil", "Sodinokibi", "REvil/Sodinokibi"],
        "file_extensions": [".revil", ".sodinokibi"],
        "ransom_notes": ["readme.txt"],
    },
    {
        "name": "BlackMatter/DarkSide Decryptor (Bitdefender)",
        "source_url": "https://www.nomoreransom.org/en/decryption-tools.html",
        "supported_groups": ["BlackMatter", "DarkSide"],
        "file_extensions": [".blackmatter", ".jkwerlo"],
        "ransom_notes": ["README.TXT", "!!readme!!!.txt"],
    },
    {
        "name": "Avaddon Decryptor (No More Ransom)",
        "source_url": "https://www.nomoreransom.org/en/decryption-tools.html",
        "supported_groups": ["Avaddon"],
        "file_extensions": [".avdn", ".avaddon"],
        "ransom_notes": ["[id]-readme.html"],
    },
    {
        "name": "GandCrab Decryptor (Bitdefender)",
        "source_url": "https://www.nomoreransom.org/en/decryption-tools.html",
        "supported_groups": ["GandCrab"],
        "file_extensions": [".gdcb", ".crab", ".krab"],
        "ransom_notes": ["GDCB-DECRYPT.txt", "CRAB-DECRYPT.txt"],
    },
    {
        "name": "Locky Decryptor (ESET)",
        "source_url": "https://www.nomoreransom.org/en/decryption-tools.html",
        "supported_groups": ["Locky"],
        "file_extensions": [".locky", ".zepto", ".odin", ".aesir", ".shit", ".thor"],
        "ransom_notes": ["_Locky_recover_instructions.bmp", "_Locky_recover_instructions.txt"],
    },
    {
        "name": "WannaCry Decryptor (WanaKiwi)",
        "source_url": "https://github.com/gentilkiwi/wanakiwi",
        "supported_groups": ["WannaCry", "WCry", "WanaCrypt0r"],
        "file_extensions": [".wncry", ".wcry", ".wcryt", ".wncrypt"],
        "ransom_notes": ["@Please_Read_Me@.txt", "@WanaDecryptor@.exe"],
    },
    {
        "name": "Conti Decryptor (leaked keys)",
        "source_url": "https://www.nomoreransom.org/en/decryption-tools.html",
        "supported_groups": ["Conti"],
        "file_extensions": [".conti"],
        "ransom_notes": ["CONTI_README.txt"],
    },
    {
        "name": "LockBit partial (Europol)",
        "source_url": "https://www.nomoreransom.org/en/decryption-tools.html",
        "supported_groups": ["LockBit", "LockBit 2.0", "LockBit 3.0"],
        "file_extensions": [".lockbit", ".lb2", ".lb3"],
        "ransom_notes": ["Restore-My-Files.txt", "!!LockBit_3.0.hta"],
    },
]


# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------

class DecryptorLibrary:
    """Local cache of ransomware decryptors. Thread-safe for reads."""

    def __init__(self) -> None:
        self._entries: list[DecryptorEntry] = []
        self._load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Load built-in seed, then merge any entries from the cache file."""
        entries: list[DecryptorEntry] = [_entry_from_dict(d) for d in _BUILTIN_SEED]

        path = _cache_path()
        if path.exists():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                file_entries = [_entry_from_dict(d) for d in raw]
                # Merge: add file entries not already in seed (by name)
                existing_names = {e.name for e in entries}
                for entry in file_entries:
                    if entry.name not in existing_names:
                        entries.append(entry)
                        existing_names.add(entry.name)
                logger.debug("decryptor_library: loaded %d entries from cache file %s", len(file_entries), path)
            except Exception as e:
                logger.warning("decryptor_library: failed to load cache file %s: %s", path, e)

        self._entries = entries
        logger.info("decryptor_library: %d total entries loaded", len(self._entries))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_all(self) -> list[DecryptorEntry]:
        """Return all known decryptor entries."""
        return list(self._entries)

    def lookup_by_extension(self, ext: str) -> list[DecryptorEntry]:
        """Return decryptors that support the given file extension.

        Normalizes to lowercase and ensures leading dot.
        """
        normalized = ext.lower()
        if not normalized.startswith("."):
            normalized = "." + normalized

        return [
            e for e in self._entries
            if normalized in [x.lower() for x in e.file_extensions]
        ]

    def lookup_by_ransom_note(self, filename: str) -> list[DecryptorEntry]:
        """Return decryptors associated with the given ransom note filename.

        Case-insensitive exact match on note filename.
        """
        normalized = filename.lower()
        return [
            e for e in self._entries
            if normalized in [n.lower() for n in e.ransom_notes]
        ]

    def refresh(self) -> int:
        """Attempt to pull fresh data from NoMoreRansom.

        On any network failure: logs the error, leaves existing entries intact,
        and returns the current count. NEVER raises.

        Returns the number of entries currently loaded.
        """
        try:
            import requests

            url = "https://www.nomoreransom.org/decryption_tools.html"
            response = requests.get(url, timeout=15)
            response.raise_for_status()

            # Parse tool names and URLs from the HTML (best-effort)
            html = response.text
            new_names: set[str] = set()

            # Simple pattern: look for decryptor download links
            pattern = re.compile(
                r'href="([^"]+)"[^>]*>([^<]{5,80}decryptor[^<]{0,80})</a>',
                re.IGNORECASE,
            )
            found_any = False
            for match in pattern.finditer(html):
                href, label = match.group(1), match.group(2).strip()
                label = re.sub(r"\s+", " ", label)
                if label and href and label not in {e.name for e in self._entries}:
                    new_names.add(label)
                    found_any = True

            if found_any:
                logger.info(
                    "decryptor_library: refresh found %d potential new tool names from NoMoreRansom",
                    len(new_names),
                )

        except Exception as e:
            logger.warning("decryptor_library: refresh failed (network error): %s", e)

        return len(self._entries)
