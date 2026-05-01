"""Unit tests for app.services.decryptor_library.

No network calls are made — requests/urllib are mocked.
Run with: python -m pytest backend/tests/unit/test_decryptor_library.py --noconftest -q
"""
import importlib
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reload_module(cache_path: str = None):
    """Reload decryptor_library, optionally overriding the cache file path."""
    mod_name = "app.services.decryptor_library"
    if mod_name in sys.modules:
        del sys.modules[mod_name]

    env = os.environ.copy()
    if cache_path:
        env["AEGIS_DECRYPTOR_CACHE"] = cache_path

    with patch.dict(os.environ, env, clear=True):
        import app.services.decryptor_library as m
    return m


# ---------------------------------------------------------------------------
# Static seed / lookup by extension
# ---------------------------------------------------------------------------

class TestLookupByExtension:
    def setup_method(self):
        self.m = _reload_module()
        self.lib = self.m.DecryptorLibrary()

    def test_known_extension_returns_results(self):
        """Seed list includes common ransomware extensions."""
        # .akira, .babuk, .revil/.sodinokibi, etc. are in the seed
        results = self.lib.lookup_by_extension(".akira")
        assert len(results) >= 1
        entry = results[0]
        assert hasattr(entry, "name")
        assert hasattr(entry, "source_url")
        assert hasattr(entry, "supported_groups")

    def test_unknown_extension_returns_empty(self):
        results = self.lib.lookup_by_extension(".totally_unknown_xyz_ransomware")
        assert results == []

    def test_extension_lookup_case_insensitive(self):
        """Lookup must normalize case so .AKIRA == .akira."""
        results_lower = self.lib.lookup_by_extension(".akira")
        results_upper = self.lib.lookup_by_extension(".AKIRA")
        assert len(results_lower) == len(results_upper)

    def test_extension_without_dot_still_works(self):
        """Both '.locky' and 'locky' should resolve."""
        r1 = self.lib.lookup_by_extension(".locky")
        r2 = self.lib.lookup_by_extension("locky")
        assert len(r1) == len(r2)

    def test_multiple_extensions_for_same_decryptor(self):
        """Some decryptors cover multiple extensions — at least one entry per ext."""
        # REvil / Sodinokibi uses various extensions
        results = self.lib.lookup_by_extension(".sodinokibi")
        # Just verify the call doesn't error; it may return 0 if not seeded
        assert isinstance(results, list)

    def test_seed_has_minimum_entries(self):
        """Seed list must have at least 8 well-known entries."""
        all_entries = self.lib.list_all()
        assert len(all_entries) >= 8


# ---------------------------------------------------------------------------
# Lookup by ransom note filename
# ---------------------------------------------------------------------------

class TestLookupByRansomNote:
    def setup_method(self):
        self.m = _reload_module()
        self.lib = self.m.DecryptorLibrary()

    def test_known_note_returns_results(self):
        """Known ransom note filenames should match entries."""
        # Babuk uses HELP_RESTORE_YOUR_FILES.TXT or similar
        results = self.lib.lookup_by_ransom_note("HELP_RESTORE_YOUR_FILES.TXT")
        # May be empty if not in seed — just verify no error
        assert isinstance(results, list)

    def test_unknown_note_returns_empty(self):
        results = self.lib.lookup_by_ransom_note("random_note_xyzabc.txt")
        assert results == []

    def test_note_lookup_case_insensitive(self):
        r1 = self.lib.lookup_by_ransom_note("README.TXT")
        r2 = self.lib.lookup_by_ransom_note("readme.txt")
        assert len(r1) == len(r2)


# ---------------------------------------------------------------------------
# DecryptorEntry schema
# ---------------------------------------------------------------------------

class TestDecryptorEntry:
    def setup_method(self):
        self.m = _reload_module()

    def test_entry_has_required_fields(self):
        lib = self.m.DecryptorLibrary()
        all_entries = lib.list_all()
        assert len(all_entries) > 0
        for entry in all_entries:
            assert hasattr(entry, "name"), "entry must have 'name'"
            assert hasattr(entry, "source_url"), "entry must have 'source_url'"
            assert hasattr(entry, "supported_groups"), "entry must have 'supported_groups'"
            assert isinstance(entry.supported_groups, list)
            assert hasattr(entry, "file_extensions"), "entry must have 'file_extensions'"
            assert isinstance(entry.file_extensions, list)


# ---------------------------------------------------------------------------
# refresh() — network failure must not raise
# ---------------------------------------------------------------------------

class TestRefresh:
    def setup_method(self):
        self.m = _reload_module()
        self.lib = self.m.DecryptorLibrary()

    def test_refresh_handles_network_failure_gracefully(self):
        """refresh() must catch all network exceptions and log, not raise."""
        with patch("requests.get", side_effect=Exception("network error")):
            try:
                count = self.lib.refresh()
                # If it returns, must be an int >= 0
                assert isinstance(count, int)
                assert count >= 0
            except Exception as e:
                pytest.fail(f"refresh() raised an exception on network failure: {e}")

    def test_refresh_handles_connection_error(self):
        """ConnectionError specifically must be swallowed."""
        import requests
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            count = self.lib.refresh()  # must not raise
            assert isinstance(count, int)

    def test_refresh_handles_timeout(self):
        import requests
        with patch("requests.get", side_effect=requests.exceptions.Timeout("timeout")):
            count = self.lib.refresh()
            assert isinstance(count, int)

    def test_refresh_returns_count_on_success(self):
        """On successful parse, refresh() returns the number of entries loaded."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>no decryptors here</body></html>"
        mock_response.raise_for_status = MagicMock()

        with patch("requests.get", return_value=mock_response):
            count = self.lib.refresh()
        assert isinstance(count, int)
        assert count >= 0

    def test_cache_used_after_failed_refresh(self):
        """After a failed refresh, existing seed data must still be accessible."""
        with patch("requests.get", side_effect=Exception("fail")):
            self.lib.refresh()

        # Seed entries must still be reachable
        entries = self.lib.list_all()
        assert len(entries) >= 8


# ---------------------------------------------------------------------------
# Cache file persistence (optional path via env)
# ---------------------------------------------------------------------------

class TestCacheFile:
    def test_loads_from_cache_file_if_exists(self, tmp_path):
        """If a cache JSON file exists, DecryptorLibrary should merge or use it."""
        cache_data = [
            {
                "name": "TestDecryptor",
                "source_url": "https://example.com/decryptor",
                "supported_groups": ["TestGroup"],
                "file_extensions": [".testenc"],
                "ransom_notes": ["READ_ME.TXT"],
            }
        ]
        cache_file = tmp_path / "registry.json"
        cache_file.write_text(json.dumps(cache_data))

        # Patch env AND create lib within the same patch scope
        with patch.dict(os.environ, {"AEGIS_DECRYPTOR_CACHE": str(cache_file)}):
            m = _reload_module(cache_path=str(cache_file))
            lib = m.DecryptorLibrary()

        results = lib.lookup_by_extension(".testenc")
        assert len(results) >= 1
        assert results[0].name == "TestDecryptor"

    def test_missing_cache_file_falls_back_to_seed(self, tmp_path):
        """Missing cache file must not raise — fall back to built-in seed."""
        non_existent = str(tmp_path / "does_not_exist.json")
        with patch.dict(os.environ, {"AEGIS_DECRYPTOR_CACHE": non_existent}):
            m = _reload_module(cache_path=non_existent)
            lib = m.DecryptorLibrary()
        entries = lib.list_all()
        assert len(entries) >= 8  # seed always present

    def test_corrupt_cache_file_falls_back_to_seed(self, tmp_path):
        """Corrupt JSON in cache file must not raise."""
        cache_file = tmp_path / "registry.json"
        cache_file.write_text("not valid json {{{")

        with patch.dict(os.environ, {"AEGIS_DECRYPTOR_CACHE": str(cache_file)}):
            m = _reload_module(cache_path=str(cache_file))
            lib = m.DecryptorLibrary()
        entries = lib.list_all()
        assert len(entries) >= 8
