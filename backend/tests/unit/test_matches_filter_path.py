# backend/tests/unit/test_matches_filter_path.py
from app.services.correlation_engine import _matches_filter

def test_path_contains_matches_request_path_field():
    # Web events from event_normalizer carry `request_path`, not `path`.
    event = {"request_path": "/index.php?q=UNION SELECT"}
    filt = {"path_contains": ["UNION", "SELECT"]}
    assert _matches_filter(event, filt) is True

def test_path_contains_still_matches_legacy_path_field():
    # FIM/host events use `path`; must keep working.
    event = {"path": "/etc/passwd"}
    filt = {"path_contains": ["/etc/passwd"]}
    assert _matches_filter(event, filt) is True

def test_path_contains_is_case_insensitive():
    # Mixed-case source must match a lowercase fragment. NOTE: the payload uses
    # literal spaces (not '+') so the multi-word fragment "union select" can match.
    event = {"request_path": "/x?q=UnIoN SeLeCt 1"}
    filt = {"path_contains": ["union select"]}
    assert _matches_filter(event, filt) is True
