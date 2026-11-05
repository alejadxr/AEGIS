"""The route table is the contract: every operator action must be mounted, with
the right method and the right auth dependency, and the frontend must not call
a path that does not exist.

Why this exists: the Settings page shipped a call to POST /response/webhook/test
that no router ever defined, and nothing noticed until a human clicked it.
"""
import importlib
import re
from pathlib import Path

import pytest

from app.core.auth import require_admin, require_analyst, require_viewer

ROOT = Path(__file__).resolve().parents[3]
MAIN_PY = ROOT / "backend" / "app" / "main.py"
API_TS = ROOT / "frontend" / "src" / "lib" / "api.ts"


def _app_routes():
    """Routes of the real app. If app.main cannot be imported in this
    environment (an optional dependency such as email-validator is absent),
    rebuild the table from main.py's own include_router lines instead of
    skipping: the prefixes and routers still come from the shipped source."""
    try:
        from app.main import app
        return list(app.routes), set()
    except Exception:
        pass
    from fastapi import FastAPI
    src = MAIN_PY.read_text()
    alias_to_module = {}
    for m in re.finditer(r"^from app\.api import (.+)$", src, re.M):
        for part in m.group(1).split(","):
            name, _, alias = part.strip().partition(" as ")
            alias_to_module[alias.strip() or name.strip()] = f"app.api.{name.strip()}"
    app = FastAPI()
    unimportable: set[str] = set()
    for m in re.finditer(r'^app\.include_router\((\w+)\.router,\s*prefix="([^"]*)"', src, re.M):
        mod = alias_to_module.get(m.group(1))
        if not mod:
            continue
        try:
            router = importlib.import_module(mod).router
        except Exception:
            # Not importable in this environment (e.g. onboarding needs
            # email-validator). Remember it so the frontend check does not call
            # its paths "missing"; the routes under test above all import.
            unimportable.add(mod.rsplit(".", 1)[-1])
            continue
        app.include_router(router, prefix=m.group(2))
    return list(app.routes), unimportable


@pytest.fixture(scope="module")
def table():
    return _app_routes()[0]


def _deps(dependant, seen=None):
    seen = seen if seen is not None else set()
    for d in dependant.dependencies:
        if d.call is not None:
            seen.add(d.call)
        _deps(d, seen)
    return seen


def _find(table, method, path):
    for r in table:
        if getattr(r, "path", None) == path and method in (getattr(r, "methods", None) or ()):
            return r
    return None


# (method, path, auth dependency that must be on the route)
EXPECTED = [
    # A. operator block
    ("POST", "/api/v1/firewall/blocked", require_admin),
    # B. safelist
    ("GET", "/api/v1/firewall/safelist", require_viewer),
    ("GET", "/api/v1/firewall/safelist/{category}", require_viewer),
    ("POST", "/api/v1/firewall/safelist/{category}", require_admin),
    ("DELETE", "/api/v1/firewall/safelist/{category}", require_admin),
    # C. human incident verdicts
    ("PATCH", "/api/v1/response/incidents/{incident_id}", require_analyst),
    # the dangling route the Settings page has always called
    ("POST", "/api/v1/response/webhook/test", require_admin),
    # pre-existing, relied on by the new flows (must not regress)
    ("DELETE", "/api/v1/firewall/blocked/{ip}", require_admin),
    ("POST", "/api/v1/response/actions/{action_id}/approve", require_analyst),
    ("POST", "/api/v1/rules/propose", require_admin),
]


@pytest.mark.parametrize("method,path,auth", EXPECTED, ids=[f"{m} {p}" for m, p, _ in EXPECTED])
def test_route_is_mounted_with_expected_auth(table, method, path, auth):
    route = _find(table, method, path)
    assert route is not None, f"{method} {path} is not mounted"
    assert auth in _deps(route.dependant), f"{method} {path} is missing {auth.__name__}"


def test_ask_route_requires_an_authenticated_context(table):
    from app.core.auth import get_auth_context
    route = _find(table, "POST", "/api/v1/ask")
    assert route is not None and get_auth_context in _deps(route.dependant)


def test_no_new_route_is_unauthenticated(table):
    """Every mutating operator route above resolves an AuthContext, none is open."""
    from app.core.auth import get_auth_context
    for method, path, _ in EXPECTED:
        route = _find(table, method, path)
        assert route is not None
        assert get_auth_context in _deps(route.dependant), f"{method} {path} has no auth at all"


# --- the frontend must not call a path the backend does not serve -------------

_CALL = re.compile(r"""request(?:<[^()]*?>)?\(\s*([`'"])(/[^`'"]*)\1""", re.S)
# Paths the client builds that this check cannot resolve statically.
_KNOWN_DYNAMIC_PREFIX_ONLY = ()


def _frontend_paths():
    src = API_TS.read_text()
    out = set()
    for m in _CALL.finditer(src):
        path = m.group(2).split("?")[0]
        kept = []
        for seg in path.split("/"):
            if "${" in seg and not seg.startswith("${"):
                kept.append(seg.split("${")[0])   # `/assets${qs}`: a query-string suffix, not a path part
                break
            kept.append(re.sub(r"\$\{[^}]*\}", "{x}", seg))
        out.add("/".join(kept))
    return out


def _matches(template_segments, path_segments):
    if len(template_segments) != len(path_segments):
        return False
    return all(t == p or t.startswith("{") or p == "{x}" for t, p in zip(template_segments, path_segments))


@pytest.mark.skipif(not API_TS.exists(), reason="frontend not present in this checkout")
def test_frontend_never_calls_a_nonexistent_route(table):
    unimportable = _app_routes()[1]
    served = [r.path[len("/api/v1"):].strip("/").split("/") for r in table
              if getattr(r, "path", "").startswith("/api/v1")]
    missing = []
    for p in sorted(_frontend_paths()):
        segs = p.strip("/").split("/")
        if segs[0] in unimportable:
            continue
        if not any(_matches(s, segs) for s in served):
            missing.append(p)
    assert not missing, f"frontend calls paths with no backend route: {missing}"


@pytest.mark.skipif(not API_TS.exists(), reason="frontend not present in this checkout")
def test_the_frontend_scanner_actually_sees_calls():
    """Guard the guard: if the regex stops matching, the test above passes vacuously."""
    paths = _frontend_paths()
    assert len(paths) > 50 and "/response/webhook/test" in paths and "/ask" in paths
