"""Single source of truth for the AEGIS version.

Four different versions used to be declared independently and had all drifted
apart: `main.py` reported 1.6.4.9 on /health, `auto_updater.py` believed it was
running 1.4.0, a smoke script asserted 1.6.3.9, and the README badge and
frontend package.json said 1.6.5.1.

That was not merely untidy. `auto_updater` compares CURRENT_VERSION against the
newest GitHub release to decide whether an update exists, so a stale constant
made AEGIS permanently report "update available"; and the smoke test asserted a
/health version the API had not returned for three releases, so it failed for a
reason that had nothing to do with the deployment being healthy.

Anything that needs the version imports it from here. The one copy that cannot
(frontend/package.json, which npm owns) is checked against this file by
scripts/check_version_sync.py.
"""

__version__ = "1.7.14"
