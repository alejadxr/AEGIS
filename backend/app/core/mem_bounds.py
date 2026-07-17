"""
Shared memory-bounding helpers for AEGIS hot-path in-memory trackers.

The detection engines (correlation_engine, dos_shield, log_watcher,
attack_detector) keep per-IP / per-(rule,IP) sliding-window state in plain
dicts. Deque *contents* are pruned by age on the hot path, but the dict KEYS
themselves accumulate one entry per unique source IP ever seen — under an
internet-facing honeypot receiving constant scanner traffic this leaks
memory proportional to the number of distinct IPs since process start.

These helpers evict IDLE / STALE keys only. They never touch state for an IP
that is still inside its tracking window, so detection behaviour for active
attackers is unchanged. Two complementary strategies are provided:

  * `prune_stale_*`  — drop keys whose newest timestamp is older than the
                        tracking window (called from a periodic sweep, off the
                        hot path). Also drops keys whose collection is empty.
  * `cap_lru`        — hard ceiling on the number of tracked keys; when the map
                        exceeds `max_keys`, evict the oldest-idle entries first
                        (called on insert as a backstop against a burst of
                        millions of unique IPs faster than the sweep runs).

All functions mutate the mapping in place and are O(n) over the map size; call
them from a background coroutine (every 30-60 s) rather than per request.
"""

from __future__ import annotations

from collections import deque
from typing import Callable, Hashable, MutableMapping


# Default hard ceiling on distinct tracked keys per structure. 50k unique IPs
# is far above any legitimate concurrent-attacker count while capping worst-case
# heap growth. Tunable per call site.
DEFAULT_MAX_KEYS = 50_000


def _deque_newest_ts(dq: deque, ts_getter: Callable) -> float | None:
    """Newest timestamp in a deque of items, or None if empty."""
    if not dq:
        return None
    return ts_getter(dq[-1])


def prune_stale_deque_map(
    mapping: MutableMapping[Hashable, deque],
    window_s: float,
    now: float,
    ts_getter: Callable = lambda item: item,
) -> int:
    """Evict keys from a `key -> deque` map when the deque is empty OR its
    newest entry is older than `now - window_s`.

    `ts_getter` extracts the float timestamp from a deque item; the default
    treats each item AS the timestamp. For deques of tuples like
    ``(timestamp, pattern)`` pass ``ts_getter=lambda item: item[0]``.

    Returns the number of keys evicted. Only removes IDLE keys — a key whose
    deque still holds an in-window timestamp is always retained.
    """
    cutoff = now - window_s
    stale = []
    for key, dq in mapping.items():
        newest = _deque_newest_ts(dq, ts_getter)
        if newest is None or newest < cutoff:
            stale.append(key)
    for key in stale:
        mapping.pop(key, None)
    return len(stale)


def prune_stale_ts_map(
    mapping: MutableMapping[Hashable, float],
    window_s: float,
    now: float,
) -> int:
    """Evict keys from a `key -> float_timestamp` map when the stored timestamp
    is older than `now - window_s`. Returns the number of keys evicted."""
    cutoff = now - window_s
    stale = [key for key, ts in mapping.items() if ts < cutoff]
    for key in stale:
        mapping.pop(key, None)
    return len(stale)


def prune_stale_list_map(
    mapping: MutableMapping[Hashable, list],
    window_s: float,
    now: float,
    ts_getter: Callable = lambda item: item,
) -> int:
    """Like `prune_stale_deque_map` but for `key -> list[timestamp]` maps.

    Assumes the list is append-ordered (newest last), so only the final element
    is inspected. Evicts empty lists and lists whose newest entry is stale.
    """
    cutoff = now - window_s
    stale = []
    for key, lst in mapping.items():
        if not lst or ts_getter(lst[-1]) < cutoff:
            stale.append(key)
    for key in stale:
        mapping.pop(key, None)
    return len(stale)


def cap_lru(
    mapping: MutableMapping[Hashable, object],
    max_keys: int,
    idle_ts: Callable[[object], float],
) -> int:
    """Hard-cap the number of keys in `mapping` at `max_keys`. When exceeded,
    evict the entries with the OLDEST idle timestamp first (LRU by last-seen).

    `idle_ts` maps a stored value to its last-activity float timestamp. Returns
    the number of keys evicted. Cheap no-op when under the cap.
    """
    over = len(mapping) - max_keys
    if over <= 0:
        return 0
    # Sort keys by their idle timestamp ascending; evict the coldest `over`.
    victims = sorted(mapping.items(), key=lambda kv: idle_ts(kv[1]))[:over]
    for key, _ in victims:
        mapping.pop(key, None)
    return len(victims)


def prune_stale_keyed_maps(
    last_seen: MutableMapping[Hashable, float],
    window_s: float,
    now: float,
    *companions: MutableMapping[Hashable, object],
) -> int:
    """Evict cold keys across several parallel maps that share the same key
    space, driven by a `key -> last_seen_ts` map.

    Any key whose `last_seen` timestamp is older than `now - window_s` (or that
    is absent from `last_seen`) is removed from `last_seen` AND from every map in
    `companions`. Keeps the phase-set / alert-timestamp maps of the campaign
    tracker bounded without dropping a still-active IP. Returns keys evicted."""
    cutoff = now - window_s
    stale = [key for key, ts in last_seen.items() if ts < cutoff]
    for key in stale:
        last_seen.pop(key, None)
        for comp in companions:
            comp.pop(key, None)
    return len(stale)
