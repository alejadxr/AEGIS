# backend/tests/unit/test_edr_event_map.py
from app.services.correlation_engine import _EDR_EVENT_MAP

def test_fim_kinds_are_mapped():
    # host_monitor emits these exact kinds; the map must recognize them.
    for kind in ("file_create", "file_modify", "file_delete"):
        assert kind in _EDR_EVENT_MAP, f"{kind} not mapped -> FIM events dropped"
