"""Audit timestamps come from the injected wall clock; the database is a disposable fake."""
from datetime import datetime, timedelta, timezone

from server.engine import Engine
from server.models import EventInput
from server.store import Store


WALL_START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_audit_timestamps_follow_wall_clock(tmp_path):
    clock = {"wall": WALL_START}
    engine = Engine(Store(tmp_path / "audit.db"), clock=lambda: clock["wall"])
    for wall_shift in (0, -3600, 3600):
        clock["wall"] = WALL_START + timedelta(seconds=wall_shift)
        result = engine.evaluate(EventInput(session_id="fake-clock-session", action="command", app="claude",
                                            content="git status"))
        assert result.created_at == clock["wall"].isoformat()
        assert engine.store.get_event(result.id)["created_at"] == result.created_at
