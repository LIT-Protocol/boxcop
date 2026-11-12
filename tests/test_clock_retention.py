"""Independent audit/TTL clocks; all events and databases are disposable fakes."""
from datetime import datetime, timedelta, timezone

import pytest

import server.engine as engine_module
from server.engine import Engine
from server.models import EventInput
from server.store import Store


WALL_START = datetime(2026, 1, 1, tzinfo=timezone.utc)
MONOTONIC_START = 1000.0


def event(**updates):
    data = dict(session_id="fake-clock-session", actor="human", role="engineering",
                action="paste", app="Fake browser", destination="https://example.invalid",
                content="FAKE_CLOCK_BODY")
    data.update(updates)
    return EventInput(**data)


@pytest.fixture
def clocked_engine(tmp_path):
    clocks = {"wall": WALL_START, "monotonic": MONOTONIC_START}
    store = Store(tmp_path / "audit.db")
    engine = Engine(store, clock=lambda: clocks["wall"],
                    monotonic_clock=lambda: clocks["monotonic"])
    return engine, clocks


@pytest.mark.parametrize("wall_shift", [-3600, 3600], ids=["backward", "forward"])
@pytest.mark.parametrize("elapsed", [299.0, 300.0], ids=["before-boundary", "at-boundary"])
def test_wall_clock_jump_does_not_change_lineage_window(clocked_engine, wall_shift, elapsed):
    engine, clocks = clocked_engine
    copied = engine.evaluate(event(action="copy", source="Workday", destination="clipboard"))
    clocks["wall"] = WALL_START + timedelta(seconds=wall_shift)
    clocks["monotonic"] = MONOTONIC_START + elapsed
    pasted = engine.evaluate(event())
    assert pasted.created_at == clocks["wall"].isoformat()
    assert pasted.decision.context_event_ids == [copied.id]
    assert "sensitive-lineage" in pasted.decision.policy_ids
    assert pasted.decision.action == "block"


def test_lineage_expires_after_301_monotonic_seconds_despite_wall_reversal(clocked_engine):
    engine, clocks = clocked_engine
    copied = engine.evaluate(event(action="copy", source="Workday", destination="clipboard"))
    clocks["wall"] = WALL_START + timedelta(seconds=100)
    clocks["monotonic"] = MONOTONIC_START + 100.0
    assert engine.evaluate(event()).decision.context_event_ids == [copied.id]
    # The wall clock reverses while elapsed time keeps advancing.
    clocks["wall"] = WALL_START + timedelta(seconds=1)
    clocks["monotonic"] = MONOTONIC_START + 301.0
    pasted = engine.evaluate(event())
    assert pasted.created_at == clocks["wall"].isoformat()
    assert pasted.decision.context_event_ids == []
    assert "sensitive-lineage" not in pasted.decision.policy_ids
    assert pasted.decision.action == "allow"
    assert not engine._lineage._sessions


def test_audit_timestamps_follow_wall_clock_not_elapsed_time(clocked_engine):
    engine, clocks = clocked_engine
    for wall_shift, elapsed in ((0, 0.0), (-3600, 1.0), (3600, 2.0)):
        clocks["wall"] = WALL_START + timedelta(seconds=wall_shift)
        clocks["monotonic"] = MONOTONIC_START + elapsed
        result = engine.evaluate(event())
        assert result.created_at == clocks["wall"].isoformat()
        assert engine.store.get_event(result.id)["created_at"] == result.created_at


def test_default_lineage_clock_uses_time_monotonic(tmp_path, monkeypatch):
    elapsed = [MONOTONIC_START]
    monkeypatch.setattr(engine_module, "monotonic", lambda: elapsed[0])
    engine = Engine(Store(tmp_path / "audit.db"), clock=lambda: WALL_START)
    copied = engine.evaluate(event(action="copy", source="Workday", destination="clipboard"))
    elapsed[0] += 300.0
    assert engine.evaluate(event()).decision.context_event_ids == [copied.id]
    elapsed[0] += 1.0
    assert engine.evaluate(event()).decision.context_event_ids == []
