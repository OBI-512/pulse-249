from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.services import configuration as configuration_service


class FakeDB:
    def __init__(self) -> None:
        self.commit_calls = 0

    async def commit(self) -> None:
        self.commit_calls += 1


class FakeAdapter:
    def __init__(self, captures) -> None:
        self._captures = list(captures)
        self.capture_calls = 0
        self.descriptor = SimpleNamespace(key="test.adapter")

    async def capture(self, _context):
        self.capture_calls += 1
        if not self._captures:
            raise AssertionError("Unexpected extra capture")
        return self._captures.pop(0)


def capture(payload: bytes, *, restorable: bool = True):
    return SimpleNamespace(payload=payload, restorable=restorable, metadata={})


def operation():
    return SimpleNamespace(
        id=uuid4(),
        device_id=uuid4(),
        template_version_id=uuid4(),
        actor_user_id=uuid4(),
        pre_change_snapshot_id=None,
    )


def test_stable_dual_capture_persists_one_prechange_checkpoint(monkeypatch):
    payload = b"hostname stable\n"
    adapter = FakeAdapter([capture(payload), capture(payload)])
    db = FakeDB()
    op = operation()
    persisted = []
    snapshot_id = uuid4()

    async def fake_persist(
        _db,
        *,
        operation,
        adapter,
        kind,
        result,
    ):
        persisted.append((operation, adapter, kind, result))
        return SimpleNamespace(id=snapshot_id, is_restorable=True), result.payload

    monkeypatch.setattr(configuration_service, "_persist_capture_result", fake_persist)

    result = asyncio.run(
        configuration_service._prepare_pre_change_snapshot(
            db,
            operation=op,
            context=SimpleNamespace(),
            adapter=adapter,
        )
    )

    assert result == snapshot_id
    assert op.pre_change_snapshot_id == snapshot_id
    assert adapter.capture_calls == 2
    assert len(persisted) == 1
    assert persisted[0][2] == "PRE_CHANGE"
    assert persisted[0][3].payload == payload
    assert db.commit_calls == 1


def test_unstable_dual_capture_fails_before_checkpoint_persistence(monkeypatch):
    adapter = FakeAdapter(
        [
            capture(b"hostname stable\n"),
            capture(b"hostname transient\n"),
        ]
    )
    db = FakeDB()
    op = operation()
    persist_calls = 0

    async def fake_persist(*_args, **_kwargs):
        nonlocal persist_calls
        persist_calls += 1
        raise AssertionError("Unstable capture must not be persisted")

    monkeypatch.setattr(configuration_service, "_persist_capture_result", fake_persist)

    with pytest.raises(
        configuration_service.ConfigurationVerificationError,
        match="CONFIGURATION_PRE_CHANGE_CAPTURE_UNSTABLE",
    ):
        asyncio.run(
            configuration_service._prepare_pre_change_snapshot(
                db,
                operation=op,
                context=SimpleNamespace(),
                adapter=adapter,
            )
        )

    assert adapter.capture_calls == 2
    assert persist_calls == 0
    assert db.commit_calls == 0
    assert op.pre_change_snapshot_id is None


def test_nonrestorable_capture_fails_before_checkpoint_persistence(monkeypatch):
    payload = b"hostname stable\n"
    adapter = FakeAdapter(
        [
            capture(payload),
            capture(payload, restorable=False),
        ]
    )
    db = FakeDB()
    op = operation()
    persist_calls = 0

    async def fake_persist(*_args, **_kwargs):
        nonlocal persist_calls
        persist_calls += 1
        raise AssertionError("Non-restorable capture must not be persisted")

    monkeypatch.setattr(configuration_service, "_persist_capture_result", fake_persist)

    with pytest.raises(
        configuration_service.ConfigurationTemplateError,
        match="CONFIGURATION_PRE_CHANGE_SNAPSHOT_NOT_RESTORABLE",
    ):
        asyncio.run(
            configuration_service._prepare_pre_change_snapshot(
                db,
                operation=op,
                context=SimpleNamespace(),
                adapter=adapter,
            )
        )

    assert adapter.capture_calls == 2
    assert persist_calls == 0
    assert db.commit_calls == 0
    assert op.pre_change_snapshot_id is None
