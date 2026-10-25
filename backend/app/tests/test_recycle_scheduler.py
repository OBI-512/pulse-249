import asyncio
from uuid import uuid4

from app.celery_app.config import celery_app
from app.services.recycle_policies import PurgeSummary
from app.tasks import recycle_bin as task_module
from app.tasks.recycle_bin import purge_expired_recycle_bin


def test_recycle_purge_task_is_registered_and_scheduled():
    assert "fttw.recycle_bin.purge_expired" in celery_app.tasks
    assert purge_expired_recycle_bin.name == "fttw.recycle_bin.purge_expired"

    entry = celery_app.conf.beat_schedule["purge-expired-recycle-bin-batches"]
    assert entry["task"] == "fttw.recycle_bin.purge_expired"
    assert entry["schedule"] <= 3600
    assert entry["options"]["expires"] < entry["schedule"]


def test_scheduled_purge_serializes_summary_for_celery(monkeypatch):
    batch_id = uuid4()

    class FakeEngine:
        async def dispose(self):
            return None

    class FakeSession:
        def __init__(self):
            self.added = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def commit(self):
            return None

        async def rollback(self):
            return None

        def add(self, value):
            self.added.append(value)

    async def fake_purge_due_batches(db):
        assert isinstance(db, FakeSession)
        return PurgeSummary(considered=2, purged=1, failed=1, batch_ids=[batch_id])

    monkeypatch.setattr(task_module, "create_async_engine", lambda *args, **kwargs: FakeEngine())
    monkeypatch.setattr(task_module, "async_sessionmaker", lambda *args, **kwargs: lambda: FakeSession())
    monkeypatch.setattr(task_module, "purge_due_batches", fake_purge_due_batches)

    assert asyncio.run(task_module._purge_expired()) == {
        "considered": 2,
        "purged": 1,
        "failed": 1,
        "batch_ids": [str(batch_id)],
    }
