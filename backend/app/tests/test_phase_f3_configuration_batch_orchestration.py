from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest
from fastapi import Request
from pydantic import ValidationError

from app.celery_app.config import celery_app
from app.schemas.configuration_batches import (
    ConfigurationBatchCreate,
    ConfigurationBatchRead,
)
from app.security.authorization import permission_for_request
from app.security.permissions import Permission as PermissionCode
from app.services.configuration_batches import (
    batch_request_fingerprint,
    ordered_device_ids,
    target_idempotency_key,
    wave_numbers,
)
from app.settings import settings
from app.tasks.configuration_batches import (
    dispatch_configuration_batch,
    reconcile_configuration_batch,
    sweep_configuration_batches,
)


DEVICE_A = UUID("00000000-0000-0000-0000-000000000003")
DEVICE_B = UUID("00000000-0000-0000-0000-000000000001")
DEVICE_C = UUID("00000000-0000-0000-0000-000000000002")
SNAP_A = UUID("10000000-0000-0000-0000-000000000003")
SNAP_B = UUID("10000000-0000-0000-0000-000000000001")
SNAP_C = UUID("10000000-0000-0000-0000-000000000002")
FUNCTION_ID = UUID("20000000-0000-0000-0000-000000000001")


def _request(method: str, path: str) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("test", 80),
        }
    )


def test_batch_schema_enforces_operation_payload_shape():
    capture = ConfigurationBatchCreate(
        operation_type="CAPTURE",
        device_ids=[DEVICE_A],
    )
    assert capture.steps == []
    assert capture.snapshot_ids == {}

    apply = ConfigurationBatchCreate(
        operation_type="APPLY",
        device_ids=[DEVICE_A],
        steps=[{"function_id": FUNCTION_ID, "parameters": {"vlan": 100}}],
    )
    assert apply.steps[0].parameters == {"vlan": 100}

    restore = ConfigurationBatchCreate(
        operation_type="RESTORE",
        device_ids=[DEVICE_A, DEVICE_B],
        snapshot_ids={DEVICE_A: SNAP_A, DEVICE_B: SNAP_B},
    )
    assert len(restore.snapshot_ids) == 2

    with pytest.raises(ValidationError):
        ConfigurationBatchCreate(
            operation_type="APPLY",
            device_ids=[DEVICE_A],
        )
    with pytest.raises(ValidationError):
        ConfigurationBatchCreate(
            operation_type="RESTORE",
            device_ids=[DEVICE_A, DEVICE_B],
            snapshot_ids={DEVICE_A: SNAP_A},
        )


def test_target_order_deduplicates_and_is_deterministic():
    assert ordered_device_ids([DEVICE_A, DEVICE_C, DEVICE_B, DEVICE_A]) == [
        DEVICE_B,
        DEVICE_C,
        DEVICE_A,
    ]


def test_canary_and_wave_membership_are_deterministic():
    assert wave_numbers(
        total=10,
        rollout_mode="CANARY_PERCENTAGE",
        canary_percent=20,
    ) == [0, 0, 1, 1, 1, 1, 1, 1, 1, 1]
    assert wave_numbers(total=7, rollout_mode="WAVES", wave_size=3) == [
        0,
        0,
        0,
        1,
        1,
        1,
        2,
    ]
    assert wave_numbers(total=3, rollout_mode="ALL_AT_ONCE") == [0, 0, 0]


def test_batch_fingerprint_is_order_independent_for_same_target_set():
    first = ConfigurationBatchCreate(
        operation_type="RESTORE",
        device_ids=[DEVICE_A, DEVICE_B, DEVICE_C],
        snapshot_ids={DEVICE_A: SNAP_A, DEVICE_B: SNAP_B, DEVICE_C: SNAP_C},
        rollout_mode="WAVES",
        wave_size=2,
        not_before=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    second = ConfigurationBatchCreate(
        operation_type="RESTORE",
        device_ids=[DEVICE_C, DEVICE_A, DEVICE_B],
        snapshot_ids={DEVICE_C: SNAP_C, DEVICE_A: SNAP_A, DEVICE_B: SNAP_B},
        rollout_mode="WAVES",
        wave_size=2,
        not_before=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    ordered = ordered_device_ids(first.device_ids)
    assert batch_request_fingerprint(first, ordered) == batch_request_fingerprint(
        second, ordered_device_ids(second.device_ids)
    )


def test_target_idempotency_key_is_stable_and_bounded():
    batch_id = UUID("30000000-0000-0000-0000-000000000001")
    fingerprint = "a" * 64
    first = target_idempotency_key(
        batch_id=batch_id,
        device_id=DEVICE_A,
        request_fingerprint=fingerprint,
    )
    second = target_idempotency_key(
        batch_id=batch_id,
        device_id=DEVICE_A,
        request_fingerprint=fingerprint,
    )
    assert first == second
    assert first.startswith("f3-")
    assert len(first) <= 128


def test_batch_routes_have_explicit_http_permission_boundary():
    for method, path in (
        ("POST", "/api/configuration-batches"),
        ("GET", "/api/configuration-batches"),
        ("GET", f"/api/configuration-batches/{UUID(int=1)}"),
        ("POST", f"/api/configuration-batches/{UUID(int=1)}/pause"),
        ("POST", f"/api/configuration-batches/{UUID(int=1)}/resume"),
        ("POST", f"/api/configuration-batches/{UUID(int=1)}/abort"),
    ):
        assert permission_for_request(_request(method, path)) == (
            PermissionCode.DEVICE_CONFIGURATION_READ
        )


def test_batch_tasks_are_registered_routed_and_scheduled():
    assert dispatch_configuration_batch.name == "fttw.configuration.batch.dispatch"
    assert reconcile_configuration_batch.name == "fttw.configuration.batch.reconcile"
    assert sweep_configuration_batches.name == "fttw.configuration.batch.sweep"
    for name in (
        "fttw.configuration.batch.dispatch",
        "fttw.configuration.batch.reconcile",
        "fttw.configuration.batch.sweep",
    ):
        assert name in celery_app.tasks
        assert celery_app.conf.task_routes[name] == {"queue": "configuration"}
    entry = celery_app.conf.beat_schedule["dispatch-configuration-batches"]
    assert entry["task"] == "fttw.configuration.batch.sweep"
    assert entry["schedule"] == 5.0
    assert entry["options"]["queue"] == "configuration"


def test_batch_public_schema_does_not_expose_internal_request_payload():
    assert "request_summary" not in ConfigurationBatchRead.model_fields
    assert "authorization_scope" not in ConfigurationBatchRead.model_fields
    assert "request_fingerprint" not in ConfigurationBatchRead.model_fields


def test_batch_orchestrator_delegates_to_f1_and_never_constructs_operation_rows():
    root = Path(__file__).resolve().parents[1]
    source = (root / "services" / "configuration_batches.py").read_text(
        encoding="utf-8"
    )
    assert "queue_operation(" in source
    assert "ConfigurationOperation(" not in source
    assert "target.configuration_operation_id" in source
    assert "await db.commit()" in source
    assert '"fttw.configuration.execute"' in source
    assert source.index("candidate.configuration_operation_id = operation.id") < source.index(
        '"fttw.configuration.execute"'
    )
    assert "created=False" in source


def test_f3_bounds_are_explicit():
    assert settings.configuration_batch_max_targets == 100
    assert settings.configuration_batch_max_concurrency == 5
