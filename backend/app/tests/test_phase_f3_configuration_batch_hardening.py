from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from app.core.exceptions import APIError
from app.schemas.configuration import ConfigurationStepRequest
from app.services.configuration_batches import _validated_apply_steps


FUNCTION_ID = UUID("20000000-0000-0000-0000-000000000099")


def _function_row(*, sensitive: bool = True):
    return SimpleNamespace(
        id=FUNCTION_ID,
        enabled=True,
        required_capabilities=["APPLY"],
        code="set_value",
        name="Set value",
        category="CUSTOM",
        description=None,
        parameter_schema={
            "parameters": [
                {
                    "name": "value",
                    "label": "Value",
                    "value_type": "STRING",
                    "required": True,
                    "sensitive": sensitive,
                }
            ]
        },
        execution_spec={},
        verification_spec={},
        rollback_spec={},
        default_order=0,
        is_destructive=False,
    )


def test_batch_apply_rejects_raw_sensitive_parameter_before_persistence():
    request = ConfigurationStepRequest(
        function_id=FUNCTION_ID,
        parameters={"value": "raw-secret-value"},
    )

    with pytest.raises(APIError) as raised:
        _validated_apply_steps([_function_row()], [request])

    assert raised.value.status_code == 422
    assert raised.value.detail["code"] == (
        "CONFIGURATION_SENSITIVE_PARAMETER_REFERENCE_REQUIRED"
    )


def test_batch_apply_persists_sensitive_parameter_as_env_reference_only():
    request = ConfigurationStepRequest(
        function_id=FUNCTION_ID,
        parameters={"value": "env://FTTW_BATCH_TEST_SECRET"},
    )

    validated = _validated_apply_steps([_function_row()], [request])

    assert validated == [
        {
            "function_id": str(FUNCTION_ID),
            "parameters": {"value": "env://FTTW_BATCH_TEST_SECRET"},
        }
    ]


def test_batch_apply_rejects_function_without_apply_capability():
    row = _function_row(sensitive=False)
    row.required_capabilities = ["CAPTURE"]
    request = ConfigurationStepRequest(
        function_id=FUNCTION_ID,
        parameters={"value": "safe"},
    )

    with pytest.raises(APIError) as raised:
        _validated_apply_steps([row], [request])

    assert raised.value.detail["code"] == "CONFIGURATION_BATCH_FUNCTION_NOT_APPLICABLE"


def test_batch_source_validates_payload_before_durable_batch_construction():
    root = Path(__file__).resolve().parents[1]
    source = (root / "services" / "configuration_batches.py").read_text(
        encoding="utf-8"
    )

    validation = source.index("operation_payload = await _validated_operation_payload")
    construction = source.index("batch = ConfigurationBatch(")
    assert validation < construction
    assert '"operation_payload": operation_payload' in source
    assert "CONFIGURATION_BATCH_TEMPLATE_VERSION_MISMATCH" in source
    assert "CONFIGURATION_BATCH_DEVICE_NOT_BOUND" in source


def test_batch_dispatch_isolates_f1_queue_validation_in_savepoint():
    root = Path(__file__).resolve().parents[1]
    source = (root / "services" / "configuration_batches.py").read_text(
        encoding="utf-8"
    )

    savepoint = source.index("async with db.begin_nested():")
    queue = source.index("operation, created = await queue_operation(")
    link = source.index("candidate.configuration_operation_id = operation.id")
    dispatch = source.index('"fttw.configuration.execute"')

    assert savepoint < queue < link < dispatch
    assert "created=False" in source
