from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.device import DeviceCreate, DeviceIPCreate, DeviceStatusUpdate, DeviceUpdate


def _device_type_id():
    return uuid4()


def test_device_create_normalizes_lifecycle_and_operational_state():
    payload = DeviceCreate(
        device_type_id=_device_type_id(),
        display_name="Test Device",
        management_ip="192.0.2.10",
        lifecycle_state="active",
        operational_state="up",
    )
    assert payload.lifecycle_state == "ACTIVE"
    assert payload.operational_state == "UP"


def test_device_create_rejects_decommissioned_initial_state():
    # Schema accepts the state so the API can return its explicit domain error.
    payload = DeviceCreate(
        device_type_id=_device_type_id(),
        display_name="Test Device",
        management_ip="192.0.2.10",
        lifecycle_state="DECOMMISSIONED",
    )
    assert payload.lifecycle_state == "DECOMMISSIONED"


def test_device_create_rejects_unknown_lifecycle_state():
    with pytest.raises(ValidationError):
        DeviceCreate(
            device_type_id=_device_type_id(),
            display_name="Test Device",
            management_ip="192.0.2.10",
            lifecycle_state="BROKEN_STATE",
        )


def test_device_update_rejects_unknown_operational_state():
    with pytest.raises(ValidationError):
        DeviceUpdate(operational_state="BROKEN_STATE")


def test_device_status_normalizes_states():
    payload = DeviceStatusUpdate(operational_state="degraded", lifecycle_state="maintenance")
    assert payload.operational_state == "DEGRADED"
    assert payload.lifecycle_state == "MAINTENANCE"


def test_primary_ip_must_be_management_is_api_domain_rule():
    payload = DeviceIPCreate(ip_address="192.0.2.10", is_primary=True, is_management=False)
    assert payload.is_primary is True
    assert payload.is_management is False


def test_ip_address_is_canonicalized():
    payload = DeviceIPCreate(ip_address="192.0.2.10")
    assert payload.ip_address == "192.0.2.10"
