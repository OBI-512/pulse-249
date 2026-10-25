from types import SimpleNamespace
import pytest
from app.schemas.group import DeviceGroupCreate

def test_sector_role_requires_sector_scope():
    with pytest.raises(ValueError):
        DeviceGroupCreate(name="Servers", code="SERVERS", device_scope="SERVER", sector_role="BACKHAUL")

def test_sector_role_allowed_for_sector_scope():
    model=DeviceGroupCreate(name="Backhaul", code="BH", device_scope="SECTOR", sector_role="BACKHAUL")
    assert model.sector_role.value == "BACKHAUL"
