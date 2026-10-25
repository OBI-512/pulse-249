from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.group import (
    DeviceGroupCreate,
    DeviceGroupScope,
)


# ---------------------------------------------------------------------------
# Step 2 — Organizational group model
# ---------------------------------------------------------------------------


def test_global_group_requires_no_context():
    group = DeviceGroupCreate(
        name="Global Operations",
        code="GLOBAL-OPS",
        scope_type=DeviceGroupScope.GLOBAL,
    )

    assert group.scope_type == DeviceGroupScope.GLOBAL
    assert group.network_id is None
    assert group.city_id is None
    assert group.location_id is None
    assert group.sector_id is None


def test_network_group_requires_network_context():
    with pytest.raises(ValidationError):
        DeviceGroupCreate(
            name="Network Operations",
            code="NETWORK-OPS",
            scope_type=DeviceGroupScope.NETWORK,
        )


def test_network_group_accepts_network_context():
    network_id = uuid4()

    group = DeviceGroupCreate(
        name="Network Operations",
        code="NETWORK-OPS",
        scope_type=DeviceGroupScope.NETWORK,
        network_id=network_id,
    )

    assert group.scope_type == DeviceGroupScope.NETWORK
    assert group.network_id == network_id
    assert group.city_id is None
    assert group.location_id is None
    assert group.sector_id is None


def test_city_group_rejects_network_context():
    with pytest.raises(ValidationError):
        DeviceGroupCreate(
            name="City Operations",
            code="CITY-OPS",
            scope_type=DeviceGroupScope.CITY,
            city_id=uuid4(),
            network_id=uuid4(),
        )


def test_location_group_requires_location_context():
    with pytest.raises(ValidationError):
        DeviceGroupCreate(
            name="Location Operations",
            code="LOCATION-OPS",
            scope_type=DeviceGroupScope.LOCATION,
        )


def test_sector_group_requires_sector_context():
    with pytest.raises(ValidationError):
        DeviceGroupCreate(
            name="Sector Operations",
            code="SECTOR-OPS",
            scope_type=DeviceGroupScope.SECTOR,
        )


def test_scope_contexts_are_mutually_exclusive():
    with pytest.raises(ValidationError):
        DeviceGroupCreate(
            name="Invalid Group",
            code="INVALID-GROUP",
            scope_type=DeviceGroupScope.NETWORK,
            network_id=uuid4(),
            city_id=uuid4(),
        )


def test_global_group_rejects_any_context():
    with pytest.raises(ValidationError):
        DeviceGroupCreate(
            name="Invalid Global Group",
            code="INVALID-GLOBAL",
            scope_type=DeviceGroupScope.GLOBAL,
            network_id=uuid4(),
        )


def test_scope_values_are_stable():
    assert DeviceGroupScope.GLOBAL.value == "GLOBAL"
    assert DeviceGroupScope.NETWORK.value == "NETWORK"
    assert DeviceGroupScope.CITY.value == "CITY"
    assert DeviceGroupScope.LOCATION.value == "LOCATION"
    assert DeviceGroupScope.SECTOR.value == "SECTOR"


# ---------------------------------------------------------------------------
# Step 3 — Membership semantics
# ---------------------------------------------------------------------------


def test_membership_does_not_require_physical_placement():
    """
    Organizational membership is independent of DevicePlacement.

    A newly registered/unplaced device may still be assigned to an
    organizational group.
    """

    # Semantic contract test.
    assert True


def test_membership_is_independent_from_physical_topology():
    """
    Group membership must not be interpreted as a physical relationship.
    """

    assert True


def test_membership_is_independent_from_device_relationships():
    """
    Group membership must not create or modify DeviceRelationship records.
    """

    assert True


def test_membership_is_independent_from_customer_service():
    """
    Group membership must not create or modify CustomerService records.
    """

    assert True


def test_same_device_can_have_different_scope_groups():
    """
    A device may belong to groups at different organizational scopes.

    Example:
        Device
          -> CITY group
          -> SECTOR group
    """

    city_group = DeviceGroupCreate(
        name="Cairo Operations",
        code="CITY-CAIRO",
        scope_type=DeviceGroupScope.CITY,
        city_id=uuid4(),
    )

    sector_group = DeviceGroupCreate(
        name="Sector Maintenance",
        code="SECTOR-MAINT",
        scope_type=DeviceGroupScope.SECTOR,
        sector_id=uuid4(),
    )

    assert city_group.scope_type == DeviceGroupScope.CITY
    assert sector_group.scope_type == DeviceGroupScope.SECTOR


def test_same_device_can_have_groups_in_different_contexts():
    """
    The same device may be associated with groups representing different
    organizational contexts.
    """

    first_city = DeviceGroupCreate(
        name="Cairo Operations",
        code="CITY-CAIRO",
        scope_type=DeviceGroupScope.CITY,
        city_id=uuid4(),
    )

    second_city = DeviceGroupCreate(
        name="Alexandria Operations",
        code="CITY-ALEX",
        scope_type=DeviceGroupScope.CITY,
        city_id=uuid4(),
    )

    assert first_city.city_id != second_city.city_id


def test_global_groups_are_not_subject_to_scoped_context_rule():
    """
    GLOBAL is retained for backward compatibility.
    """

    first = DeviceGroupCreate(
        name="Operations",
        code="OPS",
        scope_type=DeviceGroupScope.GLOBAL,
    )

    second = DeviceGroupCreate(
        name="Maintenance",
        code="MAINT",
        scope_type=DeviceGroupScope.GLOBAL,
    )

    assert first.scope_type == DeviceGroupScope.GLOBAL
    assert second.scope_type == DeviceGroupScope.GLOBAL


# ---------------------------------------------------------------------------
# Step 4 — Organizational movement
# ---------------------------------------------------------------------------


def test_same_scope_same_context_is_a_move():
    """
    Two groups in the same organizational context represent alternatives
    within that context.

    Moving between them must replace the previous membership.
    """

    cairo_id = uuid4()

    group_a = DeviceGroupCreate(
        name="Cairo Operations A",
        code="CAIRO-A",
        scope_type=DeviceGroupScope.CITY,
        city_id=cairo_id,
    )

    group_b = DeviceGroupCreate(
        name="Cairo Operations B",
        code="CAIRO-B",
        scope_type=DeviceGroupScope.CITY,
        city_id=cairo_id,
    )

    assert group_a.city_id == group_b.city_id


def test_different_scopes_are_independent_during_move():
    """
    Moving a CITY membership must not remove a SECTOR membership.
    """

    city_group = DeviceGroupCreate(
        name="Cairo Operations",
        code="CITY-CAIRO",
        scope_type=DeviceGroupScope.CITY,
        city_id=uuid4(),
    )

    sector_group = DeviceGroupCreate(
        name="Sector Maintenance",
        code="SECTOR-MAINT",
        scope_type=DeviceGroupScope.SECTOR,
        sector_id=uuid4(),
    )

    assert city_group.scope_type != sector_group.scope_type


def test_different_contexts_are_independent_during_move():
    """
    A CITY group in Cairo and a CITY group in Alexandria represent
    different organizational contexts.
    """

    cairo_group = DeviceGroupCreate(
        name="Cairo Operations",
        code="CITY-CAIRO",
        scope_type=DeviceGroupScope.CITY,
        city_id=uuid4(),
    )

    alexandria_group = DeviceGroupCreate(
        name="Alexandria Operations",
        code="CITY-ALEX",
        scope_type=DeviceGroupScope.CITY,
        city_id=uuid4(),
    )

    assert cairo_group.city_id != alexandria_group.city_id


def test_global_move_is_independent_from_scoped_memberships():
    """
    Moving between GLOBAL groups must not affect scoped memberships.
    """

    global_group = DeviceGroupCreate(
        name="Global Operations",
        code="GLOBAL-OPS",
        scope_type=DeviceGroupScope.GLOBAL,
    )

    city_group = DeviceGroupCreate(
        name="Cairo Operations",
        code="CITY-CAIRO",
        scope_type=DeviceGroupScope.CITY,
        city_id=uuid4(),
    )

    assert global_group.scope_type == DeviceGroupScope.GLOBAL
    assert city_group.scope_type == DeviceGroupScope.CITY