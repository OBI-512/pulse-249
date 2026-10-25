from app.availability.service import operational_state_from_availability


def test_authoritative_availability_maps_to_operational_state():
    assert operational_state_from_availability("ONLINE") == "UP"
    assert operational_state_from_availability("ONLINE", manual_degraded_override=True) == "DEGRADED"
    assert operational_state_from_availability("OFFLINE") == "DOWN"
    assert operational_state_from_availability("OFFLINE", manual_degraded_override=True) == "DOWN"
    assert operational_state_from_availability("SUSPECT") == "UNKNOWN"
    assert operational_state_from_availability("UNKNOWN") == "UNKNOWN"


def test_maintenance_preserves_last_operational_state_and_decommission_fails_closed():
    assert operational_state_from_availability("MAINTENANCE", current_operational_state="UP") == "UP"
    assert operational_state_from_availability("MAINTENANCE", current_operational_state="DEGRADED") == "DEGRADED"
    assert operational_state_from_availability("ONLINE", lifecycle_state="DECOMMISSIONED") == "UNKNOWN"
