import pytest

from app.core.exceptions import APIError
from app.services.access_template_secret_hygiene import calculate_secret_key_transition


def test_snmp_v2_to_v3_transition_drops_community_and_requires_new_v3_material():
    resulting, stale = calculate_secret_key_transition(
        protocol="SNMP",
        protocol_variant="V3",
        existing_keys={"community"},
        changes={"security_name": object(), "auth_secret": object()},
    )
    assert resulting == {"security_name", "auth_secret"}
    assert stale == {"community"}


def test_snmp_v3_to_v2_transition_drops_v3_secret_rows():
    resulting, stale = calculate_secret_key_transition(
        protocol="SNMP",
        protocol_variant="V2C",
        existing_keys={"security_name", "auth_secret", "privacy_secret"},
        changes={"community": object()},
    )
    assert resulting == {"community"}
    assert stale == {"security_name", "auth_secret", "privacy_secret"}


def test_irrelevant_new_snmp_secret_is_rejected_for_selected_variant():
    with pytest.raises(APIError) as exc:
        calculate_secret_key_transition(
            protocol="SNMP",
            protocol_variant="V2C",
            existing_keys=set(),
            changes={"community": object(), "security_name": object()},
        )
    assert exc.value.detail["code"] == "ACCESS_TEMPLATE_SECRET_KEY_INVALID"


def test_explicit_removal_of_already_obsolete_key_is_allowed():
    resulting, stale = calculate_secret_key_transition(
        protocol="SNMP",
        protocol_variant="V2C",
        existing_keys={"community", "security_name"},
        changes={"security_name": None},
    )
    assert resulting == {"community"}
    assert stale == {"security_name"}


def test_web_none_prunes_previously_stored_device_login_credentials():
    resulting, stale = calculate_secret_key_transition(
        protocol="WEB",
        protocol_variant="NONE",
        existing_keys={"username", "password"},
        changes={},
    )
    assert resulting == set()
    assert stale == {"username", "password"}


def test_web_none_rejects_new_credentials():
    with pytest.raises(APIError) as exc:
        calculate_secret_key_transition(
            protocol="WEB",
            protocol_variant="NONE",
            existing_keys=set(),
            changes={"username": object(), "password": object()},
        )
    assert exc.value.detail["code"] == "ACCESS_TEMPLATE_SECRET_KEY_INVALID"
