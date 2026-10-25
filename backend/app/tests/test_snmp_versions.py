import asyncio
from unittest.mock import patch

from app.discovery.adapters.snmp import SNMPDiscoveryAdapter, _build_command
from app.discovery.models import DiscoveryContext


def test_v1_command_uses_community_without_leaking_to_metadata():
    context = DiscoveryContext(
        ip_address="192.0.2.1",
        snmp_version="1",
        snmp_community="SECRET-COMMUNITY",
        snmp_retries=1,
    )
    with patch("app.discovery.adapters.snmp.shutil.which", return_value="/usr/bin/snmpget"):
        command, version = _build_command(context)
    assert version == "1"
    assert "-v1" in command
    assert "SECRET-COMMUNITY" in command


def test_v3_authpriv_command_is_built_from_conditional_fields():
    context = DiscoveryContext(
        ip_address="192.0.2.2",
        snmp_version="3",
        snmp_v3_username="observer",
        snmp_v3_security_level="authPriv",
        snmp_v3_auth_protocol="SHA",
        snmp_v3_auth_password="AUTH-SECRET",
        snmp_v3_priv_protocol="AES",
        snmp_v3_priv_password="PRIV-SECRET",
    )
    with patch("app.discovery.adapters.snmp.shutil.which", return_value="/usr/bin/snmpget"):
        command, version = _build_command(context)
    assert version == "3"
    assert "-v3" in command
    assert "authPriv" in command
    assert "observer" in command
    assert "AUTH-SECRET" in command
    assert "PRIV-SECRET" in command


def test_custom_port_and_v3_context_are_applied_to_command():
    context = DiscoveryContext(
        ip_address="192.0.2.5",
        snmp_version="3",
        snmp_port=1161,
        snmp_v3_username="observer",
        snmp_v3_security_level="noAuthNoPriv",
        snmp_v3_context_name="monitoring",
    )
    with patch("app.discovery.adapters.snmp.shutil.which", return_value="/usr/bin/snmpget"):
        command, version = _build_command(context)
    assert version == "3"
    assert "-n" in command
    assert "monitoring" in command
    assert "udp:192.0.2.5:1161" in command


def test_success_result_redacts_community_and_v3_passwords():
    adapter = SNMPDiscoveryAdapter()
    context = DiscoveryContext(
        ip_address="192.0.2.3",
        snmp_version="2c",
        snmp_community="TOP-SECRET",
    )
    with patch(
        "app.discovery.adapters.snmp._run_snmpget",
        return_value=("router-01", 4.2, "2c"),
    ):
        result = asyncio.run(adapter.discover(context))
    assert result.success is True
    assert result.hostname == "router-01"
    serialized = repr(result.raw_data)
    assert "TOP-SECRET" not in serialized
    assert result.raw_data["snmp_version"] == "2c"
    assert result.raw_data["port"] == 161


def test_timeout_result_is_failure_without_secret_echo():
    adapter = SNMPDiscoveryAdapter()
    context = DiscoveryContext(
        ip_address="192.0.2.4",
        snmp_version="2c",
        snmp_community="TOP-SECRET",
    )
    with patch(
        "app.discovery.adapters.snmp._run_snmpget",
        side_effect=TimeoutError("SNMP_NO_RESPONSE"),
    ):
        result = asyncio.run(adapter.discover(context))
    assert result.success is False
    assert "TOP-SECRET" not in (result.message or "")
    assert "TOP-SECRET" not in repr(result.raw_data)
