from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from starlette.requests import Request

from app.api.router import api_router
from app.schemas.remote_access import (
    WebTLSCertificateInspectionRead,
    WebTLSReplaceRequest,
    WebTLSTrustRead,
    WebTLSTrustRequest,
)
from app.security.authorization import permission_for_request
from app.services import access_template_lifecycle, access_template_testing
from app.services.web_tls_runtime import resolve_verified_web_ssl_context
from app.services.web_tls_trust import _parse_certificate, observe_web_tls_certificate


BACKEND_ROOT = Path(__file__).resolve().parents[2]
MIGRATION = BACKEND_ROOT / "migrations" / "versions" / "0045_web_tls_trust.py"
TP3_EXTENSION = BACKEND_ROOT / "scripts" / "ci_route_permission_contract_tp3_extension.json"


def _request(path: str, method: str = "POST") -> Request:
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
            "client": ("tp3-test", 0),
            "server": ("tp3-test", 80),
            "route": SimpleNamespace(path=path),
        }
    )


def _self_signed_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "192.0.2.10")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("192.0.2.10"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def test_tp3_permission_mapping_is_exact_and_precedes_ssh_fallback():
    inspect_path = "/api/devices/{device_id}/remote-access/web/tls/inspect"
    trust_path = "/api/devices/{device_id}/remote-access/web/tls/trust"
    replace_path = "/api/devices/{device_id}/remote-access/web/tls/replace"

    assert permission_for_request(_request(inspect_path)) == "device.remote_access.web"
    assert permission_for_request(_request(trust_path)) == "device.remote_access.web.trust"
    assert permission_for_request(_request(replace_path)) == "device.remote_access.web.trust"


def test_tp3_adds_exactly_three_tls_api_operations():
    expected = {
        ("POST", "/api/devices/{device_id}/remote-access/web/tls/inspect"),
        ("POST", "/api/devices/{device_id}/remote-access/web/tls/trust"),
        ("POST", "/api/devices/{device_id}/remote-access/web/tls/replace"),
    }
    actual = set()
    for route in api_router.routes:
        if "/remote-access/web/tls/" not in route.path:
            continue
        for method in route.methods or set():
            if method not in {"HEAD", "OPTIONS"}:
                actual.add((method, route.path))
    assert actual == expected


def test_tp3_public_api_never_serializes_certificate_material():
    inspect_fields = set(WebTLSCertificateInspectionRead.model_fields)
    trust_fields = set(WebTLSTrustRead.model_fields)
    forbidden = {"certificate_der", "certificate_pem", "private_key", "password", "cookie", "ticket"}
    assert not (inspect_fields & forbidden)
    assert not (trust_fields & forbidden)
    assert WebTLSCertificateInspectionRead.model_fields["credentials_sent"].default is False
    assert WebTLSCertificateInspectionRead.model_fields["application_data_sent"].default is False


def test_tp3_trust_confirmation_requires_valid_sha256_and_explicit_replace_ack():
    valid = "ab" * 32
    assert WebTLSTrustRequest(expected_certificate_sha256=valid).expected_certificate_sha256 == valid
    with pytest.raises(ValueError):
        WebTLSTrustRequest(expected_certificate_sha256="abc")
    with pytest.raises(ValueError):
        WebTLSReplaceRequest(
            current_certificate_sha256=valid,
            expected_new_certificate_sha256="cd" * 32,
            acknowledge_certificate_change=False,
        )


def test_tp3_certificate_parser_returns_public_leaf_identity_only():
    observation = _parse_certificate(
        management_ip="192.0.2.10",
        port=443,
        compatibility_profile="MODERN",
        certificate_der=_self_signed_der(),
    )
    assert len(observation.certificate_sha256) == 64
    assert observation.management_ip == "192.0.2.10"
    assert observation.port == 443
    assert observation.self_signed is True
    assert observation.validity_state == "VALID"
    assert observation.san_ip == ("192.0.2.10",)


def test_certificate_inspection_sends_no_application_bytes(monkeypatch):
    certificate_der = _self_signed_der()

    class FakeSSLObject:
        def getpeercert(self, binary_form=False):
            assert binary_form is True
            return certificate_der

    class FakeWriter:
        def __init__(self):
            self.write_called = False
            self.closed = False

        def get_extra_info(self, name):
            assert name == "ssl_object"
            return FakeSSLObject()

        def write(self, _value):
            self.write_called = True
            raise AssertionError("TLS inspection must never send application bytes")

        async def drain(self):
            raise AssertionError("TLS inspection must never drain application bytes")

        def close(self):
            self.closed = True

        async def wait_closed(self):
            return None

    writer = FakeWriter()

    async def fake_open_connection(**kwargs):
        assert kwargs["host"] == "192.0.2.10"
        assert kwargs["port"] == 443
        assert kwargs["ssl"] is not None
        return object(), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    observation = asyncio.run(observe_web_tls_certificate("192.0.2.10", port=443))
    assert observation.certificate_der == certificate_der
    assert writer.write_called is False
    assert writer.closed is True


def test_internal_pin_is_authoritative_exact_and_has_no_fallback_after_link_exists():
    source = inspect.getsource(resolve_verified_web_ssl_context)
    internal_branch = source.index("if profile.web_tls_trust_id is not None")
    legacy_resolution = source.index("resolve_secret_reference(profile.web_tls_pinned_certificate_reference)")
    assert internal_branch < legacy_resolution
    assert "WEB_TLS_INTERNAL_TRUST_NOT_READY" in source
    assert "hashlib.sha256(presented_der).hexdigest()" in source
    assert "hmac.compare_digest" in source
    assert "The failed internal pin" not in source


def test_web_template_tests_verify_tls_before_secret_resolution():
    active_source = inspect.getsource(access_template_testing.test_access_template_connection)
    assert active_source.index("_prepare_web_transport") < active_source.index("resolved_secrets")

    revision_source = inspect.getsource(access_template_lifecycle.test_revision_connection)
    assert revision_source.index("_prepare_web_transport") < revision_source.index("resolved_revision_secrets")


def test_tp3_migration_and_route_extension_are_bounded():
    migration = MIGRATION.read_text(encoding="utf-8")
    extension = TP3_EXTENSION.read_text(encoding="utf-8")
    assert 'revision = "0045_web_tls_trust"' in migration
    assert 'down_revision = "0044_access_template_metadata"' in migration
    assert "device_web_tls_trusts" in migration
    assert "web_tls_trust_id" in migration
    assert "device.remote_access.web.trust" in migration
    assert "certificate_der" in migration
    assert "configuration_operations" not in migration
    assert "device.remote_access.web.trust" in extension
    assert extension.count('"/api/devices/{device_id}/remote-access/web/tls/') == 3
