from __future__ import annotations

import asyncio
import json
from pathlib import Path
from uuid import uuid4

import pytest

from app.configuration.artifact_edge import (
    ConfigurationArtifactEdgeError,
    build_edge_attestation_signature,
    resolve_effective_artifact_source,
)
from app.configuration.artifact_leases import (
    ArtifactLeaseStore,
    ConfigurationArtifactLeaseError,
)
from app.settings import settings


BACKEND = Path(__file__).resolve().parents[2]


class FakeRedis:
    def __init__(self):
        self.data: dict[str, str] = {}

    async def set(self, key, value, *, ex=None, nx=False, **_kwargs):
        if nx and str(key) in self.data:
            return False
        self.data[str(key)] = str(value)
        return True

    async def eval(self, _script, _keys, key, source_ip):
        raw = self.data.get(str(key))
        if raw is None:
            return ["MISSING"]
        lease = json.loads(raw)
        if lease["expected_source_ip"] != source_ip:
            return ["SOURCE_MISMATCH"]
        if int(lease["read_count"]) >= int(lease["max_reads"]):
            self.data.pop(str(key), None)
            return ["READ_LIMIT"]
        lease["read_count"] = int(lease["read_count"]) + 1
        self.data[str(key)] = json.dumps(lease, sort_keys=True, separators=(",", ":"))
        return ["OK", self.data[str(key)]]

    async def delete(self, key):
        self.data.pop(str(key), None)
        return 1


def _key_bytes() -> bytes:
    return bytes(range(32))


def _key_hex() -> str:
    return _key_bytes().hex()


def _headers(*, source: str, timestamp: int, nonce: str, path: str) -> dict[str, str]:
    signature = build_edge_attestation_signature(
        method="GET",
        path=path,
        source_ip=source,
        timestamp=timestamp,
        nonce=nonce,
        key=_key_bytes(),
    )
    return {
        "x-fttw-edge-version": "1",
        "x-fttw-edge-source": source,
        "x-fttw-edge-timestamp": str(timestamp),
        "x-fttw-edge-nonce": nonce,
        "x-fttw-edge-signature": signature,
    }


def test_edge_signature_matches_cross_runtime_known_vector():
    path = "/configuration-artifacts/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789_-"
    signature = build_edge_attestation_signature(
        method="GET",
        path=path,
        source_ip="192.0.2.4",
        timestamp=1750000000,
        nonce="nonce-test-0123456789",
        key=_key_bytes(),
    )
    assert signature == "4f165781d3845e3b19fe1f6fce5846b62ce8f1f360db8d7836edcb0196791290"


def test_valid_edge_attestation_preserves_original_source_and_blocks_replay(monkeypatch):
    monkeypatch.setenv("FTTW_CONFIGURATION_ARTIFACT_EDGE_HMAC_KEY", _key_hex())
    monkeypatch.setattr(settings, "configuration_artifact_trusted_edge_peers", "172.24.0.1")
    monkeypatch.setattr(settings, "configuration_artifact_edge_attestation_max_age_seconds", 15)
    monkeypatch.setattr(settings, "configuration_artifact_lease_ttl_seconds", 90)
    monkeypatch.setattr(settings, "configuration_artifact_lease_max_reads", 4)

    fake = FakeRedis()
    store = ArtifactLeaseStore(fake)
    timestamp = 1750000000
    path = "/configuration-artifacts/edge-test-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    headers = _headers(
        source="192.0.2.4",
        timestamp=timestamp,
        nonce="valid-edge-nonce-0001",
        path=path,
    )

    async def scenario():
        lease = await store.issue(
            operation_id=str(uuid4()),
            device_id=str(uuid4()),
            snapshot_id=str(uuid4()),
            template_version_id=str(uuid4()),
            expected_source_ip="192.0.2.4",
            expected_plaintext_sha256="a" * 64,
        )
        effective = await resolve_effective_artifact_source(
            direct_peer="172.24.0.1",
            method="GET",
            path=path,
            headers=headers,
            redis=fake,
            now=float(timestamp),
        )
        assert effective == "192.0.2.4"
        consumed = await store.consume(lease.token, source_ip=effective)
        assert consumed.expected_source_ip == "192.0.2.4"
        assert consumed.read_count == 1
        with pytest.raises(
            ConfigurationArtifactEdgeError,
            match="CONFIGURATION_ARTIFACT_EDGE_REPLAY",
        ):
            await resolve_effective_artifact_source(
                direct_peer="172.24.0.1",
                method="GET",
                path=path,
                headers=headers,
                redis=fake,
                now=float(timestamp),
            )

    asyncio.run(scenario())


def test_attested_source_still_must_match_lease_source(monkeypatch):
    monkeypatch.setenv("FTTW_CONFIGURATION_ARTIFACT_EDGE_HMAC_KEY", _key_hex())
    monkeypatch.setattr(settings, "configuration_artifact_trusted_edge_peers", "172.24.0.1")
    monkeypatch.setattr(settings, "configuration_artifact_edge_attestation_max_age_seconds", 15)
    monkeypatch.setattr(settings, "configuration_artifact_lease_ttl_seconds", 90)
    monkeypatch.setattr(settings, "configuration_artifact_lease_max_reads", 4)

    fake = FakeRedis()
    store = ArtifactLeaseStore(fake)
    timestamp = 1750000000
    path = "/configuration-artifacts/edge-test-token-SourceMismatch"
    headers = _headers(
        source="192.0.2.5",
        timestamp=timestamp,
        nonce="source-mismatch-nonce-01",
        path=path,
    )

    async def scenario():
        lease = await store.issue(
            operation_id=str(uuid4()),
            device_id=str(uuid4()),
            snapshot_id=str(uuid4()),
            template_version_id=str(uuid4()),
            expected_source_ip="192.0.2.4",
            expected_plaintext_sha256="b" * 64,
        )
        effective = await resolve_effective_artifact_source(
            direct_peer="172.24.0.1",
            method="GET",
            path=path,
            headers=headers,
            redis=fake,
            now=float(timestamp),
        )
        assert effective == "192.0.2.5"
        with pytest.raises(
            ConfigurationArtifactLeaseError,
            match="CONFIGURATION_ARTIFACT_LEASE_SOURCE_MISMATCH",
        ):
            await store.consume(lease.token, source_ip=effective)

    asyncio.run(scenario())


def test_edge_fails_closed_for_untrusted_unsigned_bad_signature_and_stale(monkeypatch):
    monkeypatch.setenv("FTTW_CONFIGURATION_ARTIFACT_EDGE_HMAC_KEY", _key_hex())
    monkeypatch.setattr(settings, "configuration_artifact_trusted_edge_peers", "172.24.0.1")
    monkeypatch.setattr(settings, "configuration_artifact_edge_attestation_max_age_seconds", 15)

    fake = FakeRedis()
    timestamp = 1750000000
    path = "/configuration-artifacts/edge-test-token-FailClosed"
    valid = _headers(
        source="192.0.2.4",
        timestamp=timestamp,
        nonce="fail-closed-valid-nonce",
        path=path,
    )

    async def scenario():
        direct = await resolve_effective_artifact_source(
            direct_peer="192.0.2.4",
            method="GET",
            path=path,
            headers={},
            redis=fake,
            now=float(timestamp),
        )
        assert direct == "192.0.2.4"

        with pytest.raises(
            ConfigurationArtifactEdgeError,
            match="CONFIGURATION_ARTIFACT_EDGE_UNTRUSTED_PEER",
        ):
            await resolve_effective_artifact_source(
                direct_peer="192.0.2.4",
                method="GET",
                path=path,
                headers=valid,
                redis=fake,
                now=float(timestamp),
            )

        with pytest.raises(
            ConfigurationArtifactEdgeError,
            match="CONFIGURATION_ARTIFACT_EDGE_ATTESTATION_REQUIRED",
        ):
            await resolve_effective_artifact_source(
                direct_peer="172.24.0.1",
                method="GET",
                path=path,
                headers={},
                redis=fake,
                now=float(timestamp),
            )

        bad = dict(valid)
        bad["x-fttw-edge-nonce"] = "bad-signature-nonce-01"
        bad["x-fttw-edge-signature"] = "0" * 64
        with pytest.raises(
            ConfigurationArtifactEdgeError,
            match="CONFIGURATION_ARTIFACT_EDGE_SIGNATURE_INVALID",
        ):
            await resolve_effective_artifact_source(
                direct_peer="172.24.0.1",
                method="GET",
                path=path,
                headers=bad,
                redis=fake,
                now=float(timestamp),
            )

        stale = _headers(
            source="192.0.2.4",
            timestamp=timestamp - 30,
            nonce="stale-attestation-nonce",
            path=path,
        )
        with pytest.raises(
            ConfigurationArtifactEdgeError,
            match="CONFIGURATION_ARTIFACT_EDGE_ATTESTATION_STALE",
        ):
            await resolve_effective_artifact_source(
                direct_peer="172.24.0.1",
                method="GET",
                path=path,
                headers=stale,
                redis=fake,
                now=float(timestamp),
            )

    asyncio.run(scenario())


def test_gateway_keeps_edge_isolated_and_no_normal_api_route_is_added():
    gateway = (BACKEND / "app" / "configuration_artifact_gateway" / "main.py").read_text(
        encoding="utf-8"
    )
    edge = (BACKEND / "app" / "configuration" / "artifact_edge.py").read_text(
        encoding="utf-8"
    )
    normal_router = (BACKEND / "app" / "api" / "router.py").read_text(
        encoding="utf-8"
    )

    assert "resolve_effective_artifact_source" in gateway
    assert "request.url.path" in gateway
    assert "CONFIGURATION_ARTIFACT_EDGE_REPLAY" in edge
    assert "hmac.compare_digest" in edge
    assert "configuration_artifact_gateway" not in normal_router
