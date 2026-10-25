from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import secrets
import time
from typing import Any

from redis.asyncio import Redis

from app.settings import settings


_LEASE_PREFIX = "fttw:configuration-artifact-lease:"
_CONSUME_LUA = r"""
local raw = redis.call('GET', KEYS[1])
if not raw then
  return {'MISSING'}
end
local lease = cjson.decode(raw)
if lease.expected_source_ip ~= '' and lease.expected_source_ip ~= ARGV[1] then
  return {'SOURCE_MISMATCH'}
end
local reads = tonumber(lease.read_count or 0)
local maximum = tonumber(lease.max_reads or 0)
if maximum < 1 or reads >= maximum then
  redis.call('DEL', KEYS[1])
  return {'READ_LIMIT'}
end
local ttl = redis.call('TTL', KEYS[1])
if ttl <= 0 then
  redis.call('DEL', KEYS[1])
  return {'MISSING'}
end
lease.read_count = reads + 1
redis.call('SET', KEYS[1], cjson.encode(lease), 'EX', ttl, 'XX')
return {'OK', cjson.encode(lease)}
"""

_MARK_SERVED_LUA = r"""
local raw = redis.call('GET', KEYS[1])
if not raw then
  return {'MISSING'}
end
local lease = cjson.decode(raw)
if lease.expected_source_ip ~= '' and lease.expected_source_ip ~= ARGV[1] then
  return {'SOURCE_MISMATCH'}
end
local reads = tonumber(lease.read_count or 0)
local served = tonumber(lease.served_count or 0)
local maximum = tonumber(lease.max_reads or 0)
if maximum < 1 or reads < 1 or reads > maximum or served < 0 or served >= reads or served >= maximum then
  return {'INVALID'}
end
local ttl = redis.call('TTL', KEYS[1])
if ttl <= 0 then
  redis.call('DEL', KEYS[1])
  return {'MISSING'}
end
lease.served_count = served + 1
redis.call('SET', KEYS[1], cjson.encode(lease), 'EX', ttl, 'XX')
return {'OK', cjson.encode(lease)}
"""


class ConfigurationArtifactLeaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class ArtifactLease:
    operation_id: str
    device_id: str
    snapshot_id: str
    template_version_id: str
    expected_source_ip: str
    expected_plaintext_sha256: str
    read_count: int
    served_count: int
    max_reads: int
    expires_at: float

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "ArtifactLease":
        try:
            lease = cls(
                operation_id=str(value["operation_id"]),
                device_id=str(value["device_id"]),
                snapshot_id=str(value["snapshot_id"]),
                template_version_id=str(value["template_version_id"]),
                expected_source_ip=str(value.get("expected_source_ip") or ""),
                expected_plaintext_sha256=str(value["expected_plaintext_sha256"]),
                read_count=int(value.get("read_count") or 0),
                served_count=int(value.get("served_count") or 0),
                max_reads=int(value["max_reads"]),
                expires_at=float(value["expires_at"]),
            )
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_CORRUPT"
            ) from exc
        if (
            len(lease.expected_plaintext_sha256) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in lease.expected_plaintext_sha256)
            or lease.max_reads < 1
            or lease.read_count < 0
            or lease.read_count > lease.max_reads
            or lease.served_count < 0
            or lease.served_count > lease.read_count
            or lease.served_count > lease.max_reads
        ):
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_CORRUPT"
            )
        return lease


@dataclass(frozen=True)
class IssuedArtifactLease:
    token: str
    expires_at: float
    max_reads: int


def normalize_source_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ConfigurationArtifactLeaseError(
            "CONFIGURATION_ARTIFACT_SOURCE_IP_INVALID"
        ) from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def _token_digest(token: str) -> str:
    if not isinstance(token, str) or len(token) < 32 or len(token) > 256:
        raise ConfigurationArtifactLeaseError(
            "CONFIGURATION_ARTIFACT_LEASE_TOKEN_INVALID"
        )
    try:
        encoded = token.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise ConfigurationArtifactLeaseError(
            "CONFIGURATION_ARTIFACT_LEASE_TOKEN_INVALID"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _lease_key(token: str) -> str:
    return f"{_LEASE_PREFIX}{_token_digest(token)}"


def _bounded_ttl() -> int:
    try:
        value = int(settings.configuration_artifact_lease_ttl_seconds)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConfigurationArtifactLeaseError(
            "CONFIGURATION_ARTIFACT_LEASE_TTL_INVALID"
        ) from exc
    if not 15 <= value <= 300:
        raise ConfigurationArtifactLeaseError(
            "CONFIGURATION_ARTIFACT_LEASE_TTL_INVALID"
        )
    return value


def _bounded_max_reads() -> int:
    try:
        value = int(settings.configuration_artifact_lease_max_reads)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConfigurationArtifactLeaseError(
            "CONFIGURATION_ARTIFACT_LEASE_READ_LIMIT_INVALID"
        ) from exc
    # Stage 4I proved this IOS can perform two GETs for one copy operation.
    if not 2 <= value <= 8:
        raise ConfigurationArtifactLeaseError(
            "CONFIGURATION_ARTIFACT_LEASE_READ_LIMIT_INVALID"
        )
    return value


def redis_client() -> Redis:
    return Redis.from_url(settings.redis_url, decode_responses=True)


class ArtifactLeaseStore:
    def __init__(self, client: Redis):
        self.client = client

    async def issue(
        self,
        *,
        operation_id: str,
        device_id: str,
        snapshot_id: str,
        template_version_id: str,
        expected_source_ip: str,
        expected_plaintext_sha256: str,
    ) -> IssuedArtifactLease:
        if (
            len(expected_plaintext_sha256) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in expected_plaintext_sha256)
        ):
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_HASH_INVALID"
            )
        source_ip = normalize_source_ip(expected_source_ip)
        ttl = _bounded_ttl()
        max_reads = _bounded_max_reads()
        expires_at = time.time() + ttl
        lease = ArtifactLease(
            operation_id=str(operation_id),
            device_id=str(device_id),
            snapshot_id=str(snapshot_id),
            template_version_id=str(template_version_id),
            expected_source_ip=source_ip,
            expected_plaintext_sha256=expected_plaintext_sha256.lower(),
            read_count=0,
            served_count=0,
            max_reads=max_reads,
            expires_at=expires_at,
        )
        encoded = json.dumps(asdict(lease), sort_keys=True, separators=(",", ":"))
        for _ in range(4):
            token = secrets.token_urlsafe(32)
            try:
                created = await self.client.set(
                    _lease_key(token), encoded, ex=ttl, nx=True
                )
            except Exception as exc:
                raise ConfigurationArtifactLeaseError(
                    "CONFIGURATION_ARTIFACT_LEASE_BACKEND_UNAVAILABLE"
                ) from exc
            if created:
                return IssuedArtifactLease(
                    token=token,
                    expires_at=expires_at,
                    max_reads=max_reads,
                )
        raise ConfigurationArtifactLeaseError(
            "CONFIGURATION_ARTIFACT_LEASE_ISSUE_FAILED"
        )

    async def consume(self, token: str, *, source_ip: str) -> ArtifactLease:
        normalized_source = normalize_source_ip(source_ip)
        try:
            result = await self.client.eval(
                _CONSUME_LUA,
                1,
                _lease_key(token),
                normalized_source,
            )
        except ConfigurationArtifactLeaseError:
            raise
        except Exception as exc:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_BACKEND_UNAVAILABLE"
            ) from exc
        lease = self._lease_from_script_result(result)
        if lease.expires_at <= time.time():
            await self.revoke(token)
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_UNAVAILABLE"
            )
        return lease

    async def mark_served(self, token: str, *, source_ip: str) -> ArtifactLease:
        """Record one gateway-served response after payload authorization succeeds.

        This receipt is source-bound and cannot outnumber successful lease consumes.
        It is deliberately recorded only by the artifact gateway after the bound
        snapshot has been loaded, decrypted and checksum-verified.
        """
        normalized_source = normalize_source_ip(source_ip)
        try:
            result = await self.client.eval(
                _MARK_SERVED_LUA,
                1,
                _lease_key(token),
                normalized_source,
            )
        except ConfigurationArtifactLeaseError:
            raise
        except Exception as exc:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_BACKEND_UNAVAILABLE"
            ) from exc
        lease = self._lease_from_script_result(
            result,
            invalid_code="CONFIGURATION_ARTIFACT_LEASE_SERVE_STATE_INVALID",
        )
        if lease.expires_at <= time.time():
            await self.revoke(token)
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_UNAVAILABLE"
            )
        return lease

    async def get_served_count(self, token: str, *, source_ip: str) -> int:
        normalized_source = normalize_source_ip(source_ip)
        try:
            raw = await self.client.get(_lease_key(token))
        except Exception as exc:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_BACKEND_UNAVAILABLE"
            ) from exc
        if raw is None:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_UNAVAILABLE"
            )
        try:
            payload = json.loads(str(raw))
        except json.JSONDecodeError as exc:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_CORRUPT"
            ) from exc
        lease = ArtifactLease.from_mapping(payload)
        if lease.expected_source_ip and lease.expected_source_ip != normalized_source:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_SOURCE_MISMATCH"
            )
        if lease.expires_at <= time.time():
            await self.revoke(token)
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_UNAVAILABLE"
            )
        return lease.served_count

    @staticmethod
    def _lease_from_script_result(
        result: Any,
        *,
        invalid_code: str = "CONFIGURATION_ARTIFACT_LEASE_REJECTED",
    ) -> ArtifactLease:
        if not isinstance(result, (list, tuple)) or not result:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_BACKEND_INVALID"
            )
        code = str(result[0])
        if code != "OK":
            mapping = {
                "MISSING": "CONFIGURATION_ARTIFACT_LEASE_UNAVAILABLE",
                "SOURCE_MISMATCH": "CONFIGURATION_ARTIFACT_LEASE_SOURCE_MISMATCH",
                "READ_LIMIT": "CONFIGURATION_ARTIFACT_LEASE_READ_LIMIT_EXCEEDED",
                "INVALID": invalid_code,
            }
            raise ConfigurationArtifactLeaseError(
                mapping.get(code, "CONFIGURATION_ARTIFACT_LEASE_REJECTED")
            )
        if len(result) != 2:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_BACKEND_INVALID"
            )
        try:
            payload = json.loads(str(result[1]))
        except json.JSONDecodeError as exc:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_CORRUPT"
            ) from exc
        return ArtifactLease.from_mapping(payload)

    async def revoke(self, token: str) -> None:
        try:
            await self.client.delete(_lease_key(token))
        except ConfigurationArtifactLeaseError:
            raise
        except Exception as exc:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_BACKEND_UNAVAILABLE"
            ) from exc


async def issue_artifact_lease(**kwargs: str) -> IssuedArtifactLease:
    client = redis_client()
    try:
        return await ArtifactLeaseStore(client).issue(**kwargs)
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


async def get_artifact_lease_served_count(token: str, *, source_ip: str) -> int:
    client = redis_client()
    try:
        return await ArtifactLeaseStore(client).get_served_count(
            token,
            source_ip=source_ip,
        )
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


async def revoke_artifact_lease(token: str) -> None:
    client = redis_client()
    try:
        await ArtifactLeaseStore(client).revoke(token)
    finally:
        try:
            await client.aclose()
        except Exception:
            pass
