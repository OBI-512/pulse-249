from __future__ import annotations

from hashlib import sha256
import json

from app.security.resource_scope import EffectiveResourceScope


def scope_snapshot(scope: EffectiveResourceScope) -> dict[str, object]:
    """Stable, secret-free authorization snapshot for deferred work."""
    return {
        "global": bool(scope.global_access),
        "networks": sorted(str(value) for value in scope.network_ids),
        "cities": sorted(str(value) for value in scope.city_ids),
        "locations": sorted(str(value) for value in scope.location_ids),
        "sectors": sorted(str(value) for value in scope.sector_ids),
        "groups": sorted(str(value) for value in scope.group_ids),
    }


def snapshot_fingerprint(snapshot: dict[str, object]) -> str:
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def scope_fingerprint(scope: EffectiveResourceScope) -> str:
    return snapshot_fingerprint(scope_snapshot(scope))
