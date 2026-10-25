from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.configuration.registry import registry
from app.configuration.templating import ConfigurationTemplateError
from app.core.exceptions import APIError
from app.models import User
from app.schemas.template_packages import (
    TemplateKind,
    TemplatePackageImportRead,
    TemplatePackageImportRequest,
    TemplatePackagePreviewRead,
    TemplatePackagePreviewRequest,
)
from app.security.authorization import get_current_user, user_has_permission
from app.security.resource_scope import require_global_scope
from app.services.access_templates import validate_template_definition
from app.services.template_packages import (
    PACKAGE_MEDIA_TYPE,
    _typed_package,
    export_template_package,
    import_template_package,
    preview_template_package,
    template_kind_from_raw,
)


router = APIRouter(prefix="/template-packages", tags=["Template Packages"])

ACCESS_READ = "access_template.read"
ACCESS_MANAGE = "access_template.manage"
CONFIGURATION_READ = "device.configuration.template.read"
CONFIGURATION_MANAGE = "device.configuration.template.manage"
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9_.-]+")
_ACCESS_CREDENTIAL_VALUE_KEYS = frozenset(
    {
        "username",
        "password",
        "private_key",
        "private_key_passphrase",
        "community",
        "security_name",
        "auth_secret",
        "privacy_secret",
    }
)


async def _require_package_authority(
    db: AsyncSession,
    actor: User,
    *,
    template_kind: TemplateKind,
    manage: bool,
) -> None:
    if template_kind == "ACCESS":
        permission = ACCESS_MANAGE if manage else ACCESS_READ
    else:
        permission = CONFIGURATION_MANAGE if manage else CONFIGURATION_READ
    if not await user_has_permission(
        db,
        user_id=actor.id,
        permission_code=permission,
    ):
        raise APIError(
            403,
            "PERMISSION_DENIED",
            f"Permission '{permission}' is required.",
        )
    if template_kind == "CONFIGURATION":
        await require_global_scope(
            db,
            actor,
            message="Global resource scope is required for Configuration Template package operations.",
        )


def _download_filename(package: dict) -> str:
    manifest = package.get("manifest") or {}
    provenance = manifest.get("provenance") or {}
    source_key = str(provenance.get("source_family_key") or "template")
    safe_key = _SAFE_FILENAME.sub("-", source_key).strip("-._") or "template"
    package_version = str(manifest.get("package_version") or "1.0.0")
    safe_version = _SAFE_FILENAME.sub("-", package_version)
    return f"{safe_key}-{safe_version}.fttw-template.json"


def _reject_access_credential_values(value: Any) -> None:
    """Reject credential-bearing field names anywhere outside credential_slots."""
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key).strip().lower()
            if key in _ACCESS_CREDENTIAL_VALUE_KEYS:
                raise APIError(
                    422,
                    "TEMPLATE_PACKAGE_SECURITY_POLICY_REJECTED",
                    "Access Template packages may contain credential slot names only, never credential values.",
                )
            _reject_access_credential_values(child)
    elif isinstance(value, list):
        for child in value:
            # credential_slots itself is a list of symbolic strings, which is
            # intentionally portable. Only nested objects can introduce fields.
            if isinstance(child, (dict, list)):
                _reject_access_credential_values(child)


def _advisory_lock_key(value: str) -> int:
    """Map a stable import-conflict identity to PostgreSQL signed int64."""
    return int.from_bytes(
        hashlib.sha256(value.encode("utf-8")).digest()[:8],
        byteorder="big",
        signed=True,
    )


async def _lock_import_conflicts(
    db: AsyncSession,
    *,
    actor_id: UUID,
    package,
    template,
    target,
) -> None:
    """Serialize package-id and target-identity conflict decisions transactionally."""
    keys = {
        _advisory_lock_key(f"TP2:PACKAGE:{package.manifest.package_id}"),
    }
    if package.manifest.template_kind == "ACCESS":
        target_name = (target.name or template.family.name).strip()
        identity = f"TP2:ACCESS:{actor_id}:{template.family.protocol}:{target_name}"
    else:
        target_code = (target.code or template.family.code).strip().lower()
        identity = f"TP2:CONFIGURATION:{target_code}"
    keys.add(_advisory_lock_key(identity))
    for lock_key in sorted(keys):
        await db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": lock_key},
        )


async def _validate_export_boundary(package: dict[str, Any]) -> None:
    """Revalidate exact generated bytes against portable and adapter contracts."""
    typed_package, template, _package_hash = _typed_package(package)
    if typed_package.manifest.template_kind == "ACCESS":
        _reject_access_credential_values(package.get("template"))
        validate_template_definition(
            protocol=template.family.protocol,
            protocol_variant=template.revision.protocol_variant,
            template_settings=dict(template.revision.settings),
            secret_keys=set(template.revision.credential_slots),
            is_active=False,
        )
        return

    definition = template.version.definition
    try:
        adapter = registry.get(definition.adapter_key)
        registry.validate_capabilities(definition.adapter_key, set(definition.capabilities))
        if adapter.descriptor.transport != definition.transport:
            raise ValueError("CONFIGURATION_ADAPTER_TRANSPORT_MISMATCH")
        await adapter.validate_template(definition)
    except (KeyError, ConfigurationTemplateError, ValueError) as exc:
        raise APIError(
            409,
            "TEMPLATE_PACKAGE_SOURCE_DEFINITION_INVALID",
            "Configuration Template source no longer satisfies its registered adapter contract.",
        ) from exc


@router.get("/export/{template_kind}/{template_id}")
async def export_package(
    template_kind: TemplateKind,
    template_id: UUID,
    source_id: UUID | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    await _require_package_authority(
        db,
        actor,
        template_kind=template_kind,
        manage=False,
    )
    package = await export_template_package(
        db,
        template_kind=template_kind,
        template_id=template_id,
        source_id=source_id,
        actor_user_id=actor.id,
    )
    # No package bytes leave the API until the exact generated object has
    # passed schema/integrity/security validation and the current adapter contract.
    await _validate_export_boundary(package)
    return Response(
        content=json.dumps(package, ensure_ascii=False, separators=(",", ":")),
        media_type=PACKAGE_MEDIA_TYPE,
        headers={
            "Content-Disposition": f'attachment; filename="{_download_filename(package)}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/preview", response_model=TemplatePackagePreviewRead)
async def preview_package(
    payload: TemplatePackagePreviewRequest,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    template_kind = template_kind_from_raw(payload.package)
    await _require_package_authority(
        db,
        actor,
        template_kind=template_kind,
        manage=True,
    )
    if template_kind == "ACCESS":
        _reject_access_credential_values(payload.package.get("template"))
    return await preview_template_package(
        db,
        raw_package=payload.package,
        target=payload.target,
        actor_user_id=actor.id,
    )


@router.post("/import", response_model=TemplatePackageImportRead, status_code=201)
async def import_package(
    payload: TemplatePackageImportRequest,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    template_kind = template_kind_from_raw(payload.package)
    await _require_package_authority(
        db,
        actor,
        template_kind=template_kind,
        manage=True,
    )
    try:
        if template_kind == "ACCESS":
            _reject_access_credential_values(payload.package.get("template"))
        package, template, _package_hash = _typed_package(payload.package)
        await _lock_import_conflicts(
            db,
            actor_id=actor.id,
            package=package,
            template=template,
            target=payload.target,
        )
        result = await import_template_package(
            db,
            raw_package=payload.package,
            expected_package_sha256=payload.expected_package_sha256,
            target=payload.target,
            actor_user_id=actor.id,
        )
        await db.commit()
        return result
    except APIError:
        await db.rollback()
        raise
    except Exception:
        await db.rollback()
        raise
