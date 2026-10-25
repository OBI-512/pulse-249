from __future__ import annotations

from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..models import AccessTemplate
from ..security.authorization import user_has_permission
from .access_templates import (
    AccessTemplateSecretError,
    SNMPRuntimeAccess,
    build_snmp_runtime_credential,
    resolved_secrets,
)


async def require_discovery_snmp_template(
    db: AsyncSession,
    *,
    template_id: UUID,
    actor_user_id: UUID,
) -> AccessTemplate:
    """Validate an operator-selected reusable SNMP credential reference.

    Discovery requires its normal discovery.run permission at the router and
    access_template.read before a reusable Access Template may be selected.
    Secret values are deliberately not resolved in this validation step.
    """

    if not await user_has_permission(
        db,
        user_id=actor_user_id,
        permission_code="access_template.read",
    ):
        raise APIError(
            403,
            "PERMISSION_DENIED",
            "Permission 'access_template.read' is required to use an Access Template for discovery.",
        )

    template = await db.scalar(
        select(AccessTemplate).where(
            AccessTemplate.id == template_id,
            AccessTemplate.protocol == "SNMP",
            AccessTemplate.is_active.is_(True),
            AccessTemplate.deleted_at.is_(None),
            or_(
                AccessTemplate.owner_user_id == actor_user_id,
                AccessTemplate.visibility == "SHARED",
            ),
        )
    )
    if template is None:
        raise APIError(
            404,
            "DISCOVERY_SNMP_ACCESS_TEMPLATE_NOT_FOUND",
            "The selected active SNMP Access Template is not available to this user.",
        )
    return template


async def resolve_discovery_snmp_template(
    db: AsyncSession,
    *,
    template_id: UUID,
) -> SNMPRuntimeAccess:
    """Resolve SNMP secret material only inside the process executing probes."""

    template = await db.scalar(
        select(AccessTemplate).where(
            AccessTemplate.id == template_id,
            AccessTemplate.protocol == "SNMP",
            AccessTemplate.is_active.is_(True),
            AccessTemplate.deleted_at.is_(None),
        )
    )
    if template is None:
        raise AccessTemplateSecretError("DISCOVERY_SNMP_ACCESS_TEMPLATE_NOT_AVAILABLE")

    secrets = await resolved_secrets(db, template.id)
    credential = build_snmp_runtime_credential(template, secrets)
    settings = dict(template.settings_json or {})
    return SNMPRuntimeAccess(
        credential=credential,
        port=int(settings.get("port", 161)),
        timeout_seconds=int(settings.get("timeout_seconds", 10)),
        retries=int(settings.get("retries", 1)),
    )


def snmp_context_kwargs(access: SNMPRuntimeAccess) -> dict[str, object]:
    """Translate resolved runtime material to the existing DiscoveryContext fields."""

    credential = access.credential
    version = str(credential.get("version") or "2c")
    return {
        "snmp_version": version,
        "snmp_port": access.port,
        "snmp_community": credential.get("community"),
        "snmp_retries": access.retries,
        "snmp_v3_username": credential.get("username"),
        "snmp_v3_security_level": credential.get("security_level", "noAuthNoPriv"),
        "snmp_v3_auth_protocol": credential.get("auth_protocol"),
        "snmp_v3_auth_password": credential.get("auth_password"),
        "snmp_v3_priv_protocol": credential.get("priv_protocol"),
        "snmp_v3_priv_password": credential.get("priv_password"),
        "snmp_v3_context_name": credential.get("context_name"),
    }
