from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import APIError
from app.models import AccessTemplate, AccessTemplateAssignment, AccessTemplateRevision, User
from app.services.access_templates import resolve_effective_access
from app.services.audit import record_audit
from app.settings import settings


SUPPORTED_PROTOCOLS = frozenset({"SSH", "SNMP", "WEB", "TELNET"})


@dataclass(frozen=True)
class AccessAssignmentPreview:
    protocol: str
    status: str
    planned_change: dict[str, Any]
    warnings: list[dict[str, Any]]
    blockers: list[dict[str, Any]]


async def visible_active_template_for_assignment(
    db: AsyncSession,
    *,
    template_id: UUID,
    actor: User,
) -> tuple[AccessTemplate, AccessTemplateRevision]:
    template = await db.scalar(
        select(AccessTemplate).where(
            AccessTemplate.id == template_id,
            AccessTemplate.deleted_at.is_(None),
            AccessTemplate.is_active.is_(True),
            (AccessTemplate.owner_user_id == actor.id)
            | (AccessTemplate.visibility == "SHARED"),
        )
    )
    if template is None:
        raise APIError(
            404,
            "ACCESS_TEMPLATE_NOT_FOUND",
            "Access Template not found.",
        )
    protocol = template.protocol.strip().upper()
    if protocol not in SUPPORTED_PROTOCOLS:
        raise APIError(
            422,
            "ACCESS_TEMPLATE_PROTOCOL_INVALID",
            "Unsupported Access Template protocol.",
        )
    if protocol == "TELNET" and not settings.telnet_access_enabled:
        raise APIError(
            422,
            "TELNET_DISABLED",
            "Telnet Access Template assignment is disabled by policy.",
        )
    revision = await db.scalar(
        select(AccessTemplateRevision)
        .where(
            AccessTemplateRevision.template_id == template.id,
            AccessTemplateRevision.lifecycle_status == "ACTIVE",
        )
        .order_by(AccessTemplateRevision.revision_number.desc())
        .limit(1)
    )
    if revision is None:
        raise APIError(
            422,
            "ACCESS_TEMPLATE_ACTIVE_REVISION_REQUIRED",
            "The selected Access Template has no ACTIVE revision.",
        )
    return template, revision


async def _device_protocol_assignments(
    db: AsyncSession,
    *,
    device_id: UUID,
    protocol: str,
    for_update: bool = False,
) -> list[tuple[AccessTemplateAssignment, AccessTemplate]]:
    statement = (
        select(AccessTemplateAssignment, AccessTemplate)
        .join(AccessTemplate, AccessTemplate.id == AccessTemplateAssignment.template_id)
        .where(
            AccessTemplateAssignment.scope_type == "DEVICE",
            AccessTemplateAssignment.device_id == device_id,
            AccessTemplate.protocol == protocol,
            AccessTemplate.deleted_at.is_(None),
        )
        .order_by(
            AccessTemplateAssignment.priority.desc(),
            AccessTemplateAssignment.created_at,
            AccessTemplateAssignment.id,
        )
    )
    if for_update:
        statement = statement.with_for_update()
    return list((await db.execute(statement)).all())


def _can_remove(
    *,
    actor: User,
    assignment: AccessTemplateAssignment,
    template: AccessTemplate,
) -> bool:
    return template.owner_user_id == actor.id or assignment.created_by_user_id == actor.id


async def preview_device_access_assignment(
    db: AsyncSession,
    *,
    device_id: UUID,
    template: AccessTemplate,
    actor: User,
    priority: int,
    conflict_policy: str,
) -> AccessAssignmentPreview:
    protocol = template.protocol.strip().upper()
    if conflict_policy not in {"FAIL_ON_CONFLICT", "REPLACE_DEVICE_PROTOCOL"}:
        raise APIError(
            422,
            "TEMPLATE_ASSIGNMENT_CONFLICT_POLICY_INVALID",
            "Unsupported Access Template conflict policy.",
        )

    rows = await _device_protocol_assignments(
        db,
        device_id=device_id,
        protocol=protocol,
    )
    exact = next(
        (
            assignment
            for assignment, _row_template in rows
            if assignment.template_id == template.id
            and assignment.priority == priority
            and assignment.enabled
        ),
        None,
    )

    if conflict_policy == "FAIL_ON_CONFLICT":
        conflicting = [
            assignment
            for assignment, row_template in rows
            if assignment.enabled
            and row_template.id != template.id
            and assignment.priority >= priority
        ]
        if conflicting:
            return AccessAssignmentPreview(
                protocol=protocol,
                status="BLOCKED",
                planned_change={
                    "kind": "ACCESS",
                    "protocol": protocol,
                    "template_id": str(template.id),
                    "priority": priority,
                    "conflict_policy": conflict_policy,
                },
                warnings=[],
                blockers=[
                    {
                        "code": "ACCESS_TEMPLATE_DEVICE_PROTOCOL_CONFLICT",
                        "protocol": protocol,
                    }
                ],
            )
        if exact is not None:
            effective = await resolve_effective_access(
                db,
                device_id=device_id,
                protocol=protocol,
            )
            if (
                effective.status == "RESOLVED"
                and effective.template is not None
                and effective.template.id == template.id
                and effective.assignment is not None
                and effective.assignment.id == exact.id
            ):
                return AccessAssignmentPreview(
                    protocol=protocol,
                    status="NOOP",
                    planned_change={
                        "kind": "ACCESS",
                        "protocol": protocol,
                        "template_id": str(template.id),
                        "priority": priority,
                        "action": "NOOP",
                    },
                    warnings=[],
                    blockers=[],
                )
        return AccessAssignmentPreview(
            protocol=protocol,
            status="READY",
            planned_change={
                "kind": "ACCESS",
                "protocol": protocol,
                "template_id": str(template.id),
                "priority": priority,
                "conflict_policy": conflict_policy,
                "action": "CREATE",
            },
            warnings=[],
            blockers=[],
        )

    rows_to_remove = [
        (assignment, row_template)
        for assignment, row_template in rows
        if not (
            assignment.template_id == template.id
            and assignment.priority == priority
            and assignment.enabled
        )
    ]
    if any(
        not _can_remove(
            actor=actor,
            assignment=assignment,
            template=row_template,
        )
        for assignment, row_template in rows_to_remove
    ):
        return AccessAssignmentPreview(
            protocol=protocol,
            status="BLOCKED",
            planned_change={
                "kind": "ACCESS",
                "protocol": protocol,
                "template_id": str(template.id),
                "priority": priority,
                "conflict_policy": conflict_policy,
            },
            warnings=[],
            blockers=[
                {
                    "code": "ACCESS_TEMPLATE_ASSIGNMENT_NOT_OWNED",
                    "protocol": protocol,
                }
            ],
        )
    if exact is not None and not rows_to_remove:
        return AccessAssignmentPreview(
            protocol=protocol,
            status="NOOP",
            planned_change={
                "kind": "ACCESS",
                "protocol": protocol,
                "template_id": str(template.id),
                "priority": priority,
                "action": "NOOP",
            },
            warnings=[],
            blockers=[],
        )
    return AccessAssignmentPreview(
        protocol=protocol,
        status="READY",
        planned_change={
            "kind": "ACCESS",
            "protocol": protocol,
            "template_id": str(template.id),
            "priority": priority,
            "conflict_policy": conflict_policy,
            "action": "REPLACE" if rows else "CREATE",
            "remove_count": len(rows_to_remove),
        },
        warnings=[],
        blockers=[],
    )


async def apply_device_access_assignment(
    db: AsyncSession,
    *,
    device_id: UUID,
    template: AccessTemplate,
    actor: User,
    priority: int,
    conflict_policy: str,
    batch_id: UUID | None = None,
) -> dict[str, Any]:
    preview = await preview_device_access_assignment(
        db,
        device_id=device_id,
        template=template,
        actor=actor,
        priority=priority,
        conflict_policy=conflict_policy,
    )
    if preview.status == "BLOCKED":
        code = str(preview.blockers[0].get("code") or "TEMPLATE_ASSIGNMENT_BLOCKED")
        raise APIError(409, code, "Access Template assignment is no longer applicable.")
    if preview.status == "NOOP":
        return {
            "kind": "ACCESS",
            "protocol": preview.protocol,
            "status": "NOOP",
            "template_id": str(template.id),
        }

    protocol = template.protocol.strip().upper()
    rows = await _device_protocol_assignments(
        db,
        device_id=device_id,
        protocol=protocol,
        for_update=True,
    )
    exact = next(
        (
            assignment
            for assignment, _row_template in rows
            if assignment.template_id == template.id
            and assignment.priority == priority
            and assignment.enabled
        ),
        None,
    )

    removed = 0
    if conflict_policy == "REPLACE_DEVICE_PROTOCOL":
        for assignment, row_template in rows:
            if exact is not None and assignment.id == exact.id:
                continue
            if not _can_remove(
                actor=actor,
                assignment=assignment,
                template=row_template,
            ):
                raise APIError(
                    403,
                    "ACCESS_TEMPLATE_ASSIGNMENT_NOT_OWNED",
                    "Only the template owner or assignment creator can remove this assignment.",
                )
            await db.delete(assignment)
            removed += 1
            await record_audit(
                db,
                action="ACCESS_TEMPLATE_UNASSIGN",
                entity_type="ACCESS_TEMPLATE_ASSIGNMENT",
                entity_id=assignment.id,
                actor_user_id=actor.id,
                metadata={
                    "template_id": str(row_template.id),
                    "scope_type": "DEVICE",
                    "protocol": protocol,
                    "tp4_batch_id": str(batch_id) if batch_id else None,
                },
            )
        await db.flush()

    if conflict_policy == "FAIL_ON_CONFLICT":
        blocker = next(
            (
                assignment
                for assignment, row_template in rows
                if assignment.enabled
                and row_template.id != template.id
                and assignment.priority >= priority
            ),
            None,
        )
        if blocker is not None:
            raise APIError(
                409,
                "ACCESS_TEMPLATE_DEVICE_PROTOCOL_CONFLICT",
                "A conflicting device-level Access Template assignment exists.",
            )

    if exact is None:
        exact = AccessTemplateAssignment(
            template_id=template.id,
            scope_type="DEVICE",
            priority=priority,
            enabled=True,
            device_id=device_id,
            created_by_user_id=actor.id,
        )
        db.add(exact)
        await db.flush()
        await record_audit(
            db,
            action="ACCESS_TEMPLATE_ASSIGN",
            entity_type="ACCESS_TEMPLATE_ASSIGNMENT",
            entity_id=exact.id,
            actor_user_id=actor.id,
            metadata={
                "template_id": str(template.id),
                "scope_type": "DEVICE",
                "scope_id": str(device_id),
                "priority": priority,
                "protocol": protocol,
                "tp4_batch_id": str(batch_id) if batch_id else None,
            },
        )

    return {
        "kind": "ACCESS",
        "protocol": protocol,
        "status": "SUCCEEDED",
        "template_id": str(template.id),
        "assignment_id": str(exact.id),
        "removed_assignment_count": removed,
    }
