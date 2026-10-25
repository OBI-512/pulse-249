from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.celery_app.config import celery_app
from app.core.exceptions import APIError
from app.models import (
    ConfigurationFunction,
    ConfigurationOperation,
    ConfigurationOperationStep,
    ConfigurationSnapshot,
    ConfigurationTemplate,
    ConfigurationTemplateVersion,
    DeviceConfigurationBinding,
    DeviceConfigurationState,
    User,
)
from app.schemas.configuration import (
    ConfigurationApplyRequest,
    ConfigurationCaptureRequest,
    ConfigurationDiffRead,
    ConfigurationFunctionRead,
    ConfigurationOperationDetail,
    ConfigurationOperationQueued,
    ConfigurationOperationRead,
    ConfigurationOperationStepRead,
    ConfigurationRestoreRequest,
    ConfigurationSnapshotRead,
    ConfigurationTemplateCreate,
    ConfigurationTemplateDetail,
    ConfigurationTemplateRead,
    ConfigurationTemplateVersionDetail,
    ConfigurationTemplateVersionRead,
    ConfigurationTemplateVersionUpdate,
    ConfigurationVerifyRequest,
    DeviceConfigurationBindingRead,
    DeviceConfigurationBindingWrite,
    DeviceConfigurationStateRead,
    public_parameter_summary,
)
from app.schemas.configuration_template_lifecycle import (
    ConfigurationTemplateFamilyCloneRead,
    ConfigurationTemplateFamilyCloneRequest,
    ConfigurationTemplateVersionCloneRequest,
    ConfigurationTemplateVersionLifecycleRead,
)
from app.security.authorization import authorize_request, get_current_user, user_has_permission
from app.security.resource_scope import require_global_request_scope, scope_for_actor
from app.security.scope_queries import require_device
from app.services.configuration import (
    bind_device,
    create_template,
    create_template_version,
    diff_snapshots,
    mark_dispatch_failure,
    queue_operation,
)
from app.services.configuration_template_lifecycle import (
    activate_configuration_template_version,
    approve_configuration_template_version,
    clone_configuration_template_family,
    clone_configuration_template_version,
    read_version_lifecycle,
    test_configuration_template_version,
    update_configuration_template_version_lifecycle,
)


template_router = APIRouter(
    prefix="/configuration-templates",
    tags=["Configuration Management"],
    dependencies=[Depends(authorize_request), Depends(require_global_request_scope)],
)

device_router = APIRouter(
    prefix="/devices/{device_id}/configuration",
    tags=["Configuration Management"],
    dependencies=[Depends(authorize_request)],
)


def _binding_read(binding: DeviceConfigurationBinding) -> DeviceConfigurationBindingRead:
    return DeviceConfigurationBindingRead(
        id=binding.id,
        device_id=binding.device_id,
        template_version_id=binding.template_version_id,
        credential_source=binding.credential_source,
        credential_reference_configured=bool(binding.credential_reference),
        connection_overrides=dict(binding.connection_overrides or {}),
        enabled=binding.enabled,
        bound_at=binding.bound_at,
    )


def _step_read(row: ConfigurationOperationStep) -> ConfigurationOperationStepRead:
    return ConfigurationOperationStepRead(
        id=row.id,
        operation_id=row.operation_id,
        function_id=row.function_id,
        step_order=row.step_order,
        function_code_snapshot=row.function_code_snapshot,
        function_name_snapshot=row.function_name_snapshot,
        status=row.status,
        parameter_summary=public_parameter_summary(row.parameter_summary),
        verification_summary=dict(row.verification_summary or {}),
        failure_code=row.failure_code,
        failure_message=row.failure_message,
        started_at=row.started_at,
        finished_at=row.finished_at,
    )


async def _require_permission(db: AsyncSession, actor: User, code: str) -> None:
    if not await user_has_permission(db, user_id=actor.id, permission_code=code):
        raise APIError(403, "PERMISSION_DENIED", f"Permission '{code}' is required.")


async def _template_detail(db: AsyncSession, template: ConfigurationTemplate) -> ConfigurationTemplateDetail:
    versions = list(
        (
            await db.scalars(
                select(ConfigurationTemplateVersion)
                .where(ConfigurationTemplateVersion.template_id == template.id)
                .order_by(ConfigurationTemplateVersion.version_number.desc())
            )
        ).all()
    )
    version_details: list[ConfigurationTemplateVersionDetail] = []
    for version in versions:
        functions = list(
            (
                await db.scalars(
                    select(ConfigurationFunction)
                    .where(ConfigurationFunction.template_version_id == version.id)
                    .order_by(ConfigurationFunction.default_order, ConfigurationFunction.id)
                )
            ).all()
        )
        version_details.append(
            ConfigurationTemplateVersionDetail(
                version=ConfigurationTemplateVersionRead.model_validate(version),
                functions=[ConfigurationFunctionRead.model_validate(row) for row in functions],
            )
        )
    return ConfigurationTemplateDetail(
        template=ConfigurationTemplateRead.model_validate(template),
        versions=version_details,
    )


@template_router.get("", response_model=list[ConfigurationTemplateRead])
async def list_configuration_templates(
    active_only: bool = Query(default=True),
    limit: int = Query(default=200, ge=1, le=500),
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ConfigurationTemplate)
    if active_only:
        stmt = stmt.where(ConfigurationTemplate.is_active.is_(True))
    rows = list(
        (
            await db.scalars(
                stmt.order_by(
                    ConfigurationTemplate.vendor,
                    ConfigurationTemplate.model,
                    ConfigurationTemplate.code,
                ).limit(limit)
            )
        ).all()
    )
    return rows


@template_router.post("", response_model=ConfigurationTemplateDetail, status_code=201)
async def create_configuration_template(
    payload: ConfigurationTemplateCreate,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    template, _ = await create_template(db, payload=payload, actor_user_id=actor.id)
    await db.commit()
    return await _template_detail(db, template)


@template_router.get("/{template_id}", response_model=ConfigurationTemplateDetail)
async def get_configuration_template(
    template_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    template = await db.get(ConfigurationTemplate, template_id)
    if template is None:
        raise APIError(404, "CONFIGURATION_TEMPLATE_NOT_FOUND", "Configuration template not found.")
    return await _template_detail(db, template)


@template_router.post(
    "/{template_id}/versions",
    response_model=ConfigurationTemplateVersionRead,
    status_code=201,
)
async def create_configuration_template_version(
    template_id: UUID,
    payload: ConfigurationTemplateVersionUpdate,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    version = await create_template_version(
        db,
        template_id=template_id,
        payload=payload,
        actor_user_id=actor.id,
    )
    await db.commit()
    await db.refresh(version)
    return version


@template_router.put(
    "/{template_id}/versions/{version_id}",
    response_model=ConfigurationTemplateVersionRead,
)
async def update_configuration_template_version(
    template_id: UUID,
    version_id: UUID,
    payload: ConfigurationTemplateVersionUpdate,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    version = await update_configuration_template_version_lifecycle(
        db,
        template_id=template_id,
        version_id=version_id,
        payload=payload,
        actor_user_id=actor.id,
    )
    await db.commit()
    await db.refresh(version)
    return version


@template_router.get(
    "/{template_id}/versions/{version_id}/lifecycle",
    response_model=ConfigurationTemplateVersionLifecycleRead,
)
async def get_configuration_template_version_lifecycle(
    template_id: UUID,
    version_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await read_version_lifecycle(
        db,
        template_id=template_id,
        version_id=version_id,
    )


@template_router.post(
    "/{template_id}/versions/{version_id}/clone",
    response_model=ConfigurationTemplateVersionRead,
    status_code=201,
)
async def clone_configuration_template_version_endpoint(
    template_id: UUID,
    version_id: UUID,
    payload: ConfigurationTemplateVersionCloneRequest,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    version = await clone_configuration_template_version(
        db,
        template_id=template_id,
        source_version_id=version_id,
        change_note=payload.change_note,
        actor_user_id=actor.id,
    )
    await db.commit()
    await db.refresh(version)
    return version


@template_router.post(
    "/{template_id}/versions/{version_id}/clone-family",
    response_model=ConfigurationTemplateFamilyCloneRead,
    status_code=201,
)
async def clone_configuration_template_family_endpoint(
    template_id: UUID,
    version_id: UUID,
    payload: ConfigurationTemplateFamilyCloneRequest,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    clone, version = await clone_configuration_template_family(
        db,
        source_template_id=template_id,
        source_version_id=version_id,
        payload=payload,
        actor_user_id=actor.id,
    )
    await db.commit()
    return ConfigurationTemplateFamilyCloneRead(
        template_id=clone.id,
        version_id=version.id,
        version_number=version.version_number,
        status=version.status,
        source_version_id=version_id,
    )


@template_router.post(
    "/{template_id}/versions/{version_id}/test",
    response_model=ConfigurationTemplateVersionLifecycleRead,
)
async def test_configuration_template_version_endpoint(
    template_id: UUID,
    version_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await test_configuration_template_version(
        db,
        template_id=template_id,
        version_id=version_id,
        actor_user_id=actor.id,
    )
    await db.commit()
    return await read_version_lifecycle(
        db,
        template_id=template_id,
        version_id=version_id,
    )


@template_router.post(
    "/{template_id}/versions/{version_id}/approve",
    response_model=ConfigurationTemplateVersionLifecycleRead,
)
async def approve_configuration_template_version_endpoint(
    template_id: UUID,
    version_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await approve_configuration_template_version(
        db,
        template_id=template_id,
        version_id=version_id,
        actor_user_id=actor.id,
    )
    await db.commit()
    return await read_version_lifecycle(
        db,
        template_id=template_id,
        version_id=version_id,
    )


@template_router.post(
    "/{template_id}/versions/{version_id}/activate",
    response_model=ConfigurationTemplateVersionLifecycleRead,
)
async def activate_configuration_template_version_endpoint(
    template_id: UUID,
    version_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await activate_configuration_template_version(
        db,
        template_id=template_id,
        version_id=version_id,
        actor_user_id=actor.id,
    )
    await db.commit()
    return await read_version_lifecycle(
        db,
        template_id=template_id,
        version_id=version_id,
    )


@template_router.post(
    "/{template_id}/versions/{version_id}/publish",
    response_model=ConfigurationTemplateVersionRead,
)
async def publish_configuration_template_version(
    template_id: UUID,
    version_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Compatibility alias. It deliberately obeys the same APPROVED -> PUBLISHED
    # transition as /activate; direct DRAFT -> PUBLISHED is no longer possible.
    version = await activate_configuration_template_version(
        db,
        template_id=template_id,
        version_id=version_id,
        actor_user_id=actor.id,
    )
    await db.commit()
    await db.refresh(version)
    return version


async def _scoped_device(db: AsyncSession, actor: User, device_id: UUID, *, for_update: bool = False):
    scope = await scope_for_actor(db, actor)
    device = await require_device(db, scope, device_id, for_update=for_update)
    return scope, device


@device_router.get("/binding", response_model=DeviceConfigurationBindingRead)
async def get_device_configuration_binding(
    device_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _scoped_device(db, actor, device_id)
    binding = await db.scalar(
        select(DeviceConfigurationBinding).where(DeviceConfigurationBinding.device_id == device_id)
    )
    if binding is None:
        raise APIError(404, "CONFIGURATION_DEVICE_NOT_BOUND", "The device has no configuration template binding.")
    return _binding_read(binding)


@device_router.put("/binding", response_model=DeviceConfigurationBindingRead)
async def set_device_configuration_binding(
    device_id: UUID,
    payload: DeviceConfigurationBindingWrite,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Binding a device to executable template logic is intentionally compound:
    # the actor must manage templates and also have device configuration read
    # authority within the device's WHERE scope.
    await _require_permission(db, actor, "device.configuration.read")
    _, device = await _scoped_device(db, actor, device_id, for_update=True)
    binding = await bind_device(db, device=device, payload=payload, actor_user_id=actor.id)
    await db.commit()
    return _binding_read(binding)


@device_router.get("/state", response_model=DeviceConfigurationStateRead)
async def get_device_configuration_state(
    device_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _scoped_device(db, actor, device_id)
    row = await db.scalar(
        select(DeviceConfigurationState).where(DeviceConfigurationState.device_id == device_id)
    )
    if row is None:
        return DeviceConfigurationStateRead(
            device_id=device_id,
            last_known_good_snapshot_id=None,
            last_verified_snapshot_id=None,
            last_operation_id=None,
            drift_status="UNKNOWN",
            last_verified_at=None,
        )
    return row


@device_router.get("/snapshots", response_model=list[ConfigurationSnapshotRead])
async def list_device_configuration_snapshots(
    device_id: UUID,
    limit: int = Query(default=100, ge=1, le=500),
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _scoped_device(db, actor, device_id)
    return list(
        (
            await db.scalars(
                select(ConfigurationSnapshot)
                .where(ConfigurationSnapshot.device_id == device_id)
                .order_by(ConfigurationSnapshot.created_at.desc(), ConfigurationSnapshot.id.desc())
                .limit(limit)
            )
        ).all()
    )


@device_router.get("/diff", response_model=ConfigurationDiffRead)
async def get_device_configuration_diff(
    device_id: UUID,
    from_snapshot_id: UUID = Query(),
    to_snapshot_id: UUID = Query(),
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _scoped_device(db, actor, device_id)
    diff, truncated = await diff_snapshots(
        db,
        device_id=device_id,
        from_snapshot_id=from_snapshot_id,
        to_snapshot_id=to_snapshot_id,
    )
    return ConfigurationDiffRead(
        from_snapshot_id=from_snapshot_id,
        to_snapshot_id=to_snapshot_id,
        diff=diff,
        truncated=truncated,
    )


@device_router.get("/operations", response_model=list[ConfigurationOperationRead])
async def list_device_configuration_operations(
    device_id: UUID,
    limit: int = Query(default=100, ge=1, le=500),
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _scoped_device(db, actor, device_id)
    return list(
        (
            await db.scalars(
                select(ConfigurationOperation)
                .where(ConfigurationOperation.device_id == device_id)
                .order_by(ConfigurationOperation.created_at.desc(), ConfigurationOperation.id.desc())
                .limit(limit)
            )
        ).all()
    )


@device_router.get(
    "/operations/{operation_id}",
    response_model=ConfigurationOperationDetail,
)
async def get_device_configuration_operation(
    device_id: UUID,
    operation_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _scoped_device(db, actor, device_id)
    operation = await db.scalar(
        select(ConfigurationOperation).where(
            ConfigurationOperation.id == operation_id,
            ConfigurationOperation.device_id == device_id,
        )
    )
    if operation is None:
        raise APIError(404, "CONFIGURATION_OPERATION_NOT_FOUND", "Configuration operation not found.")
    steps = list(
        (
            await db.scalars(
                select(ConfigurationOperationStep)
                .where(ConfigurationOperationStep.operation_id == operation.id)
                .order_by(ConfigurationOperationStep.step_order)
            )
        ).all()
    )
    return ConfigurationOperationDetail(
        operation=ConfigurationOperationRead.model_validate(operation),
        steps=[_step_read(row) for row in steps],
    )


async def _queue_and_dispatch(
    *,
    db: AsyncSession,
    actor: User,
    device_id: UUID,
    operation_type: str,
    idempotency_key: str | None,
    steps: list | None = None,
    snapshot_id: UUID | None = None,
) -> ConfigurationOperationQueued:
    # Serialize queueing against template rebinding on the same device.
    scope, device = await _scoped_device(db, actor, device_id, for_update=True)
    operation, created = await queue_operation(
        db,
        device=device,
        actor=actor,
        scope=scope,
        operation_type=operation_type,
        idempotency_key=idempotency_key,
        steps=steps,
        snapshot_id=snapshot_id,
    )
    await db.commit()
    if created:
        try:
            celery_app.send_task(
                "fttw.configuration.execute",
                args=[str(operation.id)],
                queue="configuration",
            )
        except Exception as exc:
            await mark_dispatch_failure(db, operation.id)
            raise APIError(
                503,
                "CONFIGURATION_TASK_DISPATCH_FAILED",
                "The isolated configuration worker is unavailable; the operation was not executed.",
            ) from exc
    return ConfigurationOperationQueued(operation_id=operation.id, status=operation.status)


@device_router.post("/capture", response_model=ConfigurationOperationQueued, status_code=202)
async def capture_device_configuration(
    device_id: UUID,
    payload: ConfigurationCaptureRequest,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await _queue_and_dispatch(
        db=db,
        actor=actor,
        device_id=device_id,
        operation_type="CAPTURE",
        idempotency_key=payload.idempotency_key,
    )


@device_router.post("/apply", response_model=ConfigurationOperationQueued, status_code=202)
async def apply_device_configuration(
    device_id: UUID,
    payload: ConfigurationApplyRequest,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await _queue_and_dispatch(
        db=db,
        actor=actor,
        device_id=device_id,
        operation_type="APPLY",
        idempotency_key=payload.idempotency_key,
        steps=payload.steps,
    )


@device_router.post("/verify", response_model=ConfigurationOperationQueued, status_code=202)
async def verify_device_configuration(
    device_id: UUID,
    payload: ConfigurationVerifyRequest,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await _queue_and_dispatch(
        db=db,
        actor=actor,
        device_id=device_id,
        operation_type="VERIFY",
        idempotency_key=payload.idempotency_key,
        snapshot_id=payload.snapshot_id,
    )


@device_router.post("/restore", response_model=ConfigurationOperationQueued, status_code=202)
async def restore_device_configuration(
    device_id: UUID,
    payload: ConfigurationRestoreRequest,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await _queue_and_dispatch(
        db=db,
        actor=actor,
        device_id=device_id,
        operation_type="RESTORE",
        idempotency_key=payload.idempotency_key,
        snapshot_id=payload.snapshot_id,
    )


router = APIRouter()
router.include_router(template_router)
router.include_router(device_router)
