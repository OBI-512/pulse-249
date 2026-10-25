from fastapi import APIRouter, Depends

# TP4 refines the existing configuration-binding mutation contract before any
# router imports it. Enabled bindings delegate to the original readiness gate;
# disabled bindings may be staged as metadata after non-runtime validation.
from app.services.configuration_binding_metadata import bind_device_for_assignment as _tp4_bind_device_refinement  # noqa: F401

from .routers import (
    access_template_lifecycle,
    access_template_web_wizard,
    access_templates,
    admin,
    alarms,
    assignment_options,
    audit,
    auth,
    customers,
    data_exchange,
    data_lifecycle,
    candidates,
    configuration,
    configuration_batches,
    device_summary,
    discovery,
    batch_discovery,
    devices,
    geo,
    groups,
    networks,
    onboarding,
    placements,
    recycle_bin,
    restore_points,
    operational_logs,
    operations_dashboard,
    system_info,
    movements,
    maintenance_windows,
    notifications,
    relationships,
    reports,
    telemetry,
    template_assignment_batches,
    template_packages,
    topology,
)
from ..security.authorization import authorize_request

api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router)
api_router.include_router(assignment_options.router)
api_router.include_router(admin.router)
api_router.include_router(audit.router)
api_router.include_router(alarms.router)
api_router.include_router(maintenance_windows.router)
api_router.include_router(notifications.router)
api_router.include_router(telemetry.router)
api_router.include_router(data_lifecycle.router)
api_router.include_router(data_exchange.router)
api_router.include_router(reports.router)
api_router.include_router(networks.router)
api_router.include_router(geo.router)
api_router.include_router(devices.router)
api_router.include_router(configuration.router)
api_router.include_router(configuration_batches.router)
api_router.include_router(template_assignment_batches.router)
api_router.include_router(template_packages.router)
api_router.include_router(
    access_template_web_wizard.router,
    dependencies=[Depends(authorize_request)],
)
api_router.include_router(
    access_template_lifecycle.router,
    dependencies=[Depends(authorize_request)],
)
api_router.include_router(
    access_templates.router,
    dependencies=[Depends(authorize_request)],
)
api_router.include_router(device_summary.router)
api_router.include_router(customers.router)
api_router.include_router(groups.router)
api_router.include_router(relationships.router)
api_router.include_router(topology.router)

api_router.include_router(onboarding.router)
api_router.include_router(placements.router)
api_router.include_router(movements.router)
api_router.include_router(recycle_bin.router)
api_router.include_router(restore_points.router)
api_router.include_router(operational_logs.router)
api_router.include_router(operations_dashboard.router)
api_router.include_router(system_info.router)

api_router.include_router(discovery.router)

api_router.include_router(batch_discovery.router)

api_router.include_router(candidates.router)