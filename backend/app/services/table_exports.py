from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import Request

from .tabular_formats import write_tabular_bytes


@dataclass(frozen=True)
class ColumnSpec:
    label: str
    paths: tuple[str, ...]


@dataclass(frozen=True)
class TableSpec:
    path: str
    columns: tuple[ColumnSpec, ...]
    pagination: str = "page"  # page | offset | none
    page_size: int = 500
    items_key: str = "items"
    total_key: str = "total"
    page_param: str = "page"
    page_size_param: str = "page_size"
    offset_param: str = "offset"
    limit_param: str = "limit"
    path_params: tuple[str, ...] = ()
    allowed_params: frozenset[str] = frozenset()
    post_process: bool = False


def _c(label: str, *paths: str) -> ColumnSpec:
    return ColumnSpec(label, tuple(paths))


COMMON_SORT = frozenset({"sort_by", "sort_direction", "sort_dir"})


TABLE_EXPORTS: dict[str, TableSpec] = {
    "device_inventory": TableSpec(
        "/api/devices/inventory/page",
        (
            _c("Device", "display_name"), _c("Management IP", "management_ip"),
            _c("S-VLAN", "service_vlan_id"), _c("C-VLAN", "customer_vlan_display"),
            _c("Hostname", "hostname"), _c("Vendor", "vendor"), _c("Model", "model"),
            _c("Serial Number", "serial_number"), _c("Lifecycle", "lifecycle_state"),
            _c("Operational", "operational_state"), _c("Management Protocol", "management_protocol"),
        ),
        allowed_params=COMMON_SORT | frozenset({"device_type_id", "operational_state", "lifecycle_state", "vendor", "management_protocol", "search", "service_vlan_id", "customer_vlan_id"}),
    ),
    "device_management": TableSpec(
        "/api/devices/management/page",
        (
            _c("Device", "display_name"), _c("Type", "device_type_code"), _c("Management IP", "management_ip"),
            _c("Network", "network_name"), _c("City", "city_name"), _c("Location", "location_name"),
            _c("Logical Sector", "sector_name"), _c("Physical Sector", "physical_sector_device_name"),
            _c("Parent Device", "parent_device_name"), _c("Customer", "customer_name"),
            _c("S-VLAN", "service_vlan_id"), _c("C-VLAN", "customer_vlan_id"),
            _c("C-VLAN Start", "customer_vlan_start"), _c("C-VLAN End", "customer_vlan_end"),
            _c("Lifecycle", "lifecycle_state"), _c("Operational", "operational_state"),
        ),
        allowed_params=COMMON_SORT | frozenset({"search", "device_type_id", "operational_state", "lifecycle_state", "network_id", "city_id", "location_id", "physical_sector_device_id", "sector_id", "sector_role", "group_id", "service_vlan_id", "customer_vlan_id"}),
    ),
    "device_ips": TableSpec(
        "/api/devices/{device_id}/ips",
        (_c("IP Address", "ip_address"), _c("Address Family", "address_family"), _c("Management", "is_management"), _c("Primary", "is_primary"), _c("Source", "source")),
        pagination="none", path_params=("device_id",),
        allowed_params=frozenset({"search", "management", "primary", "sort_by", "sort_direction"}),
    ),
    "device_interfaces": TableSpec(
        "/api/devices/{device_id}/interfaces",
        (_c("Interface", "interface_name"), _c("Index", "interface_index"), _c("MAC Address", "mac_address"), _c("Description", "description"), _c("Operational", "operational_status"), _c("Administrative", "administrative_status")),
        pagination="none", path_params=("device_id",),
        allowed_params=frozenset({"search", "status", "sort_by", "sort_direction"}),
    ),
    "networks": TableSpec(
        "/api/networks/page",
        (_c("Name", "name"), _c("Code", "code"), _c("Status", "status"), _c("Cities", "city_count"), _c("Description", "description")),
        allowed_params=COMMON_SORT | frozenset({"search", "status"}),
    ),
    "cities": TableSpec(
        "/api/cities/page",
        (_c("Name", "name"), _c("Code", "code"), _c("Network", "network_name"), _c("S-VLAN", "service_vlan_id"), _c("Status", "status"), _c("Locations", "location_count"), _c("Description", "description")),
        allowed_params=COMMON_SORT | frozenset({"search", "status", "network_id", "group_id", "service_vlan_id", "customer_vlan_id", "service_vlan_only"}),
    ),
    "locations": TableSpec(
        "/api/locations/page",
        (_c("Name", "name"), _c("Code", "code"), _c("Network", "network_name"), _c("City", "city_name"), _c("S-VLAN", "service_vlan_id"), _c("Address", "address"), _c("Latitude", "latitude"), _c("Longitude", "longitude"), _c("Status", "status"), _c("Sectors", "sector_count")),
        allowed_params=COMMON_SORT | frozenset({"search", "status", "network_id", "city_id", "group_id", "service_vlan_id", "customer_vlan_id"}),
    ),
    "sectors": TableSpec(
        "/api/sectors/page",
        (_c("Name", "name"), _c("Code", "code"), _c("Role", "role"), _c("Network", "network_name"), _c("City", "city_name"), _c("S-VLAN", "service_vlan_id"), _c("C-VLAN Start", "customer_vlan_start"), _c("C-VLAN End", "customer_vlan_end"), _c("Location", "location_name"), _c("Physical Sector", "physical_sector_device_name"), _c("Sequence", "sequence_number"), _c("Status", "status")),
        allowed_params=COMMON_SORT | frozenset({"search", "status", "network_id", "city_id", "location_id", "group_id", "role", "bound", "service_vlan_id", "customer_vlan_id"}),
    ),
    "customers": TableSpec(
        "/api/customers/page",
        (_c("Customer Code", "customer_code"), _c("Customer", "name"), _c("Status", "status"), _c("Service ID", "service_code"), _c("Sector", "sector_name"), _c("S-VLAN", "service_vlan_id"), _c("C-VLAN", "customer_vlan_id")),
        allowed_params=COMMON_SORT | frozenset({"search", "customer_name", "service_code", "sector_id", "service_vlan_id", "customer_vlan_id", "status"}),
    ),
    "customer_services": TableSpec(
        "/api/customers/{customer_id}/services",
        (_c("Service ID", "service_code"), _c("Sector", "sector_name"), _c("S-VLAN", "service_vlan_id"), _c("C-VLAN", "customer_vlan_id"), _c("CPE", "cpe_name"), _c("Access Point", "access_point_name"), _c("Status", "status")),
        pagination="none", path_params=("customer_id",),
        allowed_params=frozenset({"search", "status", "sort_by", "sort_direction"}),
    ),
    "groups": TableSpec(
        "/api/device-groups/page",
        (_c("Name", "name"), _c("Code", "code"), _c("Kind", "group_kind"), _c("Membership", "membership_mode"), _c("Scope", "scope_type"), _c("Context", "context_name"), _c("Device Scope", "device_scope"), _c("Sector Role", "sector_role"), _c("Devices", "device_count"), _c("Children", "child_count"), _c("Description", "description")),
        allowed_params=COMMON_SORT | frozenset({"search", "group_kind", "membership_mode", "scope_type", "device_scope", "sector_role", "network_id", "city_id", "location_id", "sector_id", "group_id"}),
    ),
    "group_members": TableSpec(
        "/api/device-groups/{group_id}/devices/page",
        (_c("Device", "display_name"), _c("Management IP", "management_ip"), _c("Hostname", "hostname"), _c("Vendor", "vendor"), _c("Model", "model"), _c("Lifecycle", "lifecycle_state"), _c("Operational", "operational_state")),
        path_params=("group_id",), allowed_params=COMMON_SORT | frozenset({"search"}),
    ),
    "group_items": TableSpec(
        "/api/device-groups/{group_id}/items/page",
        (_c("Type", "item_type"), _c("Name", "display_name"), _c("Code", "code"), _c("Device Type", "device_type_code"), _c("Management IP", "management_ip"), _c("Lifecycle", "lifecycle_state"), _c("Operational", "operational_state"), _c("Item Count", "item_count"), _c("Source Groups", "source_groups")),
        path_params=("group_id",), allowed_params=COMMON_SORT | frozenset({"search", "item_type", "device_type", "lifecycle_state", "operational_state", "include_all_children", "child_group_ids"}),
    ),
    "candidates": TableSpec(
        "/api/device-candidates",
        (_c("IP", "ip_address"), _c("State", "state"), _c("Device Name", "display_name_suggestion"), _c("Hostname", "hostname"), _c("Vendor", "vendor"), _c("Model", "model"), _c("Serial", "serial_number"), _c("Confidence", "confidence"), _c("Management Protocol", "management_protocol"), _c("Created", "created_at")),
        pagination="offset", total_key="count", allowed_params=COMMON_SORT | frozenset({"search", "state", "vendor", "device_type_id"}),
    ),
    "discovery_jobs": TableSpec(
        "/api/discovery/jobs/page",
        (_c("Scope Type", "scope_type"), _c("Scope", "scope_value"), _c("Status", "status"), _c("Created", "created_at"), _c("Updated", "updated_at")),
        allowed_params=COMMON_SORT | frozenset({"search", "status", "scope_type"}),
    ),
    "discovery_results": TableSpec(
        "/api/discovery/jobs/{job_id}/results",
        (_c("IP", "ip_address"), _c("Method", "discovery_method"), _c("Status", "status"), _c("Vendor", "vendor"), _c("Model", "model"), _c("Hostname", "hostname"), _c("Serial", "serial_number"), _c("Created", "created_at")),
        pagination="none", path_params=("job_id",),
        allowed_params=frozenset({"search", "method", "status", "sort_by", "sort_direction"}),
    ),
    "alarms": TableSpec(
        "/api/alarms/page",
        (_c("Severity", "severity"), _c("Device", "device_display_name"), _c("Management IP", "management_ip"), _c("State", "state"), _c("Acknowledged", "acknowledged_at"), _c("Owner", "owner_display_name"), _c("Occurrences", "occurrence_count"), _c("Summary", "summary"), _c("Last Raised", "last_raised_at")),
        allowed_params=COMMON_SORT | frozenset({"state", "severity", "acknowledged", "owner", "search"}),
    ),
    "maintenance": TableSpec(
        "/api/maintenance-windows",
        (_c("Name", "name"), _c("State", "state"), _c("Target Type", "target_type"), _c("Target", "target_display_name"), _c("Starts", "starts_at"), _c("Ends", "ends_at"), _c("Reason", "reason"), _c("Enabled", "enabled")),
        page_size=250, allowed_params=COMMON_SORT | frozenset({"state", "target_type", "search"}),
    ),
    "notification_deliveries": TableSpec(
        "/api/notifications/deliveries",
        (_c("Status", "status"), _c("Channel", "channel_type"), _c("Summary", "metadata.summary"), _c("Attempts", "attempt_count"), _c("Next Attempt", "next_attempt_at"), _c("Delivered", "delivered_at"), _c("Error", "last_error_code"), _c("Created", "created_at")),
        page_size=250, allowed_params=frozenset({"status", "channel_type"}), post_process=True,
    ),
    "audit_logs": TableSpec(
        "/api/audit",
        (_c("Occurred", "occurred_at"), _c("Actor", "actor_display_name_snapshot", "actor_username_snapshot"), _c("Action", "action"), _c("Entity", "entity_type"), _c("Entity Display", "entity_display_snapshot.display_name", "entity_display_snapshot.name", "entity_display_snapshot.code"), _c("Result", "result"), _c("Request ID", "request_id"), _c("Source IP", "source_ip"), _c("Description", "description")),
        allowed_params=COMMON_SORT | frozenset({"search", "actor", "action", "entity_key", "result", "request_id", "occurred_after", "occurred_before"}),
    ),
    "operational_logs": TableSpec(
        "/api/operational-logs/page",
        (_c("Timestamp", "timestamp"), _c("Level", "level"), _c("Service", "service"), _c("Logger", "logger"), _c("Message", "message"), _c("Request ID", "request_id"), _c("User ID", "user_id"), _c("Exception", "exception_class")),
        allowed_params=COMMON_SORT | frozenset({"service", "level", "logger", "user_id", "request_id", "search", "since", "until"}),
    ),
    "recycle_batches": TableSpec(
        "/api/recycle-bin",
        (_c("Entity Type", "root_entity_type"), _c("Item", "root_display_snapshot.display_name", "root_display_snapshot.name", "root_display_snapshot.code", "root_display_snapshot.customer_code", "root_display_snapshot.service_code"), _c("Status", "status"), _c("Deleted", "deleted_at"), _c("Reason", "deletion_reason"), _c("Purge After", "purge_after"), _c("Items", "item_count"), _c("Last Error", "last_error_message")),
        allowed_params=COMMON_SORT | frozenset({"search", "status", "entity_type"}),
    ),
    "recycle_items": TableSpec(
        "/api/recycle-bin/items",
        (_c("Entity Type", "entity_type"), _c("Item", "display_snapshot.display_name", "display_snapshot.name", "display_snapshot.code", "display_snapshot.customer_code", "display_snapshot.service_code"), _c("Role", "item_role"), _c("Restore Order", "restore_order"), _c("Purge Order", "purge_order"), _c("Created", "created_at")),
        allowed_params=COMMON_SORT | frozenset({"batch_id", "entity_type", "search"}),
    ),
    "restore_points": TableSpec(
        "/api/restore-points/page",
        (_c("Created", "created_at"), _c("Source", "source"), _c("Status", "status"), _c("Description", "description"), _c("Size Bytes", "artifact_size"), _c("Retention Until", "retention_until"), _c("Pinned", "pinned"), _c("Failure", "failure_message")),
        allowed_params=COMMON_SORT | frozenset({"search", "status", "source", "pinned"}),
    ),
    "users": TableSpec(
        "/api/admin/users/page",
        (_c("Username", "username"), _c("Display Name", "display_name"), _c("Active", "is_active"), _c("Must Change Password", "must_change_password"), _c("Password Change Reason", "password_change_reason"), _c("Roles", "roles"), _c("Direct Permissions", "direct_permissions")),
        allowed_params=frozenset({"search", "status", "role", "sort_by", "sort_dir"}),
    ),
    "user_sessions": TableSpec(
        "/api/admin/users/{user_id}/sessions",
        (_c("Status", "status"), _c("Login", "created_at"), _c("Last Activity", "last_user_activity_at", "last_seen_at"), _c("Expires", "expires_at"), _c("IP", "last_ip", "login_ip"), _c("Browser", "browser_name"), _c("OS", "os_name"), _c("Device", "device_type")),
        pagination="none", path_params=("user_id",), allowed_params=frozenset({"status", "sort_by", "sort_direction"}),
    ),
    "online_sessions": TableSpec(
        "/api/admin/sessions/online",
        (_c("Username", "username"), _c("Display Name", "display_name"), _c("Status", "status"), _c("Login Time", "created_at"), _c("Last Activity", "last_user_activity_at"), _c("Duration Seconds", "duration_seconds"), _c("Idle Seconds", "idle_seconds"), _c("IP", "last_ip", "login_ip"), _c("Browser", "browser_name"), _c("OS", "os_name"), _c("Device", "device_type"), _c("Roles", "roles"), _c("Expires", "expires_at")),
        allowed_params=frozenset({"search", "status", "browser", "operating_system", "device_type", "sort_by", "sort_dir"}),
    ),
    "account_sessions": TableSpec(
        "/api/auth/sessions",
        (_c("Status", "status"), _c("Created", "created_at"), _c("Last Activity", "last_user_activity_at", "last_seen_at"), _c("Expires", "expires_at"), _c("IP", "last_ip", "login_ip"), _c("Browser", "browser_name"), _c("OS", "os_name"), _c("Device", "device_type")),
        pagination="none", allowed_params=frozenset({"search", "status", "current", "sort_by", "sort_direction"}),
    ),
    "settings": TableSpec(
        "/api/admin/settings",
        (_c("Key", "key"), _c("Category", "category"), _c("Configured", "is_configured"), _c("Secret", "is_secret"), _c("Value", "value"), _c("Description", "description")),
        pagination="none", allowed_params=frozenset({"search", "category", "configured", "sort_by", "sort_direction"}),
    ),
    "telemetry_profiles": TableSpec(
        "/api/telemetry/profiles",
        (_c("Name", "name"), _c("Device Type", "device_type_name", "device_type_code"), _c("Enabled", "enabled"), _c("Protocol", "protocol"), _c("Interval Seconds", "interval_seconds"), _c("Timeout Seconds", "timeout_seconds"), _c("Retries", "retries"), _c("Max Metrics", "max_metrics"), _c("Description", "description")),
        pagination="none", allowed_params=frozenset({"search", "enabled", "sort_by", "sort_direction"}),
    ),
    "telemetry_states": TableSpec(
        "/api/telemetry/states",
        (_c("Device", "device_display_name"), _c("Status", "status"), _c("Enabled", "enabled"), _c("Last Collection", "last_collect_at"), _c("Last Success", "last_success_at"), _c("Last Failure", "last_failure_at"), _c("Next Due", "next_collect_at"), _c("Failures", "consecutive_failures"), _c("Duration ms", "last_duration_ms"), _c("Error", "last_error_code")),
        allowed_params=COMMON_SORT | frozenset({"search", "status", "enabled", "device_type"}),
    ),
    "retention_policies": TableSpec(
        "/api/data-lifecycle/policies",
        (_c("Class", "data_class"), _c("Enabled", "enabled"), _c("Retain Days", "retain_days"), _c("Rollup After Days", "rollup_after_days"), _c("Batch Hours", "batch_hours"), _c("Description", "description")),
        pagination="none", allowed_params=frozenset({"search", "enabled", "sort_by", "sort_direction"}),
    ),
    "lifecycle_runs": TableSpec(
        "/api/data-lifecycle/runs",
        (_c("Class", "data_class"), _c("Status", "status"), _c("Started", "started_at"), _c("Completed", "completed_at"), _c("Scanned", "scanned_rows"), _c("Rolled Up", "rolled_up_rows"), _c("Purged", "purged_rows"), _c("Error", "error_code")),
        allowed_params=COMMON_SORT | frozenset({"search", "status", "data_class"}),
    ),
    "import_preview_records": TableSpec(
        "/api/data-exchange/imports/{job_id}",
        (_c("Row", "row_number"), _c("Status", "status"), _c("Error Code", "error_code"), _c("Message", "error_message"), _c("Input Data", "source_data")),
        pagination="none", items_key="records", path_params=("job_id",), allowed_params=frozenset({"record_limit", "sort_by", "sort_direction"}),
    ),
    "import_jobs": TableSpec(
        "/api/data-exchange/imports",
        (_c("Created", "created_at"), _c("Entity", "entity_type"), _c("Filename", "filename"), _c("Format", "file_format"), _c("Status", "status"), _c("Total", "total_records"), _c("Imported", "imported_records"), _c("Errors", "error_records"), _c("Preview Expires", "preview_expires_at"), _c("Committed", "committed_at")),
        allowed_params=COMMON_SORT,
    ),
    "report_definitions": TableSpec(
        "/api/reports/definitions",
        (_c("Name", "name"), _c("Report Type", "report_type"), _c("Format", "format"), _c("Sensitive", "include_sensitive"), _c("Description", "description"), _c("Created", "created_at"), _c("Updated", "updated_at")),
        allowed_params=frozenset({"state", "search", "report_type", "format", "link_state", "sort_by", "sort_direction"}),
    ),
    "report_jobs": TableSpec(
        "/api/reports/jobs",
        (_c("Requested", "requested_at"), _c("Name", "display_name"), _c("Report Type", "report_type"), _c("Format", "format"), _c("Status", "status"), _c("Rows", "row_count"), _c("Artifact", "artifact_name"), _c("Size Bytes", "artifact_size"), _c("Completed", "completed_at"), _c("Error", "error_code")),
        allowed_params=COMMON_SORT,
    ),
    "report_schedules": TableSpec(
        "/api/reports/schedules",
        (_c("Name", "name"), _c("Report Type", "report_type"), _c("Format", "format"), _c("Definition", "definition_name"), _c("Enabled", "enabled"), _c("Interval Minutes", "interval_minutes"), _c("Next Run", "next_run_at"), _c("Last Run", "last_run_at"), _c("Channel", "channel_type"), _c("Destination", "destination")),
        allowed_params=frozenset({"state", "search", "report_type", "format", "link_state", "enabled", "sort_by", "sort_direction"}),
    ),
    "report_deliveries": TableSpec(
        "/api/reports/deliveries",
        (_c("Created", "created_at"), _c("Channel", "channel_type"), _c("Destination", "destination"), _c("Status", "status"), _c("Attempts", "attempt_count"), _c("Next Attempt", "next_attempt_at"), _c("Delivered", "delivered_at"), _c("Response Status", "response_status"), _c("Error", "last_error_code")),
        allowed_params=COMMON_SORT,
    ),
}


def _safe_scalar(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "YES" if value else "NO"
    if isinstance(value, (int, float, str)):
        return value
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        parts: list[str] = []
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            if isinstance(item, (dict, list)):
                continue
            parts.append(f"{key}={item}")
        return "; ".join(parts)
    return str(value)


def _get_path(row: dict[str, Any], path: str) -> Any:
    current: Any = row
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _extract(row: dict[str, Any], spec: ColumnSpec) -> Any:
    for path in spec.paths:
        value = _get_path(row, path)
        if value not in (None, "", [], {}):
            return _safe_scalar(value)
    return ""


def _format_path(spec: TableSpec, filters: dict[str, Any]) -> str:
    path = spec.path
    for name in spec.path_params:
        raw = filters.get(name)
        if raw is None or str(raw).strip() == "":
            raise ValueError(f"{name} is required for this table export.")
        path = path.replace("{" + name + "}", quote(str(raw), safe=""))
    return path


def _query_filters(spec: TableSpec, filters: dict[str, Any]) -> dict[str, str]:
    allowed = spec.allowed_params
    query: dict[str, str] = {}
    for key, value in filters.items():
        if key in spec.path_params or key == "table_id" or key not in allowed:
            continue
        if value is None or value == "" or value == []:
            continue
        if isinstance(value, bool):
            query[key] = "true" if value else "false"
        elif isinstance(value, list):
            query[key] = ",".join(str(item) for item in value)
        else:
            query[key] = str(value)
    return query


def _local_filter_sort(rows: list[dict[str, Any]], filters: dict[str, Any]) -> list[dict[str, Any]]:
    # Small non-paginated endpoints return the complete authorized collection.
    # Reapply the visible table filters here so exports match the UI exactly.
    search = str(filters.get("search") or "").strip().lower()
    exact_map = {
        "method": "discovery_method", "status": "status", "category": "category",
        "enabled": "enabled", "configured": "is_configured", "current": "is_current",
    }
    filtered: list[dict[str, Any]] = []
    for row in rows:
        if search:
            haystack = " ".join(str(v) for v in row.values() if isinstance(v, (str, int, float))).lower()
            if search not in haystack:
                continue
        rejected = False
        for filter_key, row_key in exact_map.items():
            raw = filters.get(filter_key)
            if raw in (None, ""):
                continue
            actual = row.get(row_key)
            expected = str(raw).strip().lower()
            if isinstance(actual, bool):
                if expected in {"true", "false"} and actual != (expected == "true"):
                    rejected = True; break
            elif str(actual or "").strip().lower() != expected:
                rejected = True; break
        if rejected:
            continue
        management = str(filters.get("management") or "").strip().lower()
        primary = str(filters.get("primary") or "").strip().lower()
        if management in {"true", "false"} and bool(row.get("is_management")) != (management == "true"):
            continue
        if primary in {"true", "false"} and bool(row.get("is_primary")) != (primary == "true"):
            continue
        filtered.append(row)
    sort_by = str(filters.get("sort_by") or "").strip()
    direction = str(filters.get("sort_direction") or filters.get("sort_dir") or "asc").strip().lower()
    if sort_by:
        sort_path = {"summary": "metadata.summary"}.get(sort_by, sort_by)
        def sort_value(row: dict[str, Any]):
            value = _get_path(row, sort_path)
            if isinstance(value, (int, float)):
                return (value is None, 0, value)
            return (value is None, 1, str(value or "").lower())
        filtered.sort(key=sort_value, reverse=direction == "desc")
    return filtered


async def _get_json(client: httpx.AsyncClient, path: str, params: dict[str, str]) -> Any:
    response = await client.get(path, params=params)
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail")
        except Exception:
            detail = None
        if isinstance(detail, dict):
            message = detail.get("message") or detail.get("code")
        else:
            message = detail
        raise ValueError(str(message or f"Source table request failed with HTTP {response.status_code}."))
    return response.json()


async def collect_table_rows(request: Request, table_id: str, filters: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    spec = TABLE_EXPORTS.get(table_id.strip().lower())
    if spec is None:
        raise ValueError("Unsupported table export.")
    path = _format_path(spec, filters)
    base = _query_filters(spec, filters)
    authorization = request.headers.get("authorization")
    headers = {"Authorization": authorization} if authorization else {}
    transport = httpx.ASGITransport(app=request.app)
    materialized: list[dict[str, Any]] = []
    async with httpx.AsyncClient(transport=transport, base_url="http://fttw-internal", headers=headers, timeout=120.0) as client:
        if spec.pagination == "none":
            payload = await _get_json(client, path, base)
            if isinstance(payload, list):
                materialized = [item for item in payload if isinstance(item, dict)]
            elif isinstance(payload, dict):
                values = payload.get(spec.items_key, [])
                materialized = [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []
            materialized = _local_filter_sort(materialized, filters)
        elif spec.pagination == "offset":
            offset = 0
            total: int | None = None
            while total is None or offset < total:
                params = {**base, spec.limit_param: str(spec.page_size), spec.offset_param: str(offset)}
                payload = await _get_json(client, path, params)
                if not isinstance(payload, dict):
                    raise ValueError("Source table returned an invalid paginated response.")
                batch = payload.get(spec.items_key, [])
                if not isinstance(batch, list):
                    raise ValueError("Source table returned an invalid item collection.")
                materialized.extend(item for item in batch if isinstance(item, dict))
                total = int(payload.get(spec.total_key) or 0)
                if not batch:
                    break
                offset += len(batch)
        else:
            page = 1
            total: int | None = None
            while total is None or len(materialized) < total:
                params = {**base, spec.page_param: str(page), spec.page_size_param: str(spec.page_size)}
                payload = await _get_json(client, path, params)
                if not isinstance(payload, dict):
                    raise ValueError("Source table returned an invalid paginated response.")
                batch = payload.get(spec.items_key, [])
                if not isinstance(batch, list):
                    raise ValueError("Source table returned an invalid item collection.")
                materialized.extend(item for item in batch if isinstance(item, dict))
                total = int(payload.get(spec.total_key) or 0)
                if not batch:
                    break
                page += 1
        if spec.pagination != "none" and spec.post_process:
            materialized = _local_filter_sort(materialized, filters)
    columns = [column.label for column in spec.columns]
    rows = [{column.label: _extract(row, column) for column in spec.columns} for row in materialized]
    return columns, rows


async def export_table_bytes(request: Request, table_id: str, file_format: str, filters: dict[str, Any]) -> tuple[bytes, str, str, int]:
    fmt = file_format.strip().upper()
    if fmt not in {"CSV", "XLSX"}:
        raise ValueError("Table exports support CSV and XLSX only.")
    columns, rows = await collect_table_rows(request, table_id, filters)
    data = write_tabular_bytes(columns, rows, fmt, title=f"FTTW {table_id.replace('_', ' ').title()}")
    media = {"CSV": "text/csv", "XLSX": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}[fmt]
    return data, f"fttw_{table_id}.{fmt.lower()}", media, len(rows)
