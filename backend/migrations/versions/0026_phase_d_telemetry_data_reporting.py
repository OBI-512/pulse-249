"""Phase D telemetry, data lifecycle, data exchange, and reporting.

Revision ID: 0026_phase_d_reporting
Revises: 0025_vlan_documentation

Migration 0001 materializes current SQLAlchemy metadata on a fresh database.
This revision is therefore idempotent when those Phase-D tables/columns already
exist, while remaining incremental for a deployed 0025 database.
"""
from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0026_phase_d_reporting"
down_revision = "0025_vlan_documentation"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("1c4e6f87-24df-4c99-b9f5-e4ee15a7ec45")

_PERMISSIONS = (
    ("telemetry.read", "Telemetry Read", ("administrator", "operator", "administrative_viewer", "viewer")),
    ("telemetry.manage", "Telemetry Manage", ("administrator",)),
    ("data_lifecycle.read", "Data Lifecycle Read", ("administrator", "operator", "administrative_viewer")),
    ("data_lifecycle.manage", "Data Lifecycle Manage", ("administrator",)),
    ("data_exchange.read", "Data Exchange Read", ("administrator", "operator", "administrative_viewer")),
    ("data_exchange.import", "Data Exchange Import", ("administrator",)),
    ("data_exchange.export", "Data Exchange Export", ("administrator", "operator")),
    ("report.read", "Report Read", ("administrator", "operator", "administrative_viewer", "viewer")),
    ("report.manage", "Report Manage", ("administrator", "operator")),
    ("report.export", "Report Export", ("administrator", "operator")),
    ("report.schedule", "Report Schedule", ("administrator", "operator")),
    ("report.sensitive", "Report Sensitive Fields", ("administrator",)),
)

_SETTINGS = (
    ("telemetry.enabled", {"value": True}, "Enable independent telemetry scheduling."),
    ("telemetry.dispatch_limit_per_tick", {"value": 250}, "Maximum telemetry devices claimed per dispatcher tick."),
    ("telemetry.task_batch_size", {"value": 50}, "Maximum telemetry devices carried by one worker task."),
    ("telemetry.max_outstanding_devices", {"value": 2000}, "Backpressure cap for claimed telemetry devices."),
    ("telemetry.worker_concurrency", {"value": 16}, "Concurrent telemetry collectors inside one worker batch."),
    ("telemetry.lease_seconds", {"value": 180}, "Telemetry claim lease duration."),
)

_RETENTION = (
    ("TELEMETRY_RAW", 30, 7, 24, "Raw telemetry retention with hourly rollup before purge."),
    ("TELEMETRY_ROLLUP", 365, None, 24, "Historical telemetry rollup retention."),
    ("IMPORT_PREVIEW", 7, None, 24, "Expired import preview/evidence retention."),
    ("REPORT_ARTIFACT", 30, None, 24, "Generated report artifact retention."),
)

_DEFAULT_METRICS = [
    {"key": "sys_uptime_seconds", "oid": "1.3.6.1.2.1.1.3.0", "kind": "COUNTER", "unit": "seconds", "transform": "timeticks_seconds"},
    {"key": "sys_name", "oid": "1.3.6.1.2.1.1.5.0", "kind": "STATE", "transform": "raw"},
    {"key": "if_count", "oid": "1.3.6.1.2.1.2.1.0", "kind": "GAUGE", "unit": "interfaces", "transform": "int"},
]


def _id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def _inspector(bind):
    return sa.inspect(bind)


def _has_table(bind, table: str) -> bool:
    return _inspector(bind).has_table(table)


def _columns(bind, table: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_columns(table)}


def _checks(bind, table: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_check_constraints(table) if row.get("name")}


def _indexes(bind, table: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_indexes(table) if row.get("name")}


def _uniques(bind, table: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_unique_constraints(table) if row.get("name")}


def _fks(bind, table: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_foreign_keys(table) if row.get("name")}


def _create_phase_d_tables(bind) -> None:
    from app.models import Base

    names = (
        "telemetry_profiles", "telemetry_device_state", "telemetry_metrics",
        "telemetry_metric_rollups", "data_retention_policies", "data_lifecycle_runs",
        "report_definitions", "report_schedules", "report_jobs", "report_deliveries",
    )
    Base.metadata.create_all(bind=bind, tables=[Base.metadata.tables[name] for name in names], checkfirst=True)


def _upgrade_import_tables(bind) -> None:
    if not _has_table(bind, "import_jobs") or not _has_table(bind, "import_records"):
        raise RuntimeError("Phase D requires existing import_jobs/import_records baseline tables.")

    cols = _columns(bind, "import_jobs")
    additions = (
        ("entity_type", sa.String(length=40), True, None),
        ("file_format", sa.String(length=10), True, None),
        ("file_sha256", sa.String(length=64), True, None),
        ("created_by_user_id", sa.UUID(), True, None),
        ("scope_snapshot", postgresql.JSONB(astext_type=sa.Text()), False, sa.text("'{}'::jsonb")),
        ("scope_fingerprint", sa.String(length=64), True, None),
        ("idempotency_key", sa.String(length=255), True, None),
        ("preview_expires_at", sa.DateTime(timezone=True), True, None),
        ("committed_at", sa.DateTime(timezone=True), True, None),
        ("validation_summary", postgresql.JSONB(astext_type=sa.Text()), False, sa.text("'{}'::jsonb")),
    )
    for name, typ, nullable, default in additions:
        if name not in cols:
            op.add_column("import_jobs", sa.Column(name, typ, nullable=nullable, server_default=default))
            cols.add(name)

    fks = _fks(bind, "import_jobs")
    if "fk_import_jobs_created_by_user_id_users" not in fks:
        # Inspector may report an unnamed fresh-metadata FK; do not duplicate it.
        existing_cols = {tuple(row.get("constrained_columns") or []) for row in _inspector(bind).get_foreign_keys("import_jobs")}
        if ("created_by_user_id",) not in existing_cols:
            op.create_foreign_key(
                "fk_import_jobs_created_by_user_id_users", "import_jobs", "users",
                ["created_by_user_id"], ["id"], ondelete="SET NULL",
            )

    checks = _checks(bind, "import_jobs")
    if "ck_import_jobs_status" not in checks:
        unexpected = bind.execute(sa.text(
            "SELECT status FROM import_jobs "
            "WHERE status NOT IN ('PENDING','PREVIEWED','COMMITTING','COMMITTED','COMPLETED','FAILED','EXPIRED') "
            "LIMIT 1"
        )).scalar_one_or_none()
        if unexpected is not None:
            raise RuntimeError(f"Unsupported legacy import_jobs.status value: {unexpected!r}")
        op.create_check_constraint(
            "ck_import_jobs_status", "import_jobs",
            "status IN ('PENDING','PREVIEWED','COMMITTING','COMMITTED','COMPLETED','FAILED','EXPIRED')",
        )

    idx = _indexes(bind, "import_jobs")
    if "ix_import_jobs_actor_created" not in idx:
        op.create_index("ix_import_jobs_actor_created", "import_jobs", ["created_by_user_id", "created_at"])
    if "ix_import_jobs_status_expires" not in idx:
        op.create_index("ix_import_jobs_status_expires", "import_jobs", ["status", "preview_expires_at"])
    if "uq_import_jobs_actor_idempotency" not in idx:
        op.create_index(
            "uq_import_jobs_actor_idempotency", "import_jobs", ["created_by_user_id", "idempotency_key"],
            unique=True, postgresql_where=sa.text("idempotency_key IS NOT NULL"),
        )

    rec_cols = _columns(bind, "import_records")
    if "error_code" not in rec_cols:
        op.add_column("import_records", sa.Column("error_code", sa.String(length=120), nullable=True))
    if "normalized_data" not in rec_cols:
        op.add_column(
            "import_records",
            sa.Column("normalized_data", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        )

    uniques = _uniques(bind, "import_records")
    if "uq_import_records_job_row" not in uniques:
        # Fresh metadata may surface this as an index on some inspector versions.
        if "uq_import_records_job_row" not in _indexes(bind, "import_records"):
            op.create_unique_constraint("uq_import_records_job_row", "import_records", ["import_job_id", "row_number"])
    if "ix_import_records_job_status" not in _indexes(bind, "import_records"):
        op.create_index("ix_import_records_job_status", "import_records", ["import_job_id", "status"])


def _seed_permissions(bind) -> None:
    for code, name, role_codes in _PERMISSIONS:
        permission_id = _id(f"permission:{code}")
        bind.execute(sa.text(
            "INSERT INTO permissions (id, code, name, description) "
            "VALUES (:id, :code, :name, :description) "
            "ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description"
        ), {"id": permission_id, "code": code, "name": name, "description": f"{name} permission"})
        for role_code in role_codes:
            bind.execute(sa.text(
                "INSERT INTO role_permissions (id, role_id, permission_id) "
                "SELECT :rp_id, r.id, p.id FROM roles r JOIN permissions p ON p.code = :permission_code "
                "WHERE r.code = :role_code "
                "AND NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id = r.id AND rp.permission_id = p.id)"
            ), {
                "rp_id": _id(f"role_permission:{role_code}:{code}"),
                "permission_code": code,
                "role_code": role_code,
            })


def _seed_settings(bind) -> None:
    for key, value, description in _SETTINGS:
        bind.execute(sa.text(
            "INSERT INTO system_settings (id, key, value, description, is_secret) "
            "VALUES (:id, :key, CAST(:value AS jsonb), :description, false) "
            "ON CONFLICT (key) DO NOTHING"
        ), {"id": _id(f"setting:{key}"), "key": key, "value": sa.text("NULL") if False else __import__("json").dumps(value), "description": description})


def _seed_retention(bind) -> None:
    for data_class, retain_days, rollup_after_days, batch_hours, description in _RETENTION:
        bind.execute(sa.text(
            "INSERT INTO data_retention_policies "
            "(id, data_class, enabled, retain_days, rollup_after_days, batch_hours, description) "
            "VALUES (:id, :data_class, true, :retain_days, :rollup_after_days, :batch_hours, :description) "
            "ON CONFLICT (data_class) DO NOTHING"
        ), {
            "id": _id(f"retention:{data_class}"), "data_class": data_class,
            "retain_days": retain_days, "rollup_after_days": rollup_after_days,
            "batch_hours": batch_hours, "description": description,
        })


def _seed_profiles(bind) -> None:
    import json
    rows = bind.execute(sa.text("SELECT id, code FROM device_types ORDER BY code")).mappings().all()
    for row in rows:
        code = str(row["code"])
        bind.execute(sa.text(
            "INSERT INTO telemetry_profiles "
            "(id, device_type_id, name, enabled, protocol, interval_seconds, timeout_seconds, retries, max_metrics, metric_definitions, vendor_extensions, description) "
            "VALUES (:id, :device_type_id, :name, false, 'SNMP', 900, 5, 1, 32, CAST(:metrics AS jsonb), '{}'::jsonb, :description) "
            "ON CONFLICT (device_type_id) DO NOTHING"
        ), {
            "id": _id(f"telemetry_profile:{code}"), "device_type_id": row["id"],
            "name": f"{code} Standard", "metrics": json.dumps(_DEFAULT_METRICS),
            "description": "Safe opt-in Phase D SNMP telemetry profile. Availability remains independent.",
        })


def upgrade() -> None:
    bind = op.get_bind()
    _create_phase_d_tables(bind)
    _upgrade_import_tables(bind)
    _seed_permissions(bind)
    _seed_settings(bind)
    _seed_retention(bind)
    _seed_profiles(bind)


def downgrade() -> None:
    bind = op.get_bind()

    # Remove catalog grants introduced by this migration. Custom role grants to
    # these permission IDs disappear via role_permissions before permissions.
    codes = tuple(row[0] for row in _PERMISSIONS)
    bind.execute(sa.text("DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code = ANY(:codes))"), {"codes": list(codes)})
    bind.execute(sa.text("DELETE FROM user_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code = ANY(:codes))"), {"codes": list(codes)})
    bind.execute(sa.text("DELETE FROM permissions WHERE code = ANY(:codes)"), {"codes": list(codes)})
    bind.execute(sa.text("DELETE FROM system_settings WHERE key = ANY(:keys)"), {"keys": [row[0] for row in _SETTINGS]})

    # Report tables have a report_jobs <-> report_schedules FK cycle. Explicitly
    # drop the schedule FK from jobs first where present.
    if _has_table(bind, "report_jobs"):
        for fk in _inspector(bind).get_foreign_keys("report_jobs"):
            if fk.get("referred_table") == "report_schedules" and fk.get("name"):
                op.drop_constraint(fk["name"], "report_jobs", type_="foreignkey")
    for table in (
        "report_deliveries", "report_jobs", "report_schedules", "report_definitions",
        "data_lifecycle_runs", "data_retention_policies", "telemetry_metric_rollups",
        "telemetry_metrics", "telemetry_device_state", "telemetry_profiles",
    ):
        if _has_table(bind, table):
            op.drop_table(table)

    if _has_table(bind, "import_records"):
        if "ix_import_records_job_status" in _indexes(bind, "import_records"):
            op.drop_index("ix_import_records_job_status", table_name="import_records")
        if "uq_import_records_job_row" in _uniques(bind, "import_records"):
            op.drop_constraint("uq_import_records_job_row", "import_records", type_="unique")
        for column in ("normalized_data", "error_code"):
            if column in _columns(bind, "import_records"):
                op.drop_column("import_records", column)

    if _has_table(bind, "import_jobs"):
        for index in ("uq_import_jobs_actor_idempotency", "ix_import_jobs_status_expires", "ix_import_jobs_actor_created"):
            if index in _indexes(bind, "import_jobs"):
                op.drop_index(index, table_name="import_jobs")
        if "ck_import_jobs_status" in _checks(bind, "import_jobs"):
            op.drop_constraint("ck_import_jobs_status", "import_jobs", type_="check")
        for fk in _inspector(bind).get_foreign_keys("import_jobs"):
            if tuple(fk.get("constrained_columns") or []) == ("created_by_user_id",) and fk.get("name"):
                op.drop_constraint(fk["name"], "import_jobs", type_="foreignkey")
                break
        for column in (
            "validation_summary", "committed_at", "preview_expires_at", "idempotency_key",
            "scope_fingerprint", "scope_snapshot", "created_by_user_id", "file_sha256",
            "file_format", "entity_type",
        ):
            if column in _columns(bind, "import_jobs"):
                op.drop_column("import_jobs", column)
