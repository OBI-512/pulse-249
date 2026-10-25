"""Add C2 operational event and alarm engine.

Revision ID: 0022_alarm_event_engine
Revises: 0021_device_availability

The replacement baseline creates current SQLAlchemy metadata in migration 0001,
so this revision supports both an existing 0021 database and a fresh database
where the C2 tables were already materialized by current metadata.
"""
from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op


revision = "0022_alarm_event_engine"
down_revision = "0021_device_availability"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_PERMISSIONS = (
    ("alarm.read", "Alarm Read", ("administrator", "operator", "administrative_viewer", "viewer")),
    ("alarm.acknowledge", "Alarm Acknowledge", ("administrator", "operator")),
    ("alarm.assign", "Alarm Assign", ("administrator", "operator")),
    ("alarm.clear", "Alarm Clear", ("administrator", "operator")),
)


def _id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def _inspector(bind):
    return sa.inspect(bind)


def _has_table(bind, table_name: str) -> bool:
    return _inspector(bind).has_table(table_name)


def _index_names(bind, table_name: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_indexes(table_name) if row.get("name")}


def _create_operational_events(bind) -> None:
    if _has_table(bind, "operational_events"):
        return
    op.create_table(
        "operational_events",
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("correlation_key", sa.String(length=255), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "severity IN ('INFO','WARNING','MINOR','MAJOR','CRITICAL')",
            name="ck_operational_events_severity",
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_alarms(bind) -> None:
    if _has_table(bind, "alarms"):
        return
    op.create_table(
        "alarms",
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("alarm_type", sa.String(length=80), nullable=False),
        sa.Column("correlation_key", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("state", sa.String(length=20), server_default="ACTIVE", nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("first_raised_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_raised_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_cleared_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by_user_id", sa.UUID(), nullable=True),
        sa.Column("owner_user_id", sa.UUID(), nullable=True),
        sa.Column("occurrence_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("last_event_id", sa.UUID(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "severity IN ('INFO','WARNING','MINOR','MAJOR','CRITICAL')",
            name="ck_alarms_severity",
        ),
        sa.CheckConstraint("state IN ('ACTIVE','CLEARED')", name="ck_alarms_state"),
        sa.CheckConstraint("occurrence_count >= 1", name="ck_alarms_occurrence_count"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["acknowledged_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["last_event_id"], ["operational_events.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_alarm_history(bind) -> None:
    if _has_table(bind, "alarm_history"):
        return
    op.create_table(
        "alarm_history",
        sa.Column("alarm_id", sa.UUID(), nullable=False),
        sa.Column("event_id", sa.UUID(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("actor_user_id", sa.UUID(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("before_summary", postgresql.JSONB(), nullable=True),
        sa.Column("after_summary", postgresql.JSONB(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "action IN ('OPENED','REOPENED','ACKNOWLEDGED','ASSIGNED','UNASSIGNED','MANUALLY_CLEARED','AUTO_CLEARED')",
            name="ck_alarm_history_action",
        ),
        sa.ForeignKeyConstraint(["alarm_id"], ["alarms.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["operational_events.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )


def _ensure_indexes(bind) -> None:
    event_indexes = _index_names(bind, "operational_events")
    for name, columns in (
        ("ix_operational_events_occurred_at", ["occurred_at"]),
        ("ix_operational_events_device_occurred_at", ["device_id", "occurred_at"]),
        ("ix_operational_events_type_occurred_at", ["event_type", "occurred_at"]),
        ("ix_operational_events_correlation_occurred_at", ["correlation_key", "occurred_at"]),
    ):
        if name not in event_indexes:
            op.create_index(name, "operational_events", columns)

    alarm_indexes = _index_names(bind, "alarms")
    definitions = (
        ("uq_alarms_correlation_key", ["correlation_key"], True),
        ("ix_alarms_state_severity", ["state", "severity"], False),
        ("ix_alarms_device_state", ["device_id", "state"], False),
        ("ix_alarms_owner_state", ["owner_user_id", "state"], False),
        ("ix_alarms_last_raised_at", ["last_raised_at"], False),
    )
    for name, columns, unique in definitions:
        if name not in alarm_indexes:
            op.create_index(name, "alarms", columns, unique=unique)

    history_indexes = _index_names(bind, "alarm_history")
    for name, columns in (
        ("ix_alarm_history_alarm_occurred_at", ["alarm_id", "occurred_at"]),
        ("ix_alarm_history_action_occurred_at", ["action", "occurred_at"]),
    ):
        if name not in history_indexes:
            op.create_index(name, "alarm_history", columns)


def _seed_permissions(bind) -> None:
    for code, name, role_codes in _PERMISSIONS:
        bind.execute(
            sa.text(
                """
                INSERT INTO permissions (id, code, name, description)
                VALUES (:id, :code, :name, :description)
                ON CONFLICT (code) DO UPDATE
                SET name = EXCLUDED.name, description = EXCLUDED.description
                """
            ),
            {"id": _id(f"perm:{code}"), "code": code, "name": name, "description": f"{name} permission"},
        )
        for role_code in role_codes:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO role_permissions (id, role_id, permission_id)
                    SELECT :id, r.id, p.id
                    FROM roles r
                    CROSS JOIN permissions p
                    WHERE r.code = :role_code AND p.code = :code
                    ON CONFLICT (role_id, permission_id) DO NOTHING
                    """
                ),
                {"id": _id(f"roleperm:{role_code}:{code}"), "role_code": role_code, "code": code},
            )


def _backfill_current_offline_conditions(bind) -> None:
    rows = list(bind.execute(sa.text(
        """
        SELECT da.device_id, da.status_changed_at, d.display_name
        FROM device_availability da
        JOIN devices d ON d.id = da.device_id
        LEFT JOIN alarms a ON a.correlation_key = ('device:' || da.device_id::text || ':availability:offline')
        WHERE da.status = 'OFFLINE'
          AND d.deleted_at IS NULL
          AND a.id IS NULL
        ORDER BY da.device_id
        """
    )).mappings())
    for row in rows:
        event_id = uuid.uuid4()
        alarm_id = uuid.uuid4()
        history_id = uuid.uuid4()
        correlation = f"device:{row['device_id']}:availability:offline"
        occurred_at = row["status_changed_at"]
        summary = f"{row['display_name']} is offline."
        bind.execute(sa.text(
            """
            INSERT INTO operational_events
                (id, device_id, event_type, severity, correlation_key, occurred_at, summary, metadata)
            VALUES
                (:id, :device_id, 'DEVICE_AVAILABILITY_OFFLINE', 'MAJOR', :correlation_key,
                 :occurred_at, :summary, CAST(:metadata AS jsonb))
            """
        ), {
            "id": event_id,
            "device_id": row["device_id"],
            "correlation_key": correlation,
            "occurred_at": occurred_at,
            "summary": summary,
            "metadata": '{"source":"C2_MIGRATION_BACKFILL"}',
        })
        bind.execute(sa.text(
            """
            INSERT INTO alarms
                (id, device_id, alarm_type, correlation_key, severity, state, summary,
                 first_raised_at, last_raised_at, occurrence_count, last_event_id)
            VALUES
                (:id, :device_id, 'DEVICE_AVAILABILITY_OFFLINE', :correlation_key, 'MAJOR',
                 'ACTIVE', :summary, :occurred_at, :occurred_at, 1, :event_id)
            ON CONFLICT (correlation_key) DO NOTHING
            """
        ), {
            "id": alarm_id,
            "device_id": row["device_id"],
            "correlation_key": correlation,
            "summary": summary,
            "occurred_at": occurred_at,
            "event_id": event_id,
        })
        persisted_alarm_id = bind.execute(
            sa.text("SELECT id FROM alarms WHERE correlation_key = :correlation_key"),
            {"correlation_key": correlation},
        ).scalar_one()
        if persisted_alarm_id == alarm_id:
            bind.execute(sa.text(
                """
                INSERT INTO alarm_history
                    (id, alarm_id, event_id, occurred_at, action, after_summary, metadata)
                VALUES
                    (:id, :alarm_id, :event_id, :occurred_at, 'OPENED',
                     CAST(:after_summary AS jsonb), CAST(:metadata AS jsonb))
                """
            ), {
                "id": history_id,
                "alarm_id": alarm_id,
                "event_id": event_id,
                "occurred_at": occurred_at,
                "after_summary": '{"state":"ACTIVE","severity":"MAJOR","occurrence_count":1}',
                "metadata": '{"source":"C2_MIGRATION_BACKFILL"}',
            })


def upgrade() -> None:
    bind = op.get_bind()
    _create_operational_events(bind)
    _create_alarms(bind)
    _create_alarm_history(bind)
    _ensure_indexes(bind)
    _seed_permissions(bind)
    _backfill_current_offline_conditions(bind)


def downgrade() -> None:
    bind = op.get_bind()
    for table in ("alarm_history", "alarms", "operational_events"):
        if _has_table(bind, table):
            op.drop_table(table)
    codes = [code for code, _, _ in _PERMISSIONS]
    bind.execute(sa.text("DELETE FROM user_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code IN :codes)")
                 .bindparams(sa.bindparam("codes", expanding=True, value=codes)))
    bind.execute(sa.text("DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code IN :codes)")
                 .bindparams(sa.bindparam("codes", expanding=True, value=codes)))
    bind.execute(sa.text("DELETE FROM permissions WHERE code IN :codes")
                 .bindparams(sa.bindparam("codes", expanding=True, value=codes)))
