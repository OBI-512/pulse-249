from __future__ import annotations

from pathlib import Path

from app.db.base import Base
from app.settings import settings


F3_TABLES = {
    "configuration_batches",
    "configuration_batch_targets",
}


def _constraint_names(table_name: str) -> set[str]:
    return {
        constraint.name
        for constraint in Base.metadata.tables[table_name].constraints
        if constraint.name
    }


def _index_names(table_name: str) -> set[str]:
    return {
        index.name
        for index in Base.metadata.tables[table_name].indexes
        if index.name
    }


def test_f3_batch_models_are_registered_without_replacing_f1_operation_authority():
    assert F3_TABLES <= set(Base.metadata.tables)

    operations = Base.metadata.tables["configuration_operations"]
    operation_indexes = _index_names("configuration_operations")

    assert operations.name == "configuration_operations"
    assert "uq_configuration_operations_active_device" in operation_indexes
    assert "uq_configuration_operations_actor_idempotency" in operation_indexes


def test_f3_batch_envelope_has_bounded_state_and_idempotency_contract():
    constraints = _constraint_names("configuration_batches")
    indexes = _index_names("configuration_batches")

    assert {
        "ck_configuration_batches_operation_type",
        "ck_configuration_batches_status",
        "ck_configuration_batches_rollout_mode",
        "ck_configuration_batches_maintenance_policy",
        "ck_configuration_batches_request_fingerprint",
        "ck_configuration_batches_scope_fingerprint",
        "ck_configuration_batches_nonnegative_counters",
        "ck_configuration_batches_counter_bounds",
    } <= constraints

    assert {
        "uq_configuration_batches_actor_idempotency",
        "ix_configuration_batches_status_not_before",
        "ix_configuration_batches_actor_created",
    } <= indexes

    columns = Base.metadata.tables["configuration_batches"].c
    assert columns.request_fingerprint.nullable is False
    assert columns.request_summary.nullable is False
    assert columns.authorization_scope.nullable is False
    assert columns.target_count.nullable is False


def test_f3_target_contract_prevents_duplicate_membership_and_operation_replacement():
    table = Base.metadata.tables["configuration_batch_targets"]
    constraints = _constraint_names("configuration_batch_targets")
    indexes = _index_names("configuration_batch_targets")

    assert {
        "uq_configuration_batch_targets_batch_device",
        "uq_configuration_batch_targets_batch_ordinal",
        "uq_configuration_batch_targets_operation",
        "ck_configuration_batch_targets_ordinal",
        "ck_configuration_batch_targets_wave",
        "ck_configuration_batch_targets_status",
        "ck_configuration_batch_targets_operation_status",
    } <= constraints

    assert {
        "ix_configuration_batch_targets_batch_wave_status",
        "ix_configuration_batch_targets_device_created",
    } <= indexes

    operation_fk = next(iter(table.c.configuration_operation_id.foreign_keys))
    device_fk = next(iter(table.c.device_id.foreign_keys))
    batch_fk = next(iter(table.c.batch_id.foreign_keys))

    assert operation_fk.ondelete == "RESTRICT"
    assert device_fk.ondelete == "RESTRICT"
    assert batch_fk.ondelete == "CASCADE"


def test_f3_initial_target_bound_is_explicit():
    assert settings.configuration_batch_max_targets == 100


def test_migration_0041_is_additive_guarded_and_chained_to_current_head():
    path = (
        Path(__file__).resolve().parents[2]
        / "migrations"
        / "versions"
        / "0041_configuration_change_batches.py"
    )
    source = path.read_text(encoding="utf-8")

    assert 'revision = "0041_config_change_batches"' in source
    assert len("0041_config_change_batches") <= 32
    assert 'down_revision = "0040_remote_template_binding"' in source
    assert 'inspector.has_table("configuration_batches")' in source
    assert 'inspector.has_table("configuration_batch_targets")' in source
    assert 'op.create_table(\n            "configuration_batches"' in source
    assert 'op.create_table(\n            "configuration_batch_targets"' in source

    # F3 persistence may reference F1 operation identity but must not alter the
    # authoritative single-device execution table.
    assert 'op.alter_column("configuration_operations"' not in source
    assert 'op.drop_table("configuration_operations")' not in source
    assert 'op.create_table(\n            "configuration_operations"' not in source
