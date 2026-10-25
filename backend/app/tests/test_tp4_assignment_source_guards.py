from __future__ import annotations

from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[2]


def test_tp4_access_apply_rechecks_fail_on_conflict_after_locked_read() -> None:
    source = (
        BACKEND_ROOT / "app" / "services" / "access_template_assignments.py"
    ).read_text(encoding="utf-8")
    apply_block = source.split("async def apply_device_access_assignment(", 1)[1]
    locked_read = apply_block.index("for_update=True")
    recheck = apply_block.index('if conflict_policy == "FAIL_ON_CONFLICT":', locked_read)
    conflict_code = apply_block.index('"ACCESS_TEMPLATE_DEVICE_PROTOCOL_CONFLICT"', recheck)
    create_row = apply_block.index("AccessTemplateAssignment(", recheck)
    assert locked_read < recheck < conflict_code < create_row


def test_tp4_preview_fingerprint_binds_exact_access_revision_identity() -> None:
    source = (
        BACKEND_ROOT / "app" / "services" / "template_assignment_batches.py"
    ).read_text(encoding="utf-8")
    summary = source.split("def _request_summary(", 1)[1].split("def _request_fingerprint(", 1)[0]
    assert '"revision_id": str(revision.id)' in summary
    assert '"revision_number": revision.revision_number' in summary
    assert '"definition_sha256": revision.definition_sha256' in summary
    apply_block = source.split("async def apply_batch(", 1)[1]
    assert "expected_summary = _request_summary(" in apply_block
    assert "if expected_summary != summary:" in apply_block
    assert '"TEMPLATE_ASSIGNMENT_TEMPLATE_STATE_CHANGED"' in apply_block


def test_tp4_configuration_binding_refinement_is_installed_before_router_imports() -> None:
    router = (BACKEND_ROOT / "app" / "api" / "router.py").read_text(encoding="utf-8")
    refinement = (
        BACKEND_ROOT / "app" / "services" / "configuration_binding_metadata.py"
    ).read_text(encoding="utf-8")
    install_import = router.index("configuration_binding_metadata")
    router_imports = router.index("from .routers import")
    assert install_import < router_imports
    assert "_configuration_service.bind_device = bind_device_for_assignment" in refinement
    assert "if payload.enabled:" in refinement
    assert "return await _original_bind_device(" in refinement


def test_tp4_assignment_sources_do_not_dispatch_configuration_operations() -> None:
    sources = "\n".join(
        (
            BACKEND_ROOT / "app" / "services" / name
        ).read_text(encoding="utf-8")
        for name in (
            "access_template_assignments.py",
            "template_assignment_batches.py",
            "data_exchange_template_mapping.py",
            "configuration_binding_metadata.py",
        )
    )
    for forbidden in (
        "send_task(",
        "delay(",
        "apply_async(",
        "queue_operation(",
        "ConfigurationOperation(",
    ):
        assert forbidden not in sources
