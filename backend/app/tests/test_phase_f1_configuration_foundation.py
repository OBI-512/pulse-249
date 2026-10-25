from __future__ import annotations

from pathlib import Path

import pytest

from app.configuration.contracts import (
    AdapterDescriptor,
    ConfigurationAdapter,
    ConfigurationAdapterRegistry,
    ConfigurationCapability,
    ConfigurationCaptureResult,
    ConfigurationExecutionContext,
    ConfigurationFunctionDefinition,
    ConfigurationTemplateDefinition,
    ConfigurationTransport,
    ConfigurationVerificationResult,
    ParameterSource,
    ParameterValueType,
    TemplateParameterDefinition,
    validate_env_secret_reference,
)
from app.configuration.state import ensure_operation_transition, ensure_step_transition
from app.db.base import Base
from app.security.permission_dependencies import expand_permission_codes
from app.security.permissions import Permission as P


F1_TABLES = {
    "configuration_templates",
    "configuration_template_versions",
    "configuration_functions",
    "device_configuration_bindings",
    "configuration_snapshots",
    "configuration_operations",
    "configuration_operation_steps",
    "device_configuration_states",
}


def test_phase_f1_models_are_registered_in_sqlalchemy_metadata():
    assert F1_TABLES <= set(Base.metadata.tables)



def test_phase_f1_database_contract_contains_fail_closed_indexes_and_encryption_guards():
    version = Base.metadata.tables["configuration_template_versions"]
    snapshots = Base.metadata.tables["configuration_snapshots"]
    operations = Base.metadata.tables["configuration_operations"]

    version_indexes = {index.name for index in version.indexes}
    snapshot_constraints = {constraint.name for constraint in snapshots.constraints if constraint.name}
    operation_indexes = {index.name for index in operations.indexes}

    assert "uq_configuration_template_versions_published" in version_indexes
    assert "ck_configuration_snapshots_encryption_scheme" in snapshot_constraints
    assert "ck_configuration_snapshots_encryption_key_reference" in snapshot_constraints
    assert "ck_configuration_snapshots_ready_artifact" in snapshot_constraints
    assert "uq_configuration_operations_active_device" in operation_indexes
    assert "uq_configuration_operations_actor_idempotency" in operation_indexes

def test_phase_f1_permissions_are_explicit_and_device_scoped_actions_require_device_visibility():
    codes = {
        P.DEVICE_CONFIGURATION_READ,
        P.DEVICE_CONFIGURATION_CAPTURE,
        P.DEVICE_CONFIGURATION_APPLY,
        P.DEVICE_CONFIGURATION_RESTORE,
        P.DEVICE_CONFIGURATION_TEMPLATE_READ,
        P.DEVICE_CONFIGURATION_TEMPLATE_MANAGE,
    }
    assert len(codes) == 6
    for permission in (
        P.DEVICE_CONFIGURATION_READ,
        P.DEVICE_CONFIGURATION_CAPTURE,
        P.DEVICE_CONFIGURATION_APPLY,
        P.DEVICE_CONFIGURATION_RESTORE,
    ):
        assert P.DEVICE_READ in expand_permission_codes([permission])
    assert P.DEVICE_CONFIGURATION_TEMPLATE_READ in expand_permission_codes([P.DEVICE_CONFIGURATION_TEMPLATE_MANAGE])


def test_template_definition_supports_vendor_neutral_functions_and_ordered_patch_metadata():
    vlan = ConfigurationFunctionDefinition(
        code="create_vlan",
        name="Create VLAN",
        parameters=[
            TemplateParameterDefinition(
                name="vlan_id",
                label="VLAN ID",
                value_type=ParameterValueType.VLAN_ID,
                minimum=2,
                maximum=4094,
            ),
            TemplateParameterDefinition(
                name="vlan_name",
                label="VLAN Name",
                value_type=ParameterValueType.STRING,
                required=False,
            ),
        ],
        execution_spec={"adapter_action": "create_vlan"},
        verification_spec={"adapter_action": "verify_vlan"},
        rollback_spec={"adapter_action": "delete_vlan"},
        required_capabilities={ConfigurationCapability.APPLY, ConfigurationCapability.VERIFY},
        default_order=20,
    )
    definition = ConfigurationTemplateDefinition(
        adapter_key="generic.ssh_cli",
        transport=ConfigurationTransport.SSH_CLI,
        capabilities={
            ConfigurationCapability.CAPTURE,
            ConfigurationCapability.APPLY,
            ConfigurationCapability.VERIFY,
            ConfigurationCapability.RESTORE,
            ConfigurationCapability.ROLLBACK,
        },
        functions=[vlan],
    )
    assert definition.adapter_key == "generic.ssh_cli"
    assert definition.functions[0].default_order == 20
    assert definition.functions[0].execution_spec == {"adapter_action": "create_vlan"}


def test_template_sensitive_parameters_cannot_embed_secret_defaults():
    with pytest.raises(ValueError, match="CONFIGURATION_SENSITIVE_PARAMETER_DEFAULT_FORBIDDEN"):
        TemplateParameterDefinition(
            name="wireless_key",
            label="Wireless key",
            value_type=ParameterValueType.STRING,
            source=ParameterSource.OPERATOR,
            sensitive=True,
            default="must-not-be-stored",
        )


def test_template_function_must_not_claim_capability_missing_from_template():
    function = ConfigurationFunctionDefinition(
        code="restore_config",
        name="Restore configuration",
        required_capabilities={ConfigurationCapability.RESTORE},
    )
    with pytest.raises(ValueError, match="CONFIGURATION_TEMPLATE_FUNCTION_CAPABILITY_UNDECLARED"):
        ConfigurationTemplateDefinition(
            adapter_key="generic.http_api",
            transport=ConfigurationTransport.HTTP_API,
            capabilities={ConfigurationCapability.CAPTURE},
            functions=[function],
        )


def test_configuration_secret_reference_is_environment_only():
    assert validate_env_secret_reference("env://FTTW_DEVICE_CONFIG_SECRET") == "env://FTTW_DEVICE_CONFIG_SECRET"
    assert validate_env_secret_reference(None) is None
    for invalid in ("plain-password", "vault://secret", "env://bad-name"):
        with pytest.raises(ValueError, match="CONFIGURATION_SECRET_REFERENCE_INVALID"):
            validate_env_secret_reference(invalid)


class _Adapter(ConfigurationAdapter):
    descriptor = AdapterDescriptor(
        key="test.adapter",
        transport=ConfigurationTransport.SSH_CLI,
        capabilities=frozenset({ConfigurationCapability.CAPTURE, ConfigurationCapability.VERIFY}),
    )

    async def validate_template(self, definition):
        return None

    async def capture(self, context):
        return ConfigurationCaptureResult(payload=b"config", metadata={}, restorable=True)

    async def validate_candidate(self, context, candidate, function_specs):
        return None

    async def apply(self, context, candidate, function_specs):
        return {}

    async def verify(self, context, expected, verification_specs):
        return ConfigurationVerificationResult(success=True, summary={})

    async def restore(self, context, snapshot):
        return {}


def test_adapter_registry_is_explicit_and_capability_based():
    registry = ConfigurationAdapterRegistry()
    adapter = _Adapter()
    registry.register(adapter)
    assert registry.get("test.adapter") is adapter
    registry.validate_capabilities("test.adapter", {ConfigurationCapability.CAPTURE})
    with pytest.raises(ValueError, match="CONFIGURATION_ADAPTER_ALREADY_REGISTERED"):
        registry.register(_Adapter())
    with pytest.raises(ValueError, match="CONFIGURATION_ADAPTER_CAPABILITY_UNAVAILABLE"):
        registry.validate_capabilities("test.adapter", {ConfigurationCapability.APPLY})


def test_operation_state_machine_never_allows_false_success_or_rollback_success():
    ensure_operation_transition("QUEUED", "RUNNING")
    ensure_operation_transition("RUNNING", "ROLLING_BACK")
    ensure_operation_transition("ROLLING_BACK", "ROLLED_BACK")
    with pytest.raises(ValueError, match="CONFIGURATION_OPERATION_TRANSITION_INVALID"):
        ensure_operation_transition("QUEUED", "SUCCEEDED")
    with pytest.raises(ValueError, match="CONFIGURATION_OPERATION_TRANSITION_INVALID"):
        ensure_operation_transition("ROLLING_BACK", "SUCCEEDED")

    ensure_step_transition("PENDING", "RUNNING")
    ensure_step_transition("RUNNING", "SUCCEEDED")
    with pytest.raises(ValueError, match="CONFIGURATION_OPERATION_STEP_TRANSITION_INVALID"):
        ensure_step_transition("PENDING", "SUCCEEDED")


def test_migration_0036_is_guarded_for_clean_install_and_seeds_least_privilege_catalog():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0036_config_foundation.py"
    source = path.read_text(encoding="utf-8")
    assert 'revision = "0036_config_foundation"' in source
    assert 'down_revision = "0035_remove_web_tls10_compat"' in source
    assert 'inspector.has_table("configuration_templates")' in source
    assert 'roles.code = \'administrator\'' in source
    assert "device.configuration.apply" in source
    assert "device.configuration.template.manage" in source
    assert "roles.code = 'operator'" not in source


def test_seed_catalog_keeps_configuration_permissions_admin_only_by_default():
    seed = (Path(__file__).resolve().parents[2] / "scripts" / "seed_demo_data.py").read_text(encoding="utf-8")
    for code in (
        "device.configuration.read",
        "device.configuration.capture",
        "device.configuration.apply",
        "device.configuration.restore",
        "device.configuration.template.read",
        "device.configuration.template.manage",
    ):
        assert code in seed
    operator_block = seed.split("OPERATOR = ADMIN - {", 1)[1].split("}", 1)[0]
    assert "device.configuration.apply" in operator_block
    assert "device.configuration.template.manage" in operator_block
