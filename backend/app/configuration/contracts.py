from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator


_ADAPTER_KEY = re.compile(r"^[a-z][a-z0-9_.-]{1,119}$")
_PARAMETER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,79}$")
_ENV_REFERENCE = re.compile(r"^env://[A-Za-z_][A-Za-z0-9_]*$")


class ConfigurationCapability(StrEnum):
    CAPTURE = "CAPTURE"
    APPLY = "APPLY"
    VERIFY = "VERIFY"
    RESTORE = "RESTORE"
    ROLLBACK = "ROLLBACK"
    PROVISIONAL_COMMIT = "PROVISIONAL_COMMIT"


class ConfigurationTransport(StrEnum):
    SSH_CLI = "SSH_CLI"
    TELNET_CLI = "TELNET_CLI"
    HTTP_API = "HTTP_API"
    NETCONF = "NETCONF"
    RESTCONF = "RESTCONF"
    VENDOR_API = "VENDOR_API"
    OTHER = "OTHER"


class ParameterValueType(StrEnum):
    STRING = "STRING"
    INTEGER = "INTEGER"
    NUMBER = "NUMBER"
    BOOLEAN = "BOOLEAN"
    ENUM = "ENUM"
    IP_ADDRESS = "IP_ADDRESS"
    CIDR = "CIDR"
    VLAN_ID = "VLAN_ID"
    INTERFACE = "INTERFACE"


class ParameterSource(StrEnum):
    OPERATOR = "OPERATOR"
    DEVICE = "DEVICE"
    TEMPLATE_DEFAULT = "TEMPLATE_DEFAULT"


class TemplateParameterDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    label: str
    value_type: ParameterValueType
    required: bool = True
    source: ParameterSource = ParameterSource.OPERATOR
    sensitive: bool = False
    default: Any | None = None
    description: str | None = None
    choices: list[str] = Field(default_factory=list)
    minimum: float | None = None
    maximum: float | None = None
    pattern: str | None = None

    @model_validator(mode="after")
    def validate_definition(self):
        if _PARAMETER_NAME.fullmatch(self.name) is None:
            raise ValueError("CONFIGURATION_PARAMETER_NAME_INVALID")
        if self.sensitive and self.default is not None:
            raise ValueError("CONFIGURATION_SENSITIVE_PARAMETER_DEFAULT_FORBIDDEN")
        if self.value_type == ParameterValueType.ENUM:
            if not self.choices:
                raise ValueError("CONFIGURATION_ENUM_PARAMETER_CHOICES_REQUIRED")
            if len(self.choices) > 200 or len(self.choices) != len(set(self.choices)):
                raise ValueError("CONFIGURATION_ENUM_PARAMETER_CHOICES_INVALID")
            if any(
                not isinstance(choice, str)
                or not choice
                or len(choice) > 512
                or "\r" in choice
                or "\n" in choice
                for choice in self.choices
            ):
                raise ValueError("CONFIGURATION_ENUM_PARAMETER_CHOICES_INVALID")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("CONFIGURATION_PARAMETER_RANGE_INVALID")
        if self.pattern is not None:
            if not self.pattern or len(self.pattern) > 500:
                raise ValueError("CONFIGURATION_PARAMETER_PATTERN_INVALID")
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError("CONFIGURATION_PARAMETER_PATTERN_INVALID") from exc
        return self


class ConfigurationFunctionDefinition(BaseModel):
    """Adapter-owned device action definition.

    execution_spec/verification_spec/rollback_spec are data only. The FTTW core
    never executes them as host shell input; only the selected registered device
    adapter may interpret them.
    """

    model_config = ConfigDict(extra="forbid")

    code: str
    name: str
    category: str = "CUSTOM"
    description: str | None = None
    parameters: list[TemplateParameterDefinition] = Field(default_factory=list)
    execution_spec: dict[str, Any] = Field(default_factory=dict)
    verification_spec: dict[str, Any] = Field(default_factory=dict)
    rollback_spec: dict[str, Any] = Field(default_factory=dict)
    required_capabilities: set[ConfigurationCapability] = Field(default_factory=set)
    default_order: int = Field(default=0, ge=0)
    enabled: bool = True
    is_destructive: bool = False

    @model_validator(mode="after")
    def validate_function(self):
        if _PARAMETER_NAME.fullmatch(self.code) is None:
            raise ValueError("CONFIGURATION_FUNCTION_CODE_INVALID")
        names = [item.name for item in self.parameters]
        if len(names) != len(set(names)):
            raise ValueError("CONFIGURATION_FUNCTION_PARAMETER_DUPLICATE")
        return self


class ConfigurationTemplateDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapter_key: str
    transport: ConfigurationTransport
    capabilities: set[ConfigurationCapability]
    parameters: list[TemplateParameterDefinition] = Field(default_factory=list)
    transport_parameters: dict[str, Any] = Field(default_factory=dict)
    functions: list[ConfigurationFunctionDefinition] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_template(self):
        if _ADAPTER_KEY.fullmatch(self.adapter_key) is None:
            raise ValueError("CONFIGURATION_ADAPTER_KEY_INVALID")
        parameter_names = [item.name for item in self.parameters]
        if len(parameter_names) != len(set(parameter_names)):
            raise ValueError("CONFIGURATION_TEMPLATE_PARAMETER_DUPLICATE")
        function_codes = [item.code for item in self.functions]
        if len(function_codes) != len(set(function_codes)):
            raise ValueError("CONFIGURATION_TEMPLATE_FUNCTION_DUPLICATE")
        unsupported = {
            capability
            for function in self.functions
            for capability in function.required_capabilities
            if capability not in self.capabilities
        }
        if unsupported:
            raise ValueError("CONFIGURATION_TEMPLATE_FUNCTION_CAPABILITY_UNDECLARED")
        return self


def validate_env_secret_reference(reference: str | None) -> str | None:
    if reference is None:
        return None
    value = reference.strip()
    if _ENV_REFERENCE.fullmatch(value) is None:
        raise ValueError("CONFIGURATION_SECRET_REFERENCE_INVALID")
    return value


@dataclass(frozen=True)
class AdapterDescriptor:
    key: str
    transport: ConfigurationTransport
    capabilities: frozenset[ConfigurationCapability]

    def __post_init__(self) -> None:
        if _ADAPTER_KEY.fullmatch(self.key) is None:
            raise ValueError("CONFIGURATION_ADAPTER_KEY_INVALID")


@dataclass(frozen=True)
class ConfigurationExecutionContext:
    device_id: str
    management_address: str
    template_version_id: str
    connection_parameters: Mapping[str, Any]


@dataclass(frozen=True)
class ConfigurationCaptureResult:
    payload: bytes
    metadata: Mapping[str, Any]
    restorable: bool


@dataclass(frozen=True)
class ConfigurationVerificationResult:
    success: bool
    summary: Mapping[str, Any]


class ConfigurationPreMutationError(RuntimeError):
    """Failure from an adapter preflight that did not mutate device configuration."""


class ConfigurationAdapter(ABC):
    """Vendor-neutral adapter boundary for Phase F.

    Implementations talk only to registered device management endpoints. They
    must never expose a generic host shell or arbitrary destination facility.
    """

    descriptor: AdapterDescriptor

    @abstractmethod
    async def validate_template(self, definition: ConfigurationTemplateDefinition) -> None:
        raise NotImplementedError

    @abstractmethod
    async def capture(self, context: ConfigurationExecutionContext) -> ConfigurationCaptureResult:
        raise NotImplementedError

    @abstractmethod
    async def validate_candidate(
        self,
        context: ConfigurationExecutionContext,
        candidate: bytes,
        function_specs: list[Mapping[str, Any]],
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    async def apply(
        self,
        context: ConfigurationExecutionContext,
        candidate: bytes,
        function_specs: list[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def verify(
        self,
        context: ConfigurationExecutionContext,
        expected: bytes | None,
        verification_specs: list[Mapping[str, Any]],
    ) -> ConfigurationVerificationResult:
        raise NotImplementedError

    async def preflight_restore(
        self,
        context: ConfigurationExecutionContext,
        snapshot: bytes,
    ) -> Mapping[str, Any]:
        """Optionally prove restore readiness without changing device configuration.

        Implementations must not alter persistent device configuration. A known
        safe preflight failure should raise ConfigurationPreMutationError.
        """
        return {}

    @abstractmethod
    async def restore(
        self,
        context: ConfigurationExecutionContext,
        snapshot: bytes,
    ) -> Mapping[str, Any]:
        raise NotImplementedError

    def validate_connection_overrides(self, overrides: Mapping[str, Any]) -> None:
        """Validate non-secret, per-device adapter connection metadata.

        Adapters must explicitly opt in to supported override keys. The core
        fails closed so an operator cannot smuggle arbitrary transport options
        or secrets through the binding JSON.
        """
        if overrides:
            raise ValueError("CONFIGURATION_CONNECTION_OVERRIDE_UNSUPPORTED")

    def sanitize_for_display(
        self,
        payload: bytes,
        transport_parameters: Mapping[str, Any],
    ) -> str:
        raise ValueError("CONFIGURATION_DISPLAY_DIFF_UNSUPPORTED")

    def normalize_for_diff(
        self,
        text: str,
        transport_parameters: Mapping[str, Any],
    ) -> str:
        raise ValueError("CONFIGURATION_DISPLAY_DIFF_UNSUPPORTED")


class ConfigurationAdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ConfigurationAdapter] = {}

    def register(self, adapter: ConfigurationAdapter) -> None:
        key = adapter.descriptor.key
        if key in self._adapters:
            raise ValueError("CONFIGURATION_ADAPTER_ALREADY_REGISTERED")
        self._adapters[key] = adapter

    def get(self, key: str) -> ConfigurationAdapter:
        try:
            return self._adapters[key]
        except KeyError as exc:
            raise KeyError("CONFIGURATION_ADAPTER_NOT_REGISTERED") from exc

    def descriptors(self) -> tuple[AdapterDescriptor, ...]:
        return tuple(self._adapters[key].descriptor for key in sorted(self._adapters))

    def validate_capabilities(
        self,
        key: str,
        required: set[ConfigurationCapability] | frozenset[ConfigurationCapability],
    ) -> None:
        available = self.get(key).descriptor.capabilities
        missing = set(required) - set(available)
        if missing:
            raise ValueError("CONFIGURATION_ADAPTER_CAPABILITY_UNAVAILABLE")
