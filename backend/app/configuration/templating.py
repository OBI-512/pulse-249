from __future__ import annotations

import difflib
from enum import Enum
import hashlib
import ipaddress
import json
import math
import re
from typing import Any, Mapping

from app.configuration.contracts import (
    ConfigurationFunctionDefinition,
    ConfigurationTemplateDefinition,
    ParameterValueType,
    TemplateParameterDefinition,
    validate_env_secret_reference,
)


_PLACEHOLDER = re.compile(r"{{\s*([A-Za-z_][A-Za-z0-9_]*)\s*}}")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DEFAULT_SECRET_LINE = re.compile(
    r"(?i)(password|passwd|passphrase|secret|community|private[-_ ]?key|pre[-_ ]?shared|\bpsk\b|token|credential|authorization)"
)


class ConfigurationTemplateError(ValueError):
    pass


def _canonicalize(value: Any) -> Any:
    """Produce deterministic JSON-compatible data without reordering semantic lists."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, set | frozenset):
        return sorted((_canonicalize(item) for item in value), key=lambda item: str(item))
    if isinstance(value, dict):
        return {str(key): _canonicalize(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_canonicalize(item) for item in value]
    return value


def canonical_definition_json(definition: ConfigurationTemplateDefinition) -> str:
    payload = _canonicalize(definition.model_dump(mode="python"))
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def definition_sha256(definition: ConfigurationTemplateDefinition) -> str:
    return hashlib.sha256(canonical_definition_json(definition).encode("utf-8")).hexdigest()


def placeholder_names(template: str) -> set[str]:
    if not isinstance(template, str):
        raise ConfigurationTemplateError("CONFIGURATION_TEMPLATE_COMMAND_INVALID")
    return set(_PLACEHOLDER.findall(template))


def _validate_scalar(definition: TemplateParameterDefinition, value: Any) -> Any:
    if value is None:
        raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_VALUE_REQUIRED")

    t = definition.value_type
    if t == ParameterValueType.BOOLEAN:
        if isinstance(value, bool):
            normalized: Any = value
        elif isinstance(value, str) and value.strip().lower() in {"true", "false"}:
            normalized = value.strip().lower() == "true"
        else:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_BOOLEAN_INVALID")
    elif t == ParameterValueType.INTEGER:
        if isinstance(value, bool):
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_INTEGER_INVALID")
        if isinstance(value, float) and not value.is_integer():
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_INTEGER_INVALID")
        try:
            normalized = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_INTEGER_INVALID") from exc
    elif t == ParameterValueType.NUMBER:
        if isinstance(value, bool):
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_NUMBER_INVALID")
        try:
            normalized = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_NUMBER_INVALID") from exc
        if not math.isfinite(normalized):
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_NUMBER_INVALID")
    elif t == ParameterValueType.IP_ADDRESS:
        try:
            normalized = str(ipaddress.ip_address(str(value).strip()))
        except ValueError as exc:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_IP_INVALID") from exc
    elif t == ParameterValueType.CIDR:
        try:
            normalized = str(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError as exc:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_CIDR_INVALID") from exc
    elif t == ParameterValueType.VLAN_ID:
        if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_VLAN_INVALID")
        try:
            normalized = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_VLAN_INVALID") from exc
        if not 1 <= normalized <= 4094:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_VLAN_INVALID")
    else:
        normalized = str(value)
        if "\r" in normalized or "\n" in normalized or _CONTROL.search(normalized):
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_CONTROL_CHARACTER_FORBIDDEN")
        if len(normalized) > 4096:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_TOO_LONG")

    numeric = normalized if isinstance(normalized, (int, float)) and not isinstance(normalized, bool) else None
    if numeric is not None:
        if definition.minimum is not None and numeric < definition.minimum:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_BELOW_MINIMUM")
        if definition.maximum is not None and numeric > definition.maximum:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_ABOVE_MAXIMUM")

    text = str(normalized)
    if definition.value_type == ParameterValueType.ENUM and text not in definition.choices:
        raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_ENUM_INVALID")
    if definition.pattern:
        try:
            matched = re.fullmatch(definition.pattern, text)
        except re.error as exc:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_PATTERN_INVALID") from exc
        if matched is None:
            raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_PATTERN_MISMATCH")
    return normalized


def resolve_parameters(
    definitions: list[TemplateParameterDefinition],
    provided: Mapping[str, Any],
    *,
    secret_resolver=None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    known = {item.name: item for item in definitions}
    unknown = sorted(set(provided) - set(known))
    if unknown:
        raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_UNKNOWN")
    resolved: dict[str, Any] = {}
    summary: dict[str, Any] = {}
    for item in definitions:
        has_value = item.name in provided
        value = provided.get(item.name)
        if not has_value and item.default is not None:
            value = item.default
            has_value = True
        if not has_value:
            if item.required:
                raise ConfigurationTemplateError("CONFIGURATION_PARAMETER_REQUIRED")
            continue
        if item.sensitive:
            try:
                reference = validate_env_secret_reference(str(value or "").strip())
            except ValueError as exc:
                raise ConfigurationTemplateError(
                    "CONFIGURATION_SENSITIVE_PARAMETER_REFERENCE_REQUIRED"
                ) from exc
            if reference is None:
                raise ConfigurationTemplateError(
                    "CONFIGURATION_SENSITIVE_PARAMETER_REFERENCE_REQUIRED"
                )
            # The env reference is server-side execution metadata, not a secret
            # value. API serializers redact the reference before browser output.
            summary[item.name] = {"sensitive": True, "reference": reference}
            if secret_resolver is None:
                resolved[item.name] = reference
            else:
                # Secret values are resolved only inside the isolated worker, but
                # they still cross the device CLI boundary. Apply the exact same
                # type/range/pattern/control-character validation as ordinary
                # parameters so an env secret can never inject a second command.
                resolved[item.name] = _validate_scalar(
                    item, secret_resolver(reference)
                )
            continue
        normalized = _validate_scalar(item, value)
        resolved[item.name] = normalized
        summary[item.name] = normalized
    return resolved, summary


def _render(template: str, values: Mapping[str, Any], *, escape_values: bool) -> str:
    if not isinstance(template, str):
        raise ConfigurationTemplateError("CONFIGURATION_TEMPLATE_COMMAND_INVALID")
    if "\r" in template or "\n" in template or _CONTROL.search(template):
        raise ConfigurationTemplateError("CONFIGURATION_TEMPLATE_COMMAND_CONTROL_CHARACTER_FORBIDDEN")

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise ConfigurationTemplateError("CONFIGURATION_TEMPLATE_PARAMETER_UNRESOLVED")
        value = values[name]
        text = "true" if value is True else "false" if value is False else str(value)
        if "\r" in text or "\n" in text or _CONTROL.search(text):
            raise ConfigurationTemplateError("CONFIGURATION_RENDERED_VALUE_CONTROL_CHARACTER_FORBIDDEN")
        return re.escape(text) if escape_values else text

    rendered = _PLACEHOLDER.sub(replace, template)
    if "{{" in rendered or "}}" in rendered:
        raise ConfigurationTemplateError("CONFIGURATION_TEMPLATE_PLACEHOLDER_INVALID")
    if len(rendered.encode("utf-8")) > 65536:
        raise ConfigurationTemplateError("CONFIGURATION_RENDERED_COMMAND_TOO_LARGE")
    return rendered


def render_text(template: str, values: Mapping[str, Any]) -> str:
    """Render a device command. Values remain literal device-CLI text."""
    return _render(template, values, escape_values=False)


def render_pattern(template: str, values: Mapping[str, Any]) -> str:
    """Render a regex while treating substituted parameter values literally."""
    return _render(template, values, escape_values=True)


def function_from_row(row) -> ConfigurationFunctionDefinition:
    params = [
        TemplateParameterDefinition.model_validate(item)
        for item in (row.parameter_schema or {}).get("parameters", [])
    ]
    return ConfigurationFunctionDefinition(
        code=row.code,
        name=row.name,
        category=row.category,
        description=row.description,
        parameters=params,
        execution_spec=row.execution_spec or {},
        verification_spec=row.verification_spec or {},
        rollback_spec=row.rollback_spec or {},
        required_capabilities=set(row.required_capabilities or []),
        default_order=row.default_order,
        enabled=row.enabled,
        is_destructive=row.is_destructive,
    )


def sanitize_text(text: str, *, extra_patterns: list[str] | None = None) -> str:
    compiled: list[re.Pattern[str]] = [_DEFAULT_SECRET_LINE]
    for raw in extra_patterns or []:
        if not isinstance(raw, str) or len(raw) > 500:
            raise ConfigurationTemplateError("CONFIGURATION_REDACTION_PATTERN_INVALID")
        try:
            compiled.append(re.compile(raw, re.IGNORECASE))
        except re.error as exc:
            raise ConfigurationTemplateError("CONFIGURATION_REDACTION_PATTERN_INVALID") from exc
    lines: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if any(pattern.search(line) for pattern in compiled):
            lines.append("[REDACTED CONFIGURATION LINE]")
        else:
            lines.append(line)
    return "\n".join(lines)


def normalize_text(text: str, *, ignore_patterns: list[str] | None = None) -> str:
    patterns: list[re.Pattern[str]] = []
    for raw in ignore_patterns or []:
        if not isinstance(raw, str) or len(raw) > 500:
            raise ConfigurationTemplateError("CONFIGURATION_IGNORE_PATTERN_INVALID")
        try:
            patterns.append(re.compile(raw))
        except re.error as exc:
            raise ConfigurationTemplateError("CONFIGURATION_IGNORE_PATTERN_INVALID") from exc
    output: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        cleaned = line.rstrip()
        if any(pattern.search(cleaned) for pattern in patterns):
            continue
        output.append(cleaned)
    while output and output[-1] == "":
        output.pop()
    return "\n".join(output) + ("\n" if output else "")


def unified_diff_text(
    before: str,
    after: str,
    *,
    from_name: str,
    to_name: str,
    max_lines: int = 4000,
) -> str:
    lines = list(
        difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile=from_name,
            tofile=to_name,
            lineterm="",
        )
    )
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... diff truncated after {max_lines} lines ..."]
    return "\n".join(lines)
