from __future__ import annotations

import asyncio
import hashlib
from pathlib import PurePosixPath
import re
from dataclasses import dataclass
from typing import Any, Mapping

from app.configuration.contracts import (
    AdapterDescriptor,
    ConfigurationAdapter,
    ConfigurationCapability,
    ConfigurationCaptureResult,
    ConfigurationExecutionContext,
    ConfigurationFunctionDefinition,
    ConfigurationTemplateDefinition,
    ConfigurationTransport,
    ConfigurationVerificationResult,
    ParameterSource,
    ParameterValueType,
)
from app.configuration.templating import (
    ConfigurationTemplateError,
    normalize_text,
    placeholder_names,
    render_pattern,
    render_text,
    sanitize_text,
)
from app.remote_gateway.ssh_transport import (
    download_file_scp,
    read_pty,
    ssh_compatibility_options,
    start_ssh,
    upload_file_scp,
    write_pty,
)
from app.settings import settings


class ConfigurationSSHError(RuntimeError):
    pass


_REMOTE_FILE_PATH = re.compile(r"^/[A-Za-z0-9._/-]{1,511}$")
_CHECKSUM_ALGORITHMS = {"MD5", "SHA256"}


_SENSITIVE_COMMAND = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|community|pre[-_ ]?shared|psk|token|private[-_ ]?key|credential)\b"
)


@dataclass
class _Session:
    process: Any
    prompt_pattern: re.Pattern[str]
    command_timeout: int
    max_output_bytes: int

    async def _read_until_prompt(self, timeout: int | None = None) -> str:
        deadline = asyncio.get_running_loop().time() + float(timeout or self.command_timeout)
        raw = bytearray()
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise ConfigurationSSHError("CONFIGURATION_SSH_PROMPT_TIMEOUT")
            chunk = await asyncio.wait_for(read_pty(self.process.master_fd, 4096), timeout=remaining)
            if not chunk:
                if self.process.process.poll() is not None:
                    raise ConfigurationSSHError("CONFIGURATION_SSH_SESSION_ENDED")
                await asyncio.sleep(0.02)
                continue
            raw.extend(chunk)
            if len(raw) > self.max_output_bytes:
                raise ConfigurationSSHError("CONFIGURATION_SSH_OUTPUT_LIMIT_EXCEEDED")
            text = raw.decode("utf-8", "replace")
            if self.prompt_pattern.search(text[-8192:]):
                return text

    async def ready(self) -> str:
        return await self._read_until_prompt()

    async def command(
        self,
        command: str,
        *,
        expect: str | None = None,
        timeout: int | None = None,
    ) -> str:
        await write_pty(self.process.master_fd, command + "\n")
        if expect:
            try:
                pattern = re.compile(expect, re.MULTILINE)
            except re.error as exc:
                raise ConfigurationSSHError("CONFIGURATION_SSH_EXPECT_PATTERN_INVALID") from exc
            deadline = asyncio.get_running_loop().time() + float(timeout or self.command_timeout)
            raw = bytearray()
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise ConfigurationSSHError("CONFIGURATION_SSH_EXPECT_TIMEOUT")
                chunk = await asyncio.wait_for(read_pty(self.process.master_fd, 4096), timeout=remaining)
                if not chunk:
                    if self.process.process.poll() is not None:
                        raise ConfigurationSSHError("CONFIGURATION_SSH_SESSION_ENDED")
                    await asyncio.sleep(0.02)
                    continue
                raw.extend(chunk)
                if len(raw) > self.max_output_bytes:
                    raise ConfigurationSSHError("CONFIGURATION_SSH_OUTPUT_LIMIT_EXCEEDED")
                text = raw.decode("utf-8", "replace")
                if pattern.search(text[-8192:]):
                    return text
        return await self._read_until_prompt(timeout)

    def close(self) -> None:
        self.process.close()


def _validate_timeout(value: Any, code: str) -> int:
    if isinstance(value, bool):
        raise ConfigurationTemplateError(code)
    try:
        timeout = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConfigurationTemplateError(code) from exc
    if not 1 <= timeout <= 300:
        raise ConfigurationTemplateError(code)
    return timeout


def _as_command_entries(
    spec: Mapping[str, Any],
    *,
    field: str = "commands",
) -> list[dict[str, Any]]:
    raw = spec.get(field, [])
    if not isinstance(raw, list) or not raw or len(raw) > 500:
        raise ConfigurationTemplateError("CONFIGURATION_SSH_COMMANDS_REQUIRED")
    entries: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, str):
            entries.append({"send": item})
        elif isinstance(item, dict) and isinstance(item.get("send"), str):
            unknown = set(item) - {
                "send",
                "expect",
                "timeout_seconds",
                "reconnect_after_command",
                "reconnect_timeout_seconds",
                "reconnect_delay_seconds",
            }
            if unknown:
                raise ConfigurationTemplateError("CONFIGURATION_SSH_COMMAND_FIELD_UNSUPPORTED")
            entry = dict(item)
            if "expect" in entry and entry["expect"] is not None:
                if not isinstance(entry["expect"], str) or not entry["expect"]:
                    raise ConfigurationTemplateError("CONFIGURATION_SSH_EXPECT_PATTERN_INVALID")
                _validate_pattern(entry["expect"], "CONFIGURATION_SSH_EXPECT_PATTERN_INVALID")
            if "timeout_seconds" in entry:
                entry["timeout_seconds"] = _validate_timeout(
                    entry["timeout_seconds"],
                    "CONFIGURATION_SSH_COMMAND_TIMEOUT_INVALID",
                )
            if "reconnect_after_command" in entry:
                if not isinstance(entry["reconnect_after_command"], bool):
                    raise ConfigurationTemplateError(
                        "CONFIGURATION_SSH_RECONNECT_FLAG_INVALID"
                    )
            if "reconnect_timeout_seconds" in entry:
                entry["reconnect_timeout_seconds"] = _validate_timeout(
                    entry["reconnect_timeout_seconds"],
                    "CONFIGURATION_SSH_RECONNECT_TIMEOUT_INVALID",
                )
            if "reconnect_delay_seconds" in entry:
                entry["reconnect_delay_seconds"] = _validate_timeout(
                    entry["reconnect_delay_seconds"],
                    "CONFIGURATION_SSH_RECONNECT_DELAY_INVALID",
                )
            if entry.get("reconnect_after_command") is True:
                if "reconnect_timeout_seconds" not in entry:
                    raise ConfigurationTemplateError(
                        "CONFIGURATION_SSH_RECONNECT_TIMEOUT_REQUIRED"
                    )
                if (
                    "reconnect_delay_seconds" in entry
                    and entry["reconnect_delay_seconds"]
                    >= entry["reconnect_timeout_seconds"]
                ):
                    raise ConfigurationTemplateError(
                        "CONFIGURATION_SSH_RECONNECT_DELAY_INVALID"
                    )
            elif (
                "reconnect_timeout_seconds" in entry
                or "reconnect_delay_seconds" in entry
            ):
                raise ConfigurationTemplateError(
                    "CONFIGURATION_SSH_RECONNECT_TIMEOUT_WITHOUT_FLAG"
                )
            entries.append(entry)
        else:
            raise ConfigurationTemplateError("CONFIGURATION_SSH_COMMAND_INVALID")
    return entries


def _validate_command_spec(
    spec: Mapping[str, Any],
    *,
    allowed_extra: set[str] | None = None,
    allow_reconnect: bool = False,
) -> list[dict[str, Any]]:
    if not isinstance(spec, Mapping):
        raise ConfigurationTemplateError("CONFIGURATION_SSH_SPEC_INVALID")
    allowed = {"commands"} | set(allowed_extra or set())
    if set(spec) - allowed:
        raise ConfigurationTemplateError("CONFIGURATION_SSH_SPEC_FIELD_UNSUPPORTED")
    entries = _as_command_entries(spec)
    if not allow_reconnect and any(
        "reconnect_after_command" in entry
        or "reconnect_timeout_seconds" in entry
        or "reconnect_delay_seconds" in entry
        for entry in entries
    ):
        raise ConfigurationTemplateError("CONFIGURATION_SSH_RECONNECT_NOT_ALLOWED")
    return entries


def _validate_pattern(value: str, code: str) -> re.Pattern[str]:
    if not isinstance(value, str) or not value or len(value) > 500:
        raise ConfigurationTemplateError(code)
    try:
        return re.compile(value, re.MULTILINE)
    except re.error as exc:
        raise ConfigurationTemplateError(code) from exc


def _validate_pattern_list(value: Any, code: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 100:
        raise ConfigurationTemplateError(code)
    result: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise ConfigurationTemplateError(code)
        _validate_pattern(raw, code)
        result.append(raw)
    return result


def _validate_string_list(value: Any, code: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 500:
        raise ConfigurationTemplateError(code)
    output: list[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or "\r" in item
            or "\n" in item
            or len(item.encode("utf-8")) > 65536
        ):
            raise ConfigurationTemplateError(code)
        output.append(item)
    return output


def _validate_remote_file_path(
    value: Any,
    code: str = "CONFIGURATION_RESTORE_UPLOAD_PATH_INVALID",
) -> str:
    if not isinstance(value, str) or _REMOTE_FILE_PATH.fullmatch(value) is None:
        raise ConfigurationTemplateError(code)
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or path.name in {"", ".", ".."}
        or ".." in path.parts
        or value.endswith("/")
        or "//" in value
        or "/./" in value
    ):
        raise ConfigurationTemplateError(code)
    return value


def _validate_checksum_algorithm(value: Any) -> str:
    algorithm = str(value or "").upper()
    if algorithm not in _CHECKSUM_ALGORITHMS:
        raise ConfigurationTemplateError("CONFIGURATION_RESTORE_CHECKSUM_ALGORITHM_INVALID")
    return algorithm


def _payload_checksum(payload: bytes, algorithm: str) -> str:
    if algorithm == "SHA256":
        return hashlib.sha256(payload).hexdigest()
    if algorithm == "MD5":
        return hashlib.md5(payload, usedforsecurity=False).hexdigest()
    raise ConfigurationSSHError("CONFIGURATION_RESTORE_CHECKSUM_ALGORITHM_INVALID")


def _checksum_command(path: str, algorithm: str) -> str:
    binary = "sha256sum" if algorithm == "SHA256" else "md5sum"
    return f"{binary} {path}"


def _assert_checksum_output(output: str, expected: str) -> None:
    if re.search(rf"(?i)(?:^|\s){re.escape(expected)}(?:\s|$)", output) is None:
        raise ConfigurationSSHError("CONFIGURATION_RESTORE_UPLOAD_CHECKSUM_MISMATCH")


def _validate_restore_command_spec(
    spec: Any,
    *,
    field_code: str,
    allowed_placeholders: set[str] | None = None,
    allow_reconnect: bool = False,
) -> dict[str, Any]:
    if not isinstance(spec, Mapping):
        raise ConfigurationTemplateError(field_code)
    _validate_command_spec(spec, allow_reconnect=allow_reconnect)
    used = _spec_placeholders(spec)
    if used - set(allowed_placeholders or set()):
        raise ConfigurationTemplateError("CONFIGURATION_RESTORE_PARAMETER_FORBIDDEN")
    for entry in _as_command_entries(spec):
        if _SENSITIVE_COMMAND.search(entry["send"]):
            raise ConfigurationTemplateError("CONFIGURATION_SSH_LITERAL_SECRET_FORBIDDEN")
    return dict(spec)


def _extract_capture_payload(raw: str, spec: Mapping[str, Any]) -> str:
    """Extract the template-declared device configuration body.

    A restorable generic SSH capture must declare explicit start/end boundaries;
    FTTW never guesses whether command echoes, banners or prompts are safe to
    replay as device configuration.
    """

    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")

    start_pattern = spec.get("start_pattern")
    if start_pattern:
        start_re = _validate_pattern(
            str(start_pattern), "CONFIGURATION_CAPTURE_START_PATTERN_INVALID"
        )
        for index, line in enumerate(lines):
            if start_re.search(line):
                lines = lines[
                    index + (0 if spec.get("include_start_line") is True else 1) :
                ]
                break
        else:
            raise ConfigurationSSHError("CONFIGURATION_CAPTURE_START_PATTERN_NOT_FOUND")

    end_pattern = spec.get("end_pattern")
    if end_pattern:
        end_re = _validate_pattern(
            str(end_pattern), "CONFIGURATION_CAPTURE_END_PATTERN_INVALID"
        )
        for index, line in enumerate(lines):
            if end_re.search(line):
                lines = lines[: index + (1 if spec.get("include_end_line") is True else 0)]
                break
        else:
            raise ConfigurationSSHError("CONFIGURATION_CAPTURE_END_PATTERN_NOT_FOUND")

    excludes = [
        _validate_pattern(raw_pattern, "CONFIGURATION_CAPTURE_EXCLUDE_PATTERN_INVALID")
        for raw_pattern in _validate_pattern_list(
            spec.get("exclude_patterns"), "CONFIGURATION_CAPTURE_EXCLUDE_PATTERN_INVALID"
        )
    ]
    if excludes:
        lines = [
            line
            for line in lines
            if not any(pattern.search(line) for pattern in excludes)
        ]

    return normalize_text(
        "\n".join(lines),
        ignore_patterns=list(spec.get("ignore_patterns") or []),
    )


def _spec_placeholders(spec: Mapping[str, Any], *, include_success: bool = False) -> set[str]:
    found: set[str] = set()
    for entry in _as_command_entries(spec):
        found.update(placeholder_names(entry["send"]))
        if entry.get("expect"):
            found.update(placeholder_names(str(entry["expect"])))
    if include_success and spec.get("success_pattern"):
        found.update(placeholder_names(str(spec["success_pattern"])))
    return found


def _assert_no_literal_secret_command(
    command: str,
    *,
    parameters: Mapping[str, Any],
) -> None:
    if _SENSITIVE_COMMAND.search(command) is None:
        return
    placeholders = placeholder_names(command)
    if not any(
        name in parameters and getattr(parameters[name], "sensitive", False)
        for name in placeholders
    ):
        raise ConfigurationTemplateError(
            "CONFIGURATION_SSH_LITERAL_SECRET_FORBIDDEN"
        )


def _validate_function_placeholders(function: ConfigurationFunctionDefinition) -> None:
    known = {parameter.name: parameter for parameter in function.parameters}
    used: set[str] = set()
    if function.execution_spec:
        used.update(_spec_placeholders(function.execution_spec))
    if function.verification_spec:
        used.update(_spec_placeholders(function.verification_spec, include_success=True))
    if function.rollback_spec:
        used.update(_spec_placeholders(function.rollback_spec))
    if used - set(known):
        raise ConfigurationTemplateError("CONFIGURATION_TEMPLATE_PARAMETER_UNDECLARED")

    for spec in (
        function.execution_spec,
        function.verification_spec,
        function.rollback_spec,
    ):
        if spec:
            for entry in _as_command_entries(spec):
                _assert_no_literal_secret_command(entry["send"], parameters=known)

    for name in used:
        parameter = known[name]
        if parameter.source == ParameterSource.DEVICE:
            raise ConfigurationTemplateError("CONFIGURATION_DEVICE_PARAMETER_SOURCE_UNSUPPORTED")
        if (
            parameter.source == ParameterSource.OPERATOR
            and not parameter.sensitive
            and parameter.value_type in {ParameterValueType.STRING, ParameterValueType.INTERFACE}
            and not parameter.pattern
        ):
            # A generic CLI adapter cannot know which punctuation a vendor treats
            # as a command delimiter. Templates must constrain free-form operator
            # text explicitly before it can be interpolated into device commands.
            raise ConfigurationTemplateError(
                "CONFIGURATION_SSH_FREEFORM_PARAMETER_PATTERN_REQUIRED"
            )


class GenericSSHCLIAdapter(ConfigurationAdapter):
    descriptor = AdapterDescriptor(
        key="generic.ssh_cli",
        transport=ConfigurationTransport.SSH_CLI,
        capabilities=frozenset(
            {
                ConfigurationCapability.CAPTURE,
                ConfigurationCapability.APPLY,
                ConfigurationCapability.VERIFY,
                ConfigurationCapability.RESTORE,
                ConfigurationCapability.ROLLBACK,
            }
        ),
    )

    _TRANSPORT_KEYS = {
        "prompt_pattern",
        "command_timeout_seconds",
        "capture",
        "restore",
        "allow_display_diff",
        "display_redaction_patterns",
        "diff_ignore_patterns",
    }
    _CAPTURE_KEYS = {
        "mode",
        "commands",
        "start_pattern",
        "end_pattern",
        "exclude_patterns",
        "ignore_patterns",
        "restorable",
        "include_start_line",
        "include_end_line",
        "transfer_protocol",
        "remote_path",
    }
    _RESTORE_KEYS = {
        "mode",
        "prefix_commands",
        "suffix_commands",
        "transfer_protocol",
        "upload_path",
        "checksum_algorithm",
        "activation",
        "cleanup",
    }
    _CONNECTION_OVERRIDE_KEYS = {"port", "host_key_fingerprint", "compatibility_profile"}

    def validate_connection_overrides(self, overrides: Mapping[str, Any]) -> None:
        values = dict(overrides or {})
        if set(values) - self._CONNECTION_OVERRIDE_KEYS:
            raise ValueError("CONFIGURATION_CONNECTION_OVERRIDE_UNSUPPORTED")
        if "port" in values:
            if isinstance(values["port"], bool):
                raise ValueError("CONFIGURATION_SSH_PORT_INVALID")
            try:
                port = int(values["port"])
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError("CONFIGURATION_SSH_PORT_INVALID") from exc
            if not 1 <= port <= 65535:
                raise ValueError("CONFIGURATION_SSH_PORT_INVALID")
        if "host_key_fingerprint" in values:
            fingerprint = str(values["host_key_fingerprint"] or "").strip()
            if not fingerprint.startswith("SHA256:") or len(fingerprint) > 160:
                raise ValueError("CONFIGURATION_HOST_KEY_FINGERPRINT_INVALID")
        if "compatibility_profile" in values:
            try:
                ssh_compatibility_options(str(values["compatibility_profile"]))
            except Exception as exc:
                raise ValueError("CONFIGURATION_SSH_COMPATIBILITY_PROFILE_INVALID") from exc

    async def validate_template(self, definition: ConfigurationTemplateDefinition) -> None:
        if definition.transport != ConfigurationTransport.SSH_CLI:
            raise ConfigurationTemplateError("CONFIGURATION_SSH_TRANSPORT_REQUIRED")
        params = definition.transport_parameters or {}
        if set(params) - self._TRANSPORT_KEYS:
            raise ConfigurationTemplateError("CONFIGURATION_SSH_TRANSPORT_FIELD_UNSUPPORTED")

        _validate_pattern(
            str(params.get("prompt_pattern") or r"[>#]\s*$"),
            "CONFIGURATION_SSH_PROMPT_PATTERN_INVALID",
        )
        if "command_timeout_seconds" in params:
            _validate_timeout(
                params["command_timeout_seconds"],
                "CONFIGURATION_SSH_COMMAND_TIMEOUT_INVALID",
            )
        if "allow_display_diff" in params and not isinstance(params["allow_display_diff"], bool):
            raise ConfigurationTemplateError("CONFIGURATION_DISPLAY_DIFF_FLAG_INVALID")

        capture = params.get("capture")
        if capture is not None:
            if not isinstance(capture, dict) or set(capture) - self._CAPTURE_KEYS:
                raise ConfigurationTemplateError("CONFIGURATION_CAPTURE_SPEC_INVALID")
            mode = str(capture.get("mode") or "COMMAND_OUTPUT").upper()
            for flag in ("restorable", "include_start_line", "include_end_line"):
                if flag in capture and not isinstance(capture[flag], bool):
                    raise ConfigurationTemplateError("CONFIGURATION_CAPTURE_FLAG_INVALID")
            if mode == "COMMAND_OUTPUT":
                if "transfer_protocol" in capture or "remote_path" in capture:
                    raise ConfigurationTemplateError("CONFIGURATION_CAPTURE_MODE_FIELD_CONFLICT")
                _validate_command_spec(capture, allowed_extra=self._CAPTURE_KEYS - {"commands"})
                if _spec_placeholders(capture):
                    raise ConfigurationTemplateError("CONFIGURATION_CAPTURE_PARAMETER_FORBIDDEN")
                for key, code in (
                    ("start_pattern", "CONFIGURATION_CAPTURE_START_PATTERN_INVALID"),
                    ("end_pattern", "CONFIGURATION_CAPTURE_END_PATTERN_INVALID"),
                ):
                    if capture.get(key):
                        _validate_pattern(str(capture[key]), code)
                _validate_pattern_list(
                    capture.get("exclude_patterns"),
                    "CONFIGURATION_CAPTURE_EXCLUDE_PATTERN_INVALID",
                )
                _validate_pattern_list(
                    capture.get("ignore_patterns"),
                    "CONFIGURATION_IGNORE_PATTERN_INVALID",
                )
                if capture.get("restorable") is True and (
                    not capture.get("start_pattern") or not capture.get("end_pattern")
                ):
                    raise ConfigurationTemplateError(
                        "CONFIGURATION_RESTORABLE_CAPTURE_BOUNDARIES_REQUIRED"
                    )
            elif mode == "FILE_DOWNLOAD":
                forbidden = {
                    "commands",
                    "start_pattern",
                    "end_pattern",
                    "exclude_patterns",
                    "ignore_patterns",
                    "include_start_line",
                    "include_end_line",
                }
                if any(key in capture for key in forbidden):
                    raise ConfigurationTemplateError("CONFIGURATION_CAPTURE_MODE_FIELD_CONFLICT")
                if str(capture.get("transfer_protocol") or "").upper() != "SCP_LEGACY":
                    raise ConfigurationTemplateError("CONFIGURATION_CAPTURE_TRANSFER_PROTOCOL_INVALID")
                _validate_remote_file_path(
                    capture.get("remote_path"),
                    "CONFIGURATION_CAPTURE_REMOTE_PATH_INVALID",
                )
            else:
                raise ConfigurationTemplateError("CONFIGURATION_CAPTURE_MODE_UNSUPPORTED")

        restore = params.get("restore")
        if restore is not None:
            if not isinstance(restore, dict) or set(restore) - self._RESTORE_KEYS:
                raise ConfigurationTemplateError("CONFIGURATION_RESTORE_SPEC_INVALID")
            mode = str(restore.get("mode") or "COMMAND_STREAM").upper()
            if mode == "COMMAND_STREAM":
                forbidden = {
                    "transfer_protocol",
                    "upload_path",
                    "checksum_algorithm",
                    "activation",
                    "cleanup",
                }
                if any(key in restore for key in forbidden):
                    raise ConfigurationTemplateError("CONFIGURATION_RESTORE_MODE_FIELD_CONFLICT")
                prefix = _validate_string_list(
                    restore.get("prefix_commands"), "CONFIGURATION_RESTORE_COMMAND_INVALID"
                )
                suffix = _validate_string_list(
                    restore.get("suffix_commands"), "CONFIGURATION_RESTORE_COMMAND_INVALID"
                )
                if any(placeholder_names(item) for item in [*prefix, *suffix]):
                    raise ConfigurationTemplateError("CONFIGURATION_RESTORE_PARAMETER_FORBIDDEN")
                if any(_SENSITIVE_COMMAND.search(item) for item in [*prefix, *suffix]):
                    raise ConfigurationTemplateError("CONFIGURATION_SSH_LITERAL_SECRET_FORBIDDEN")
            elif mode == "FILE_UPLOAD":
                if "prefix_commands" in restore or "suffix_commands" in restore:
                    raise ConfigurationTemplateError("CONFIGURATION_RESTORE_MODE_FIELD_CONFLICT")
                if str(restore.get("transfer_protocol") or "").upper() != "SCP_LEGACY":
                    raise ConfigurationTemplateError("CONFIGURATION_RESTORE_TRANSFER_PROTOCOL_INVALID")
                _validate_remote_file_path(restore.get("upload_path"))
                _validate_checksum_algorithm(restore.get("checksum_algorithm"))
                _validate_restore_command_spec(
                    restore.get("activation"),
                    field_code="CONFIGURATION_RESTORE_ACTIVATION_REQUIRED",
                    allowed_placeholders={"upload_path"},
                    allow_reconnect=True,
                )
                _validate_restore_command_spec(
                    restore.get("cleanup"),
                    field_code="CONFIGURATION_RESTORE_CLEANUP_REQUIRED",
                    allowed_placeholders={"upload_path"},
                )
            else:
                raise ConfigurationTemplateError("CONFIGURATION_RESTORE_MODE_UNSUPPORTED")

        for function in definition.functions:
            if function.execution_spec:
                _validate_command_spec(function.execution_spec, allow_reconnect=True)
            if function.verification_spec:
                _validate_command_spec(
                    function.verification_spec,
                    allowed_extra={"success_pattern"},
                )
                success_pattern = function.verification_spec.get("success_pattern")
                if (
                    not isinstance(success_pattern, str)
                    or not success_pattern
                    or len(success_pattern) > 500
                ):
                    raise ConfigurationTemplateError(
                        "CONFIGURATION_VERIFY_SUCCESS_PATTERN_REQUIRED"
                    )
                # Compile the static template as-is after replacing placeholders
                # with a safe literal token so malformed regexes fail at publish.
                probe_values = {
                    name: "FTTW_VALUE" for name in placeholder_names(success_pattern)
                }
                _validate_pattern(
                    render_pattern(success_pattern, probe_values),
                    "CONFIGURATION_VERIFY_PATTERN_INVALID",
                )
            if function.rollback_spec:
                _validate_command_spec(function.rollback_spec)
            if ConfigurationCapability.APPLY in function.required_capabilities:
                if not function.execution_spec or not function.verification_spec:
                    raise ConfigurationTemplateError(
                        "CONFIGURATION_FUNCTION_EXECUTE_VERIFY_REQUIRED"
                    )
            _validate_function_placeholders(function)

        if ConfigurationCapability.CAPTURE in definition.capabilities and not isinstance(capture, dict):
            raise ConfigurationTemplateError("CONFIGURATION_CAPTURE_SPEC_REQUIRED")
        if ConfigurationCapability.RESTORE in definition.capabilities and not isinstance(restore, dict):
            raise ConfigurationTemplateError("CONFIGURATION_RESTORE_SPEC_REQUIRED")
        if ConfigurationCapability.APPLY in definition.capabilities:
            required = {
                ConfigurationCapability.CAPTURE,
                ConfigurationCapability.VERIFY,
                ConfigurationCapability.RESTORE,
                ConfigurationCapability.ROLLBACK,
            }
            if not required.issubset(definition.capabilities):
                raise ConfigurationTemplateError(
                    "CONFIGURATION_GUARDED_APPLY_CAPABILITIES_REQUIRED"
                )
            if not isinstance(capture, dict) or capture.get("restorable") is not True:
                raise ConfigurationTemplateError(
                    "CONFIGURATION_GUARDED_APPLY_RESTORABLE_CAPTURE_REQUIRED"
                )

        if params.get("allow_display_diff") is True and not params.get(
            "display_redaction_patterns"
        ):
            raise ConfigurationTemplateError(
                "CONFIGURATION_DISPLAY_REDACTION_PATTERNS_REQUIRED"
            )
        _validate_pattern_list(
            params.get("display_redaction_patterns"),
            "CONFIGURATION_REDACTION_PATTERN_INVALID",
        )
        _validate_pattern_list(
            params.get("diff_ignore_patterns"),
            "CONFIGURATION_IGNORE_PATTERN_INVALID",
        )

    def _connection(self, context: ConfigurationExecutionContext) -> dict[str, Any]:
        params = dict(context.connection_parameters)
        username = params.get("username")
        password = params.get("password")
        private_key = params.get("private_key")
        fingerprint = params.get("host_key_fingerprint")
        trusted_host_key_line = params.get("trusted_host_key_line")
        if not username or not fingerprint or not (password or private_key):
            raise ConfigurationSSHError("CONFIGURATION_SSH_CREDENTIALS_INCOMPLETE")
        if trusted_host_key_line is not None:
            if not isinstance(trusted_host_key_line, str):
                raise ConfigurationSSHError("CONFIGURATION_SSH_TRUSTED_HOST_KEY_INVALID")
            trusted_host_key_line = trusted_host_key_line.strip()
            if not trusted_host_key_line or len(trusted_host_key_line) > 16384:
                raise ConfigurationSSHError("CONFIGURATION_SSH_TRUSTED_HOST_KEY_INVALID")
        try:
            port = int(params.get("port") or 22)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ConfigurationSSHError("CONFIGURATION_SSH_PORT_INVALID") from exc
        if not 1 <= port <= 65535:
            raise ConfigurationSSHError("CONFIGURATION_SSH_PORT_INVALID")
        compatibility = str(params.get("compatibility_profile") or "MODERN")
        try:
            ssh_compatibility_options(compatibility)
        except Exception as exc:
            raise ConfigurationSSHError(
                "CONFIGURATION_SSH_COMPATIBILITY_PROFILE_INVALID"
            ) from exc
        return {
            "host": context.management_address,
            "port": port,
            "username": str(username),
            "password": str(password) if password else None,
            "private_key": str(private_key) if private_key else None,
            "expected_fingerprint": str(fingerprint),
            "compatibility_profile": compatibility,
            "trusted_host_key_line": trusted_host_key_line,
        }

    async def _session(self, context: ConfigurationExecutionContext) -> _Session:
        params = dict(context.connection_parameters)
        prompt = _validate_pattern(
            str(params.get("prompt_pattern") or r"[>#]\s*$"),
            "CONFIGURATION_SSH_PROMPT_PATTERN_INVALID",
        )
        timeout = _validate_timeout(
            params.get("command_timeout_seconds")
            or settings.configuration_command_timeout_seconds,
            "CONFIGURATION_SSH_COMMAND_TIMEOUT_INVALID",
        )
        process = await start_ssh(**self._connection(context))
        session = _Session(
            process=process,
            prompt_pattern=prompt,
            command_timeout=timeout,
            max_output_bytes=max(
                65536,
                min(int(settings.configuration_session_max_output_bytes), 16777216),
            ),
        )
        await session.ready()
        return session

    async def _wait_for_reconnect(
        self,
        context: ConfigurationExecutionContext,
        timeout_seconds: int,
    ) -> _Session:
        deadline = asyncio.get_running_loop().time() + float(timeout_seconds)
        last_error: BaseException | None = None
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise ConfigurationSSHError(
                    "CONFIGURATION_SSH_RECONNECT_TIMEOUT"
                ) from last_error
            try:
                return await asyncio.wait_for(
                    self._session(context),
                    timeout=remaining,
                )
            except Exception as exc:
                last_error = exc
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise ConfigurationSSHError(
                        "CONFIGURATION_SSH_RECONNECT_TIMEOUT"
                    ) from last_error
                await asyncio.sleep(min(1.0, remaining))

    async def _run_spec(
        self,
        context: ConfigurationExecutionContext,
        spec: Mapping[str, Any],
        values: Mapping[str, Any],
    ) -> str:
        entries = _as_command_entries(spec)
        session = await self._session(context)
        output: list[str] = []
        expected_disconnect_codes = {
            "CONFIGURATION_SSH_SESSION_ENDED",
            "CONFIGURATION_SSH_PROMPT_TIMEOUT",
            "CONFIGURATION_SSH_EXPECT_TIMEOUT",
        }
        try:
            for entry in entries:
                command = render_text(entry["send"], values)
                expect = entry.get("expect")
                if expect is not None:
                    expect = render_pattern(str(expect), values)
                timeout = entry.get("timeout_seconds")
                if timeout is not None:
                    timeout = _validate_timeout(
                        timeout, "CONFIGURATION_SSH_COMMAND_TIMEOUT_INVALID"
                    )

                reconnect_after = entry.get("reconnect_after_command") is True
                reconnect_timeout = entry.get("reconnect_timeout_seconds")
                if reconnect_timeout is not None:
                    reconnect_timeout = _validate_timeout(
                        reconnect_timeout,
                        "CONFIGURATION_SSH_RECONNECT_TIMEOUT_INVALID",
                    )
                reconnect_delay = entry.get("reconnect_delay_seconds")
                if reconnect_delay is not None:
                    reconnect_delay = _validate_timeout(
                        reconnect_delay,
                        "CONFIGURATION_SSH_RECONNECT_DELAY_INVALID",
                    )

                try:
                    command_output = await session.command(
                        command,
                        expect=expect,
                        timeout=timeout,
                    )
                    output.append(command_output)
                except ConfigurationSSHError as exc:
                    if (
                        not reconnect_after
                        or str(exc) not in expected_disconnect_codes
                    ):
                        raise

                if reconnect_after:
                    # Commands such as commit/reload/restart may either drop the
                    # current management transport immediately or return a prompt
                    # before the restart actually begins. Close the old session
                    # in both cases. A template may declare a bounded minimum
                    # delay before the first reconnect probe; that delay consumes
                    # part of the declared total reconnect window.
                    session.close()
                    remaining_reconnect = int(reconnect_timeout)
                    if reconnect_delay is not None:
                        await asyncio.sleep(float(reconnect_delay))
                        remaining_reconnect -= int(reconnect_delay)
                    session = await self._wait_for_reconnect(
                        context,
                        remaining_reconnect,
                    )
        finally:
            session.close()
        return "\n".join(output)

    async def capture(self, context: ConfigurationExecutionContext) -> ConfigurationCaptureResult:
        transport = dict(
            context.connection_parameters.get("template_transport_parameters") or {}
        )
        capture = transport.get("capture") or {}
        mode = str(capture.get("mode") or "COMMAND_OUTPUT").upper()
        if mode == "FILE_DOWNLOAD":
            if str(capture.get("transfer_protocol") or "").upper() != "SCP_LEGACY":
                raise ConfigurationSSHError("CONFIGURATION_CAPTURE_TRANSFER_PROTOCOL_INVALID")
            try:
                remote_path = _validate_remote_file_path(
                    capture.get("remote_path"),
                    "CONFIGURATION_CAPTURE_REMOTE_PATH_INVALID",
                )
            except ConfigurationTemplateError as exc:
                raise ConfigurationSSHError(str(exc)) from exc
            connection = self._connection(context)
            timeout = _validate_timeout(
                dict(context.connection_parameters).get("command_timeout_seconds")
                or settings.configuration_command_timeout_seconds,
                "CONFIGURATION_SSH_COMMAND_TIMEOUT_INVALID",
            )
            payload = await download_file_scp(
                **connection,
                remote_path=remote_path,
                max_bytes=int(settings.configuration_artifact_max_bytes),
                timeout_seconds=max(30, min(timeout * 4, 1200)),
            )
            if not payload:
                raise ConfigurationSSHError("CONFIGURATION_CAPTURE_EMPTY")
            return ConfigurationCaptureResult(
                payload=payload,
                metadata={"transport": "SSH_CLI", "capture_mode": "FILE_DOWNLOAD"},
                restorable=capture.get("restorable") is True,
            )
        if mode != "COMMAND_OUTPUT":
            raise ConfigurationSSHError("CONFIGURATION_CAPTURE_MODE_UNSUPPORTED")
        raw = await self._run_spec(context, capture, {})
        payload = _extract_capture_payload(raw, capture)
        if not payload:
            raise ConfigurationSSHError("CONFIGURATION_CAPTURE_EMPTY")
        return ConfigurationCaptureResult(
            payload=payload.encode("utf-8"),
            metadata={"transport": "SSH_CLI", "capture_mode": "COMMAND_OUTPUT"},
            restorable=capture.get("restorable") is True,
        )

    async def validate_candidate(
        self,
        context: ConfigurationExecutionContext,
        candidate: bytes,
        function_specs: list[Mapping[str, Any]],
    ) -> None:
        if len(candidate) > settings.configuration_artifact_max_bytes:
            raise ConfigurationTemplateError("CONFIGURATION_CANDIDATE_TOO_LARGE")
        if not function_specs:
            raise ConfigurationTemplateError("CONFIGURATION_FUNCTIONS_REQUIRED")
        for spec in function_specs:
            if not isinstance(spec, Mapping):
                raise ConfigurationTemplateError("CONFIGURATION_FUNCTION_SPEC_INVALID")
            execution = spec.get("execution_spec") or {}
            verification = spec.get("verification_spec") or {}
            _validate_command_spec(execution, allow_reconnect=True)
            _validate_command_spec(verification, allowed_extra={"success_pattern"})
            if not verification.get("success_pattern"):
                raise ConfigurationTemplateError(
                    "CONFIGURATION_VERIFY_SUCCESS_PATTERN_REQUIRED"
                )

    async def apply(
        self,
        context: ConfigurationExecutionContext,
        candidate: bytes,
        function_specs: list[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        executed = 0
        for item in function_specs:
            spec = item.get("execution_spec") or {}
            values = item.get("parameters") or {}
            await self._run_spec(context, spec, values)
            executed += 1
        return {"executed_functions": executed}

    async def verify(
        self,
        context: ConfigurationExecutionContext,
        expected: bytes | None,
        verification_specs: list[Mapping[str, Any]],
    ) -> ConfigurationVerificationResult:
        if not verification_specs:
            return ConfigurationVerificationResult(
                success=False,
                summary={"code": "VERIFY_SPEC_REQUIRED"},
            )
        for item in verification_specs:
            spec = item.get("verification_spec") or {}
            if not spec:
                return ConfigurationVerificationResult(
                    success=False,
                    summary={"code": "VERIFY_SPEC_REQUIRED"},
                )
            values = item.get("parameters") or {}
            output = await self._run_spec(context, spec, values)
            success_pattern = spec.get("success_pattern")
            if not success_pattern:
                return ConfigurationVerificationResult(
                    success=False,
                    summary={"code": "VERIFY_PATTERN_REQUIRED"},
                )
            pattern = _validate_pattern(
                render_pattern(str(success_pattern), values),
                "CONFIGURATION_VERIFY_PATTERN_INVALID",
            )
            if pattern.search(output) is None:
                return ConfigurationVerificationResult(
                    success=False,
                    summary={"code": "VERIFY_PATTERN_MISMATCH"},
                )
        return ConfigurationVerificationResult(
            success=True,
            summary={"verified_steps": len(verification_specs)},
        )

    async def restore(
        self,
        context: ConfigurationExecutionContext,
        snapshot: bytes,
    ) -> Mapping[str, Any]:
        transport = dict(
            context.connection_parameters.get("template_transport_parameters") or {}
        )
        restore = transport.get("restore") or {}
        mode = str(restore.get("mode") or "COMMAND_STREAM").upper()
        if mode == "COMMAND_STREAM":
            try:
                text = snapshot.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise ConfigurationSSHError("CONFIGURATION_RESTORE_SNAPSHOT_ENCODING_INVALID") from exc
            lines = [line for line in text.splitlines() if line.strip()]
            if not lines:
                raise ConfigurationSSHError("CONFIGURATION_RESTORE_SNAPSHOT_EMPTY")
            prefix = _validate_string_list(
                restore.get("prefix_commands"), "CONFIGURATION_RESTORE_COMMAND_INVALID"
            )
            suffix = _validate_string_list(
                restore.get("suffix_commands"), "CONFIGURATION_RESTORE_COMMAND_INVALID"
            )
            commands = [*prefix, *lines, *suffix]
            session = await self._session(context)
            try:
                for item in commands:
                    command = str(item)
                    if "\r" in command or "\n" in command:
                        raise ConfigurationSSHError("CONFIGURATION_RESTORE_COMMAND_INVALID")
                    await session.command(command)
            finally:
                session.close()
            return {"restore_mode": "COMMAND_STREAM", "restored_commands": len(commands)}

        if mode != "FILE_UPLOAD":
            raise ConfigurationSSHError("CONFIGURATION_RESTORE_MODE_UNSUPPORTED")

        try:
            upload_path = _validate_remote_file_path(restore.get("upload_path"))
            algorithm = _validate_checksum_algorithm(restore.get("checksum_algorithm"))
            activation = _validate_restore_command_spec(
                restore.get("activation"),
                field_code="CONFIGURATION_RESTORE_ACTIVATION_REQUIRED",
                allowed_placeholders={"upload_path"},
                allow_reconnect=True,
            )
            cleanup = _validate_restore_command_spec(
                restore.get("cleanup"),
                field_code="CONFIGURATION_RESTORE_CLEANUP_REQUIRED",
                allowed_placeholders={"upload_path"},
            )
        except ConfigurationTemplateError as exc:
            raise ConfigurationSSHError(str(exc)) from exc
        if str(restore.get("transfer_protocol") or "").upper() != "SCP_LEGACY":
            raise ConfigurationSSHError("CONFIGURATION_RESTORE_TRANSFER_PROTOCOL_INVALID")
        if not snapshot:
            raise ConfigurationSSHError("CONFIGURATION_RESTORE_SNAPSHOT_EMPTY")

        connection = self._connection(context)
        timeout = _validate_timeout(
            dict(context.connection_parameters).get("command_timeout_seconds")
            or settings.configuration_command_timeout_seconds,
            "CONFIGURATION_SSH_COMMAND_TIMEOUT_INVALID",
        )
        expected_checksum = _payload_checksum(snapshot, algorithm)
        upload_attempted = False
        primary_error: Exception | None = None
        try:
            upload_attempted = True
            await upload_file_scp(
                **connection,
                remote_path=upload_path,
                payload=snapshot,
                timeout_seconds=max(30, min(timeout * 4, 1200)),
            )
            checksum_output = await self._run_spec(
                context,
                {"commands": [_checksum_command(upload_path, algorithm)]},
                {},
            )
            _assert_checksum_output(checksum_output, expected_checksum)
            await self._run_spec(
                context, activation, {"upload_path": upload_path}
            )
        except Exception as exc:
            primary_error = exc
            raise
        finally:
            if upload_attempted:
                try:
                    await self._run_spec(
                        context, cleanup, {"upload_path": upload_path}
                    )
                except Exception as cleanup_exc:
                    if primary_error is None:
                        raise ConfigurationSSHError(
                            "CONFIGURATION_RESTORE_STAGING_CLEANUP_FAILED"
                        ) from cleanup_exc
        return {
            "restore_mode": "FILE_UPLOAD",
            "transfer_protocol": "SCP_LEGACY",
            "checksum_algorithm": algorithm,
            "uploaded_bytes": len(snapshot),
        }

    def sanitize_for_display(
        self,
        payload: bytes,
        transport_parameters: Mapping[str, Any],
    ) -> str:
        text = payload.decode("utf-8", "replace")
        return sanitize_text(
            text,
            extra_patterns=list(
                transport_parameters.get("display_redaction_patterns") or []
            ),
        )

    def normalize_for_diff(
        self,
        text: str,
        transport_parameters: Mapping[str, Any],
    ) -> str:
        return normalize_text(
            text,
            ignore_patterns=list(transport_parameters.get("diff_ignore_patterns") or []),
        )


GENERIC_SSH_ADAPTER = GenericSSHCLIAdapter()
