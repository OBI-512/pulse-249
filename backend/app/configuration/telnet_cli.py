from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any, Mapping

from app.configuration.contracts import (
    AdapterDescriptor,
    ConfigurationCapability,
    ConfigurationCaptureResult,
    ConfigurationExecutionContext,
    ConfigurationTemplateDefinition,
    ConfigurationTransport,
    ConfigurationVerificationResult,
)
from app.configuration.ssh_cli import (
    ConfigurationSSHError,
    GenericSSHCLIAdapter,
    _validate_pattern,
    _validate_timeout,
)
from app.configuration.templating import ConfigurationTemplateError
from app.remote_gateway.telnet_transport import (
    TelnetConnection,
    TelnetTransportError,
    start_telnet,
)
from app.settings import settings


class ConfigurationTelnetError(ConfigurationSSHError):
    """Legacy Telnet configuration transport failure.

    Subclassing the established CLI transport error keeps Phase-F failure
    classification compatible while exposing TELNET-specific public codes.
    """


@dataclass
class _TelnetSession:
    connection: TelnetConnection
    prompt_pattern: re.Pattern[str]
    command_timeout: int
    max_output_bytes: int

    async def _read_until_prompt(self, timeout: int | None = None) -> str:
        deadline = asyncio.get_running_loop().time() + float(timeout or self.command_timeout)
        raw = bytearray()
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                # Internal generic code intentionally matches the established
                # reconnect state machine. Public adapter methods translate it.
                raise ConfigurationSSHError("CONFIGURATION_SSH_PROMPT_TIMEOUT")
            try:
                chunk = await asyncio.wait_for(self.connection.read(4096), timeout=remaining)
            except asyncio.TimeoutError as exc:
                raise ConfigurationSSHError("CONFIGURATION_SSH_PROMPT_TIMEOUT") from exc
            if not chunk:
                raise ConfigurationSSHError("CONFIGURATION_SSH_SESSION_ENDED")
            raw.extend(chunk)
            if len(raw) > self.max_output_bytes:
                raise ConfigurationSSHError("CONFIGURATION_SSH_OUTPUT_LIMIT_EXCEEDED")
            text = raw.decode("utf-8", "replace")
            if self.prompt_pattern.search(text[-8192:]):
                return text

    async def ready(self) -> str:
        initial = self.connection.initial_output.decode("utf-8", "replace")
        if initial and self.prompt_pattern.search(initial[-8192:]):
            return initial
        return initial + await self._read_until_prompt()

    async def command(
        self,
        command: str,
        *,
        expect: str | None = None,
        timeout: int | None = None,
    ) -> str:
        await self.connection.write(command.encode("utf-8", "replace") + b"\r\n")
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
                try:
                    chunk = await asyncio.wait_for(self.connection.read(4096), timeout=remaining)
                except asyncio.TimeoutError as exc:
                    raise ConfigurationSSHError("CONFIGURATION_SSH_EXPECT_TIMEOUT") from exc
                if not chunk:
                    raise ConfigurationSSHError("CONFIGURATION_SSH_SESSION_ENDED")
                raw.extend(chunk)
                if len(raw) > self.max_output_bytes:
                    raise ConfigurationSSHError("CONFIGURATION_SSH_OUTPUT_LIMIT_EXCEEDED")
                text = raw.decode("utf-8", "replace")
                if pattern.search(text[-8192:]):
                    return text
        return await self._read_until_prompt(timeout)

    def close(self) -> None:
        # GenericSSHCLIAdapter's guarded command state machine uses a
        # synchronous close hook. StreamWriter.close() is synchronous; the
        # underlying wait_closed() is not needed to release this local handle.
        if self.connection.closed:
            return
        self.connection.closed = True
        self.connection.writer.close()


def _translate_cli_error(exc: ConfigurationSSHError) -> ConfigurationTelnetError:
    code = str(exc)
    if code.startswith("CONFIGURATION_SSH_"):
        code = "CONFIGURATION_TELNET_" + code.removeprefix("CONFIGURATION_SSH_")
    return ConfigurationTelnetError(code)


def _translate_template_error(exc: ConfigurationTemplateError) -> ConfigurationTemplateError:
    code = str(exc)
    if code.startswith("CONFIGURATION_SSH_"):
        code = "CONFIGURATION_TELNET_" + code.removeprefix("CONFIGURATION_SSH_")
    return ConfigurationTemplateError(code)


class GenericTelnetCLIAdapter(GenericSSHCLIAdapter):
    """Guarded command-stream configuration over explicitly enabled Telnet.

    Telnet is plaintext. The adapter is registered so definitions can be
    authored while the installation gate is disabled, but every live session
    fails closed unless TELNET_ACCESS_ENABLED is true.
    """

    descriptor = AdapterDescriptor(
        key="generic.telnet_cli",
        transport=ConfigurationTransport.TELNET_CLI,
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

    _CONNECTION_OVERRIDE_KEYS = {"port"}

    def validate_connection_overrides(self, overrides: Mapping[str, Any]) -> None:
        values = dict(overrides or {})
        if set(values) - self._CONNECTION_OVERRIDE_KEYS:
            raise ValueError("CONFIGURATION_CONNECTION_OVERRIDE_UNSUPPORTED")
        if "port" in values:
            if isinstance(values["port"], bool):
                raise ValueError("CONFIGURATION_TELNET_PORT_INVALID")
            try:
                port = int(values["port"])
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError("CONFIGURATION_TELNET_PORT_INVALID") from exc
            if not 1 <= port <= 65535:
                raise ValueError("CONFIGURATION_TELNET_PORT_INVALID")

    async def validate_template(self, definition: ConfigurationTemplateDefinition) -> None:
        if definition.transport != ConfigurationTransport.TELNET_CLI:
            raise ConfigurationTemplateError("CONFIGURATION_TELNET_TRANSPORT_REQUIRED")
        restore = dict(definition.transport_parameters or {}).get("restore")
        if isinstance(restore, dict) and str(restore.get("mode") or "COMMAND_STREAM").upper() == "FILE_UPLOAD":
            raise ConfigurationTemplateError("CONFIGURATION_TELNET_FILE_UPLOAD_UNSUPPORTED")
        ssh_definition = definition.model_copy(update={"transport": ConfigurationTransport.SSH_CLI})
        try:
            await super().validate_template(ssh_definition)
        except ConfigurationTemplateError as exc:
            raise _translate_template_error(exc) from exc

    async def _session(self, context: ConfigurationExecutionContext) -> _TelnetSession:
        if not settings.telnet_access_enabled:
            raise ConfigurationTelnetError("CONFIGURATION_TELNET_DISABLED")
        params = dict(context.connection_parameters)
        username = params.get("username")
        password = params.get("password")
        if not username or not password:
            raise ConfigurationTelnetError("CONFIGURATION_TELNET_CREDENTIALS_INCOMPLETE")
        try:
            port = int(params.get("port") or 23)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ConfigurationTelnetError("CONFIGURATION_TELNET_PORT_INVALID") from exc
        if not 1 <= port <= 65535:
            raise ConfigurationTelnetError("CONFIGURATION_TELNET_PORT_INVALID")
        prompt = _validate_pattern(
            str(params.get("prompt_pattern") or r"[>#]\s*$"),
            "CONFIGURATION_TELNET_PROMPT_PATTERN_INVALID",
        )
        timeout = _validate_timeout(
            params.get("command_timeout_seconds") or settings.configuration_command_timeout_seconds,
            "CONFIGURATION_TELNET_COMMAND_TIMEOUT_INVALID",
        )
        try:
            connection = await start_telnet(
                host=context.management_address,
                port=port,
                username=str(username),
                password=str(password),
                timeout_seconds=timeout,
            )
        except TelnetTransportError as exc:
            code = str(exc)
            if code == "TELNET_LOGIN_FAILED":
                raise ConfigurationTelnetError("CONFIGURATION_TELNET_LOGIN_FAILED") from exc
            if code in {"TELNET_LOGIN_PROMPT_TIMEOUT", "TELNET_CONNECTION_CLOSED"}:
                raise ConfigurationTelnetError("CONFIGURATION_TELNET_PROMPT_TIMEOUT") from exc
            raise ConfigurationTelnetError("CONFIGURATION_TELNET_CONNECTION_FAILED") from exc
        session = _TelnetSession(
            connection=connection,
            prompt_pattern=prompt,
            command_timeout=timeout,
            max_output_bytes=max(
                65536,
                min(int(settings.configuration_session_max_output_bytes), 16777216),
            ),
        )
        try:
            await session.ready()
        except ConfigurationSSHError as exc:
            session.close()
            raise _translate_cli_error(exc) from exc
        return session

    async def capture(self, context: ConfigurationExecutionContext) -> ConfigurationCaptureResult:
        try:
            result = await super().capture(context)
        except ConfigurationSSHError as exc:
            raise _translate_cli_error(exc) from exc
        return ConfigurationCaptureResult(
            payload=result.payload,
            metadata={**dict(result.metadata or {}), "transport": "TELNET_CLI", "insecure_transport": True},
            restorable=result.restorable,
        )

    async def validate_candidate(
        self,
        context: ConfigurationExecutionContext,
        candidate: bytes,
        function_specs: list[Mapping[str, Any]],
    ) -> None:
        try:
            await super().validate_candidate(context, candidate, function_specs)
        except ConfigurationSSHError as exc:
            raise _translate_cli_error(exc) from exc
        except ConfigurationTemplateError as exc:
            raise _translate_template_error(exc) from exc

    async def apply(
        self,
        context: ConfigurationExecutionContext,
        candidate: bytes,
        function_specs: list[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        try:
            result = await super().apply(context, candidate, function_specs)
        except ConfigurationSSHError as exc:
            raise _translate_cli_error(exc) from exc
        return {**dict(result), "transport": "TELNET_CLI", "insecure_transport": True}

    async def verify(
        self,
        context: ConfigurationExecutionContext,
        expected: bytes | None,
        verification_specs: list[Mapping[str, Any]],
    ) -> ConfigurationVerificationResult:
        try:
            result = await super().verify(context, expected, verification_specs)
        except ConfigurationSSHError as exc:
            raise _translate_cli_error(exc) from exc
        return ConfigurationVerificationResult(
            success=result.success,
            summary={**dict(result.summary or {}), "transport": "TELNET_CLI", "insecure_transport": True},
        )

    async def restore(
        self,
        context: ConfigurationExecutionContext,
        snapshot: bytes,
    ) -> Mapping[str, Any]:
        transport = dict(context.connection_parameters.get("template_transport_parameters") or {})
        restore = transport.get("restore") or {}
        if str(restore.get("mode") or "COMMAND_STREAM").upper() != "COMMAND_STREAM":
            raise ConfigurationTelnetError("CONFIGURATION_TELNET_FILE_UPLOAD_UNSUPPORTED")
        try:
            result = await super().restore(context, snapshot)
        except ConfigurationSSHError as exc:
            raise _translate_cli_error(exc) from exc
        return {**dict(result), "transport": "TELNET_CLI", "insecure_transport": True}


GENERIC_TELNET_ADAPTER = GenericTelnetCLIAdapter()
