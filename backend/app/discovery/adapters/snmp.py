from __future__ import annotations

import asyncio
import ipaddress
import shutil
import subprocess
import time

from ..base import DiscoveryAdapter
from ..models import DiscoveryContext, DiscoveryResult

_SYS_NAME_OID = "1.3.6.1.2.1.1.5.0"
_SNMP_PORT = 161
_ALLOWED_VERSIONS = {"1", "2c", "3"}
_ALLOWED_SECURITY_LEVELS = {"noAuthNoPriv", "authNoPriv", "authPriv"}
_ALLOWED_AUTH_PROTOCOLS = {"MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}
_ALLOWED_PRIV_PROTOCOLS = {"DES", "AES"}


class SNMPConfigurationError(ValueError):
    pass


def _normalize_version(value: str | None) -> str:
    version = (value or "2c").strip().lower()
    if version in {"v1", "1"}:
        return "1"
    if version in {"v2c", "2c", "2"}:
        return "2c"
    if version in {"v3", "3"}:
        return "3"
    raise SNMPConfigurationError("Unsupported SNMP version.")


def _validate_context(context: DiscoveryContext) -> str:
    version = _normalize_version(context.snmp_version)
    if int(context.snmp_port) < 1 or int(context.snmp_port) > 65535:
        raise SNMPConfigurationError("SNMP port must be between 1 and 65535.")
    if version in {"1", "2c"}:
        if not (context.snmp_community or "").strip():
            raise SNMPConfigurationError(f"SNMP v{version} community is required.")
        return version

    username = (context.snmp_v3_username or "").strip()
    if not username:
        raise SNMPConfigurationError("SNMPv3 username is required.")

    level = (context.snmp_v3_security_level or "noAuthNoPriv").strip()
    if level not in _ALLOWED_SECURITY_LEVELS:
        raise SNMPConfigurationError("Unsupported SNMPv3 security level.")

    if level in {"authNoPriv", "authPriv"}:
        auth_protocol = (context.snmp_v3_auth_protocol or "SHA").upper()
        if auth_protocol not in _ALLOWED_AUTH_PROTOCOLS:
            raise SNMPConfigurationError("Unsupported SNMPv3 authentication protocol.")
        if not (context.snmp_v3_auth_password or ""):
            raise SNMPConfigurationError("SNMPv3 authentication password is required.")

    if level == "authPriv":
        priv_protocol = (context.snmp_v3_priv_protocol or "AES").upper()
        if priv_protocol not in _ALLOWED_PRIV_PROTOCOLS:
            raise SNMPConfigurationError("Unsupported SNMPv3 privacy protocol.")
        if not (context.snmp_v3_priv_password or ""):
            raise SNMPConfigurationError("SNMPv3 privacy password is required.")

    if context.snmp_v3_context_name is not None and len(context.snmp_v3_context_name) > 255:
        raise SNMPConfigurationError("SNMPv3 context name is too long.")
    return version


def _target(context: DiscoveryContext) -> str:
    port = int(context.snmp_port)
    if port == _SNMP_PORT:
        return context.ip_address
    try:
        address = ipaddress.ip_address(context.ip_address)
    except ValueError:
        return f"udp:{context.ip_address}:{port}"
    if address.version == 6:
        return f"udp6:[{address.compressed}]:{port}"
    return f"udp:{address.compressed}:{port}"


def _build_command(context: DiscoveryContext) -> tuple[list[str], str]:
    binary = shutil.which("snmpget")
    if not binary:
        raise RuntimeError("SNMP_CLIENT_NOT_INSTALLED")

    version = _validate_context(context)
    command = [
        binary,
        "-Oqv",
        f"-v{version}",
        "-t",
        str(max(0.1, float(context.timeout_seconds))),
        "-r",
        str(max(0, int(context.snmp_retries))),
    ]

    if version in {"1", "2c"}:
        command.extend(["-c", (context.snmp_community or "").strip()])
    else:
        level = (context.snmp_v3_security_level or "noAuthNoPriv").strip()
        command.extend([
            "-l",
            level,
            "-u",
            (context.snmp_v3_username or "").strip(),
        ])
        if context.snmp_v3_context_name:
            command.extend(["-n", context.snmp_v3_context_name])
        if level in {"authNoPriv", "authPriv"}:
            command.extend([
                "-a",
                (context.snmp_v3_auth_protocol or "SHA").upper(),
                "-A",
                context.snmp_v3_auth_password or "",
            ])
        if level == "authPriv":
            command.extend([
                "-x",
                (context.snmp_v3_priv_protocol or "AES").upper(),
                "-X",
                context.snmp_v3_priv_password or "",
            ])

    command.extend([_target(context), _SYS_NAME_OID])
    return command, version


def _clean_value(stdout: str) -> str:
    value = stdout.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value.strip()


def _run_snmpget(context: DiscoveryContext) -> tuple[str, float, str]:
    command, version = _build_command(context)
    started = time.perf_counter()
    outer_timeout = max(3.0, float(context.timeout_seconds) * (int(context.snmp_retries) + 1) + 2.0)
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=outer_timeout,
        check=False,
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    if proc.returncode != 0:
        stderr = (proc.stderr or "").lower()
        if "timeout" in stderr or "no response" in stderr:
            raise TimeoutError("SNMP_NO_RESPONSE")
        if "authentication failure" in stderr or "unknown user" in stderr:
            raise PermissionError("SNMP_AUTHENTICATION_FAILED")
        raise RuntimeError("SNMP_PROBE_FAILED")

    value = _clean_value(proc.stdout or "")
    if not value:
        raise RuntimeError("SNMP_EMPTY_RESPONSE")
    return value, elapsed_ms, version


def _snmp_get_sys_name(ip_address: str, community: str, timeout_seconds: float) -> tuple[str, float]:
    """Backward-compatible v2c helper used by existing operational checks."""
    value, elapsed_ms, _ = _run_snmpget(
        DiscoveryContext(
            ip_address=ip_address,
            timeout_seconds=timeout_seconds,
            snmp_version="2c",
            snmp_community=community,
            snmp_retries=0,
        )
    )
    return value, elapsed_ms


class SNMPDiscoveryAdapter(DiscoveryAdapter):
    name = "SNMP"
    method = "SNMP"

    async def discover(self, context: DiscoveryContext) -> DiscoveryResult:
        try:
            version = _validate_context(context)
        except SNMPConfigurationError as exc:
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol="SNMP",
                message=str(exc),
                raw_data={"snmp_version": context.snmp_version, "port": context.snmp_port},
            )

        safe_metadata = {
            "snmp_version": version,
            "port": context.snmp_port,
            "oid": _SYS_NAME_OID,
        }
        if version == "3":
            safe_metadata["security_level"] = context.snmp_v3_security_level
            if context.snmp_v3_context_name:
                safe_metadata["context_name"] = context.snmp_v3_context_name

        try:
            sys_name, elapsed_ms, version = await asyncio.to_thread(_run_snmpget, context)
            safe_metadata["snmp_version"] = version
            safe_metadata["sys_name"] = sys_name
            return DiscoveryResult(
                success=True,
                method=self.method,
                ip_address=context.ip_address,
                hostname=sys_name or None,
                management_protocol="SNMP",
                response_time_ms=elapsed_ms,
                message=f"SNMP v{version} response received.",
                raw_data=safe_metadata,
            )
        except TimeoutError:
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol="SNMP",
                message=f"SNMP v{version} probe timed out or received no response.",
                raw_data=safe_metadata,
            )
        except PermissionError:
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol="SNMP",
                message=f"SNMP v{version} authentication failed.",
                raw_data=safe_metadata,
            )
        except subprocess.TimeoutExpired:
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol="SNMP",
                message=f"SNMP v{version} probe exceeded the execution timeout.",
                raw_data=safe_metadata,
            )
        except RuntimeError as exc:
            code = str(exc)
            message = (
                "SNMP client utility is not installed in the backend container."
                if code == "SNMP_CLIENT_NOT_INSTALLED"
                else f"SNMP v{version} probe failed."
            )
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol="SNMP",
                message=message,
                raw_data={**safe_metadata, "error_code": code},
            )
        except Exception as exc:
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol="SNMP",
                message=f"SNMP v{version} discovery failed: {type(exc).__name__}",
                raw_data=safe_metadata,
            )
