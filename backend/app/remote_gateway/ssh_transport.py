from __future__ import annotations

import asyncio
import fcntl
import os
import pty
import re
import struct
import subprocess
import tempfile
import termios
from dataclasses import dataclass
from pathlib import Path


class SSHTransportError(RuntimeError):
    pass


SSH_COMPATIBILITY_MODERN = "MODERN"
SSH_COMPATIBILITY_LEGACY_RSA_DH1_CBC = "LEGACY_SSH_RSA_DH1_CBC"
SSH_HOST_KEY_LINE_METADATA_KEY = "ssh_host_key_known_hosts_line"

_SAFE_REMOTE_SCP_PATH = re.compile(r"^/[A-Za-z0-9._/-]{1,511}$")


def ssh_compatibility_options(profile: str) -> list[str]:
    normalized = (profile or SSH_COMPATIBILITY_MODERN).strip().upper()
    if normalized == SSH_COMPATIBILITY_MODERN:
        return []
    if normalized == SSH_COMPATIBILITY_LEGACY_RSA_DH1_CBC:
        return [
            "-o", "KexAlgorithms=+diffie-hellman-group1-sha1",
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
            "-o", "Ciphers=+aes128-cbc",
            "-o", "MACs=+hmac-sha1",
        ]
    raise SSHTransportError("SSH_COMPATIBILITY_PROFILE_UNSUPPORTED")


@dataclass
class SSHProcess:
    process: subprocess.Popen
    master_fd: int
    temp_dir: tempfile.TemporaryDirectory

    def close(self) -> None:
        try:
            if self.process.poll() is None:
                self.process.terminate()
        except Exception:
            pass
        try:
            os.close(self.master_fd)
        except OSError:
            pass
        self.temp_dir.cleanup()


def _window_size(fd: int, rows: int, cols: int) -> None:
    rows = max(5, min(int(rows), 300))
    cols = max(20, min(int(cols), 500))
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def ssh_terminal_type(profile: str) -> str:
    normalized = (profile or SSH_COMPATIBILITY_MODERN).strip().upper()
    return "xterm" if normalized == SSH_COMPATIBILITY_LEGACY_RSA_DH1_CBC else "xterm-256color"


def _configure_terminal_modes(fd: int) -> None:
    """Expose conventional VT erase/control characters to the SSH client PTY.

    OpenSSH serializes these tty modes to the remote PTY. DEL (0x7f) is the
    standard xterm Backspace sequence and fixes legacy shells whose ssh daemon
    otherwise inherits an incompatible erase character.
    """
    attrs = termios.tcgetattr(fd)
    cc = attrs[6]
    cc[termios.VERASE] = b"\x7f"
    cc[termios.VINTR] = b"\x03"
    cc[termios.VKILL] = b"\x15"
    cc[termios.VEOF] = b"\x04"
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def _ssh_log_state(text: str) -> str:
    """Classify OpenSSH verbose output without returning remote/user data."""
    lowered = text.lower()
    if "entering interactive session" in lowered:
        return "READY"
    if "permission denied" in lowered or "authentication failed" in lowered:
        return "AUTH_FAILED"
    if (
        "no matching cipher" in lowered
        or "no matching key exchange" in lowered
        or "no matching host key" in lowered
        or "no matching mac" in lowered
    ):
        return "NEGOTIATION_FAILED"
    if "authenticated to " in lowered:
        return "AUTHENTICATED"
    return "PENDING"


def _read_debug_log(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


async def _wait_for_ssh_ready(
    process: subprocess.Popen,
    debug_log: Path,
    timeout_seconds: float,
) -> None:
    """Wait until OpenSSH proves that authentication and shell entry completed."""
    timeout = max(1.0, min(float(timeout_seconds), 60.0))
    deadline = asyncio.get_running_loop().time() + timeout

    while True:
        state = _ssh_log_state(_read_debug_log(debug_log))
        if state == "READY":
            return
        if state == "AUTH_FAILED":
            raise SSHTransportError("SSH_AUTHENTICATION_FAILED")
        if state == "NEGOTIATION_FAILED":
            raise SSHTransportError("SSH_NEGOTIATION_FAILED")

        return_code = process.poll()
        if return_code is not None:
            # sshpass exit status 5 means the SSH password was rejected.
            if return_code == 5:
                raise SSHTransportError("SSH_AUTHENTICATION_FAILED")
            if state == "AUTHENTICATED":
                raise SSHTransportError("SSH_INTERACTIVE_SESSION_FAILED")
            raise SSHTransportError("SSH_SESSION_START_FAILED")

        if asyncio.get_running_loop().time() >= deadline:
            raise SSHTransportError("SSH_AUTHENTICATION_TIMEOUT")
        await asyncio.sleep(0.05)


async def _fingerprint_for_line(line: str) -> str | None:
    proc = await asyncio.create_subprocess_exec(
        "ssh-keygen",
        "-lf",
        "-",
        "-E",
        "sha256",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate((line.rstrip() + "\n").encode("utf-8"))
    if proc.returncode != 0:
        return None
    parts = stdout.decode("utf-8", "replace").strip().split()
    return parts[1] if len(parts) >= 2 else None


def _known_hosts_line_for_destination(host: str, port: int, line: str) -> str | None:
    parts = line.strip().split()
    if len(parts) != 3:
        return None
    _stored_host, key_type, key_data = parts
    if not key_type.startswith(("ssh-", "ecdsa-", "sk-")):
        return None
    host_token = host if int(port) == 22 and ":" not in host else f"[{host}]:{int(port)}"
    return f"{host_token} {key_type} {key_data}"


async def pinned_known_host(
    host: str,
    port: int,
    expected_fingerprint: str,
    destination: Path,
    compatibility_profile: str = SSH_COMPATIBILITY_MODERN,
    trusted_host_key_line: str | None = None,
) -> None:
    # A previously trusted public host key is sufficient to build a strict
    # per-session known_hosts file. Recompute its fingerprint before every use
    # so corrupted/stale metadata fails closed instead of weakening pinning.
    if trusted_host_key_line:
        fingerprint = await _fingerprint_for_line(trusted_host_key_line)
        normalized_line = _known_hosts_line_for_destination(host, port, trusted_host_key_line)
        if fingerprint != expected_fingerprint or normalized_line is None:
            raise SSHTransportError("SSH_HOST_KEY_MISMATCH")
        destination.write_text(normalized_line + "\n", encoding="utf-8")
        os.chmod(destination, 0o600)
        return

    # Backward-compatible fallback for devices trusted before public key
    # material was cached. Once discovery/trust succeeds, callers persist the
    # verified line and later sessions no longer need this extra connection.
    options = ssh_compatibility_options(compatibility_profile)
    try:
        if options:
            probe_hosts = destination.parent / "probe_known_hosts"
            command = [
                "ssh",
                "-F", "/dev/null",
                "-p", str(port),
                "-o", "BatchMode=yes",
                "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no",
                "-o", "ConnectTimeout=5",
                "-o", "ConnectionAttempts=1",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"UserKnownHostsFile={probe_hosts}",
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "HashKnownHosts=no",
                "-o", "LogLevel=ERROR",
                *options,
                f"fttw-hostkey-probe@{host}",
                "exit",
            ]
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=8)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
            if not probe_hosts.exists():
                raise SSHTransportError("SSH_HOST_KEY_SCAN_FAILED")
            raw = probe_hosts.read_text(encoding="utf-8", errors="replace")
        else:
            proc = await asyncio.create_subprocess_exec(
                "ssh-keyscan",
                "-T",
                "5",
                "-p",
                str(port),
                host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            if proc.returncode not in (0, 1):
                raise SSHTransportError("SSH_HOST_KEY_SCAN_FAILED")
            raw = stdout.decode("utf-8", "replace")
    except (asyncio.TimeoutError, OSError) as exc:
        raise SSHTransportError("SSH_HOST_KEY_SCAN_FAILED") from exc

    lines = [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    for line in lines:
        fingerprint = await _fingerprint_for_line(line)
        if fingerprint == expected_fingerprint:
            normalized_line = _known_hosts_line_for_destination(host, port, line)
            if normalized_line is None:
                continue
            destination.write_text(normalized_line + "\n", encoding="utf-8")
            os.chmod(destination, 0o600)
            return
    raise SSHTransportError("SSH_HOST_KEY_MISMATCH")


async def start_ssh(
    *,
    host: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    expected_fingerprint: str,
    compatibility_profile: str = SSH_COMPATIBILITY_MODERN,
    rows: int = 30,
    cols: int = 120,
    authentication_timeout_seconds: float = 12.0,
    trusted_host_key_line: str | None = None,
) -> SSHProcess:
    temp_dir = tempfile.TemporaryDirectory(prefix="fttw-remote-")
    base = Path(temp_dir.name)
    known_hosts = base / "known_hosts"
    debug_log = base / "ssh-debug.log"
    await pinned_known_host(
        host,
        port,
        expected_fingerprint,
        known_hosts,
        compatibility_profile=compatibility_profile,
        trusted_host_key_line=trusted_host_key_line,
    )

    compatibility_args = ssh_compatibility_options(compatibility_profile)
    identity_args: list[str] = []
    if private_key:
        identity = base / "identity"
        identity.write_text(private_key.replace("\\n", "\n"), encoding="utf-8")
        os.chmod(identity, 0o600)
        identity_args = ["-i", str(identity)]

    command = [
        "ssh",
        "-v",
        "-E", str(debug_log),
        "-F", "/dev/null",
        "-tt",
        "-p", str(port),
        "-o", "BatchMode=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=2",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "PermitLocalCommand=no",
        *compatibility_args,
        *identity_args,
        f"{username}@{host}",
    ]
    env = os.environ.copy()
    env["TERM"] = ssh_terminal_type(compatibility_profile)
    if password:
        env["SSHPASS"] = password
        command = ["sshpass", "-e", *command]

    master_fd, slave_fd = pty.openpty()
    _window_size(slave_fd, rows, cols)
    _configure_terminal_modes(slave_fd)
    process = None
    try:
        process = subprocess.Popen(
            command,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            start_new_session=True,
            env=env,
        )
    except Exception:
        os.close(master_fd)
        os.close(slave_fd)
        temp_dir.cleanup()
        raise
    finally:
        try:
            os.close(slave_fd)
        except OSError:
            pass

    try:
        await _wait_for_ssh_ready(
            process,
            debug_log,
            authentication_timeout_seconds,
        )
    except Exception:
        try:
            if process.poll() is None:
                process.terminate()
                await asyncio.to_thread(process.wait, 2)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        temp_dir.cleanup()
        raise

    return SSHProcess(process=process, master_fd=master_fd, temp_dir=temp_dir)


async def upload_file_scp(
    *,
    host: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    expected_fingerprint: str,
    remote_path: str,
    payload: bytes,
    compatibility_profile: str = SSH_COMPATIBILITY_MODERN,
    timeout_seconds: int = 120,
    trusted_host_key_line: str | None = None,
) -> None:
    """Upload bytes through pinned legacy-SCP without exposing credentials.

    OpenSSH 9+ defaults ``scp`` to SFTP, while many embedded SSH servers only
    implement the historical SCP protocol. ``-O`` deliberately selects that
    protocol. Host-key pinning and authentication handling are identical to the
    interactive SSH transport; password material is passed only via SSHPASS and
    private-key material exists only in a mode-0600 temporary file.
    """

    if not isinstance(payload, (bytes, bytearray)):
        raise SSHTransportError("SSH_SCP_PAYLOAD_INVALID")
    if (
        not isinstance(remote_path, str)
        or _SAFE_REMOTE_SCP_PATH.fullmatch(remote_path) is None
        or remote_path.endswith("/")
        or "//" in remote_path
        or "/./" in remote_path
        or "/../" in remote_path
        or remote_path.endswith("/..")
    ):
        raise SSHTransportError("SSH_SCP_REMOTE_PATH_INVALID")
    try:
        timeout = int(timeout_seconds)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SSHTransportError("SSH_SCP_TIMEOUT_INVALID") from exc
    if not 1 <= timeout <= 1800:
        raise SSHTransportError("SSH_SCP_TIMEOUT_INVALID")

    temp_dir = tempfile.TemporaryDirectory(prefix="fttw-scp-")
    base = Path(temp_dir.name)
    known_hosts = base / "known_hosts"
    local_payload = base / "payload"
    try:
        await pinned_known_host(
            host,
            port,
            expected_fingerprint,
            known_hosts,
            compatibility_profile=compatibility_profile,
            trusted_host_key_line=trusted_host_key_line,
        )
        local_payload.write_bytes(bytes(payload))
        os.chmod(local_payload, 0o600)

        compatibility_args = ssh_compatibility_options(compatibility_profile)
        identity_args: list[str] = []
        if private_key:
            identity = base / "identity"
            identity.write_text(private_key.replace("\\n", "\n"), encoding="utf-8")
            os.chmod(identity, 0o600)
            identity_args = ["-i", str(identity)]

        destination_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        command = [
            "scp",
            "-q",
            "-O",
            "-F", "/dev/null",
            "-P", str(port),
            "-o", "BatchMode=no",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "ConnectionAttempts=1",
            "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no",
            "-o", "LogLevel=ERROR",
            *compatibility_args,
            *identity_args,
            str(local_payload),
            f"{username}@{destination_host}:{remote_path}",
        ]
        env = os.environ.copy()
        if password:
            env["SSHPASS"] = password
            command = ["sshpass", "-e", *command]

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                env=env,
            )
        except OSError as exc:
            raise SSHTransportError("SSH_SCP_START_FAILED") from exc
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            proc.kill()
            await proc.communicate()
            raise SSHTransportError("SSH_SCP_TIMEOUT") from exc
        if proc.returncode != 0:
            raise SSHTransportError("SSH_SCP_UPLOAD_FAILED")
    finally:
        temp_dir.cleanup()


async def download_file_scp(
    *,
    host: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    expected_fingerprint: str,
    remote_path: str,
    max_bytes: int,
    compatibility_profile: str = SSH_COMPATIBILITY_MODERN,
    timeout_seconds: int = 120,
    trusted_host_key_line: str | None = None,
) -> bytes:
    """Download exact bytes through pinned legacy-SCP.

    This path deliberately bypasses the interactive PTY so newline conversion,
    terminal echo and prompt framing cannot alter restorable file-backed device
    configurations. OpenSSH ``scp -O`` is used for legacy embedded SSH servers.
    """
    if (
        not isinstance(remote_path, str)
        or _SAFE_REMOTE_SCP_PATH.fullmatch(remote_path) is None
        or remote_path.endswith("/")
        or "//" in remote_path
        or "/./" in remote_path
        or "/../" in remote_path
        or remote_path.endswith("/..")
    ):
        raise SSHTransportError("SSH_SCP_REMOTE_PATH_INVALID")
    try:
        limit = int(max_bytes)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SSHTransportError("SSH_SCP_DOWNLOAD_MAX_BYTES_INVALID") from exc
    if not 1 <= limit <= 1073741824:
        raise SSHTransportError("SSH_SCP_DOWNLOAD_MAX_BYTES_INVALID")
    try:
        timeout = int(timeout_seconds)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SSHTransportError("SSH_SCP_TIMEOUT_INVALID") from exc
    if not 1 <= timeout <= 1800:
        raise SSHTransportError("SSH_SCP_TIMEOUT_INVALID")

    temp_dir = tempfile.TemporaryDirectory(prefix="fttw-scp-download-")
    base = Path(temp_dir.name)
    known_hosts = base / "known_hosts"
    local_payload = base / "payload"
    try:
        await pinned_known_host(
            host,
            port,
            expected_fingerprint,
            known_hosts,
            compatibility_profile=compatibility_profile,
            trusted_host_key_line=trusted_host_key_line,
        )

        compatibility_args = ssh_compatibility_options(compatibility_profile)
        identity_args: list[str] = []
        if private_key:
            identity = base / "identity"
            identity.write_text(private_key.replace("\\n", "\n"), encoding="utf-8")
            os.chmod(identity, 0o600)
            identity_args = ["-i", str(identity)]

        destination_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        command = [
            "scp",
            "-q",
            "-O",
            "-F", "/dev/null",
            "-P", str(port),
            "-o", "BatchMode=no",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "ConnectionAttempts=1",
            "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no",
            "-o", "LogLevel=ERROR",
            *compatibility_args,
            *identity_args,
            f"{username}@{destination_host}:{remote_path}",
            str(local_payload),
        ]
        env = os.environ.copy()
        if password:
            env["SSHPASS"] = password
            command = ["sshpass", "-e", *command]

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                env=env,
            )
        except OSError as exc:
            raise SSHTransportError("SSH_SCP_DOWNLOAD_START_FAILED") from exc
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            proc.kill()
            await proc.communicate()
            raise SSHTransportError("SSH_SCP_DOWNLOAD_TIMEOUT") from exc
        if proc.returncode != 0 or not local_payload.is_file():
            raise SSHTransportError("SSH_SCP_DOWNLOAD_FAILED")
        try:
            size = local_payload.stat().st_size
        except OSError as exc:
            raise SSHTransportError("SSH_SCP_DOWNLOAD_FAILED") from exc
        if size > limit:
            raise SSHTransportError("SSH_SCP_DOWNLOAD_SIZE_EXCEEDED")
        try:
            payload = local_payload.read_bytes()
        except OSError as exc:
            raise SSHTransportError("SSH_SCP_DOWNLOAD_FAILED") from exc
        if len(payload) > limit:
            raise SSHTransportError("SSH_SCP_DOWNLOAD_SIZE_EXCEEDED")
        return payload
    finally:
        temp_dir.cleanup()


async def read_pty(fd: int, size: int = 4096) -> bytes:
    try:
        return await asyncio.to_thread(os.read, fd, size)
    except OSError:
        return b""


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("PTY write returned zero bytes")
        view = view[written:]


async def write_pty(fd: int, data: str) -> None:
    if not data:
        return
    await asyncio.to_thread(_write_all, fd, data.encode("utf-8", "replace"))


async def write_pty_bytes(fd: int, data: bytes) -> None:
    if not data:
        return
    await asyncio.to_thread(_write_all, fd, data)


async def resize_pty(fd: int, rows: int, cols: int) -> None:
    await asyncio.to_thread(_window_size, fd, rows, cols)