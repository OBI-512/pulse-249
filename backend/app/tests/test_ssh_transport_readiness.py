import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from app.remote_gateway import ssh_transport as transport
from app.remote_gateway.ssh_transport import (
    SSHTransportError,
    _ssh_log_state,
    _wait_for_ssh_ready,
)


class _FakeProcess:
    def __init__(self, return_code=None):
        self.return_code = return_code

    def poll(self):
        return self.return_code


def test_ssh_log_state_requires_interactive_session_for_ready():
    assert _ssh_log_state("debug1: Authenticated to 192.0.2.1 using password") == "AUTHENTICATED"
    assert _ssh_log_state("debug1: Entering interactive session.") == "READY"
    assert _ssh_log_state("Permission denied, please try again.") == "AUTH_FAILED"
    assert _ssh_log_state("no matching cipher found") == "NEGOTIATION_FAILED"
    assert _ssh_log_state("no matching MAC found") == "NEGOTIATION_FAILED"


def test_legacy_ssh_profile_enables_only_explicit_legacy_algorithms():
    assert transport.ssh_compatibility_options("MODERN") == []
    assert transport.ssh_compatibility_options("LEGACY_SSH_RSA_DH1_CBC") == [
        "-o", "KexAlgorithms=+diffie-hellman-group1-sha1",
        "-o", "HostKeyAlgorithms=+ssh-rsa",
        "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
        "-o", "Ciphers=+aes128-cbc",
        "-o", "MACs=+hmac-sha1",
    ]


def test_sshpass_rejected_password_is_not_ready():
    async def scenario():
        with TemporaryDirectory() as directory:
            log = Path(directory) / "ssh-debug.log"
            log.write_text(
                "debug1: Authentications that can continue: publickey,password\n",
                encoding="utf-8",
            )
            with pytest.raises(SSHTransportError) as exc:
                await _wait_for_ssh_ready(_FakeProcess(return_code=5), log, 1)
            assert str(exc.value) == "SSH_AUTHENTICATION_FAILED"

    asyncio.run(scenario())


def test_authenticated_but_not_interactive_process_exit_fails():
    async def scenario():
        with TemporaryDirectory() as directory:
            log = Path(directory) / "ssh-debug.log"
            log.write_text(
                "debug1: Authenticated to 192.0.2.1 using password\n",
                encoding="utf-8",
            )
            with pytest.raises(SSHTransportError) as exc:
                await _wait_for_ssh_ready(_FakeProcess(return_code=1), log, 1)
            assert str(exc.value) == "SSH_INTERACTIVE_SESSION_FAILED"

    asyncio.run(scenario())


def test_interactive_session_is_ready():
    async def scenario():
        with TemporaryDirectory() as directory:
            log = Path(directory) / "ssh-debug.log"
            log.write_text(
                "debug1: Authenticated to 192.0.2.1 using password\n"
                "debug1: Entering interactive session.\n",
                encoding="utf-8",
            )
            await _wait_for_ssh_ready(_FakeProcess(return_code=None), log, 1)

    asyncio.run(scenario())


def test_cached_trusted_host_key_builds_known_hosts_without_live_scan(monkeypatch):
    async def scenario():
        line = "192.0.2.1 ssh-rsa AAAATESTKEY"
        monkeypatch.setattr(
            transport,
            "_fingerprint_for_line",
            lambda _line: asyncio.sleep(0, result="SHA256:trusted"),
        )

        async def live_scan_must_not_run(*_args, **_kwargs):
            raise AssertionError("cached trusted key must bypass live SSH discovery")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", live_scan_must_not_run)

        with TemporaryDirectory() as directory:
            destination = Path(directory) / "known_hosts"
            await transport.pinned_known_host(
                "192.0.2.1",
                22,
                "SHA256:trusted",
                destination,
                compatibility_profile="LEGACY_SSH_RSA_DH1_CBC",
                trusted_host_key_line=line,
            )
            assert destination.read_text(encoding="utf-8") == line + "\n"

    asyncio.run(scenario())


def test_cached_trusted_host_key_fingerprint_mismatch_fails_closed(monkeypatch):
    async def scenario():
        monkeypatch.setattr(
            transport,
            "_fingerprint_for_line",
            lambda _line: asyncio.sleep(0, result="SHA256:other"),
        )
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "known_hosts"
            with pytest.raises(SSHTransportError) as exc:
                await transport.pinned_known_host(
                    "192.0.2.1",
                    22,
                    "SHA256:trusted",
                    destination,
                    trusted_host_key_line="192.0.2.1 ssh-rsa AAAATESTKEY",
                )
            assert str(exc.value) == "SSH_HOST_KEY_MISMATCH"
            assert not destination.exists()

    asyncio.run(scenario())
