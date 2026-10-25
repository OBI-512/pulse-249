import os
import pty
import termios

from app.remote_gateway.ssh_transport import (
    SSH_COMPATIBILITY_LEGACY_RSA_DH1_CBC,
    SSH_COMPATIBILITY_MODERN,
    _configure_terminal_modes,
    ssh_terminal_type,
)


def test_terminal_type_is_legacy_safe_without_weakening_modern_sessions():
    assert ssh_terminal_type(SSH_COMPATIBILITY_MODERN) == "xterm-256color"
    assert ssh_terminal_type(SSH_COMPATIBILITY_LEGACY_RSA_DH1_CBC) == "xterm"


def test_ssh_pty_uses_standard_xterm_backspace_and_control_characters():
    master_fd, slave_fd = pty.openpty()
    try:
        _configure_terminal_modes(slave_fd)
        control_chars = termios.tcgetattr(slave_fd)[6]
        assert control_chars[termios.VERASE] == b"\x7f"
        assert control_chars[termios.VINTR] == b"\x03"
        assert control_chars[termios.VKILL] == b"\x15"
        assert control_chars[termios.VEOF] == b"\x04"
    finally:
        os.close(master_fd)
        os.close(slave_fd)
