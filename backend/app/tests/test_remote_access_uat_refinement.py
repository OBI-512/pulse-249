from pathlib import Path
import inspect

from app.api.routers import devices_lifecycle
from app.remote_gateway import main as remote_gateway_main


def test_management_gui_resolution_uses_configured_target_with_legacy_fallback():
    source = inspect.getsource(devices_lifecycle.test_device_accessibility)
    assert "web_profile.web_port" in source
    assert 'targets = [(configured_scheme, configured_port)]' in source
    assert 'targets = [("https", 443), ("http", 80)]' in source
    assert "web_management_url" in source
    assert 'resolved_scheme' in source
    assert 'HTTPS_HTTP_UNREACHABLE' in source


def test_gateway_ready_message_exposes_only_compatibility_metadata_not_credentials():
    source = Path(remote_gateway_main.__file__).read_text(encoding="utf-8")
    ready_line = next(line for line in source.splitlines() if '"type": "ready"' in line and 'session_id' in line)
    assert 'compatibility_profile' in ready_line
    assert 'username' not in ready_line
    assert 'password' not in ready_line
    assert 'private_key' not in ready_line
