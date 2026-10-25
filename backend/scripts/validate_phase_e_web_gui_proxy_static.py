"""Dependency-light backend source invariants for the Phase-E native Web-GUI proxy.

This validator intentionally runs inside the backend image, where the frontend
source tree is not available. Frontend handoff invariants are validated by the
guarded PowerShell deployment harness and by the frontend build/test stages.
"""
from __future__ import annotations

import json
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]

proxy = (BACKEND / "app/remote_gateway/web_proxy.py").read_text(encoding="utf-8")
authz = (BACKEND / "app/security/authorization.py").read_text(encoding="utf-8")
contract = json.loads((BACKEND / "scripts/ci_route_permission_contract_baseline.json").read_text(encoding="utf-8"))

assert "verify=False" not in proxy, "Product proxy must never disable TLS verification globally."
assert "ssl.CERT_NONE" not in proxy, "Product proxy must never disable certificate verification."
assert 'profile.web_tls_compat_profile == "LEGACY_WEAK_CERT_KEY"' in proxy
assert 'context.set_ciphers("DEFAULT:@SECLEVEL=1")' in proxy
assert "LEGACY_TLS_1_0" not in proxy, "TLS 1.0 compatibility must not exist in the active gateway implementation."
assert 'profile.web_tls_mode == "PINNED_CERT"' in proxy
assert "REMOTE_ACCESS_WEB_TARGET_FORBIDDEN" in proxy
assert '"set-cookie"' in proxy and "httponly=True" in proxy
assert "REMOTE_ACCESS_WEB_DENIED" in proxy and "REMOTE_ACCESS_WEB_ENDED" in proxy and "REMOTE_ACCESS_WEB_FAILED" in proxy
assert "device.remote_access.web" in json.dumps(contract)
route_count = int(contract.get("route_count") or 0)
assert route_count == len(contract.get("routes", [])) and route_count >= 251
web = [r for r in contract["routes"] if "/remote-access/web" in r["path"]]
assert len(web) == 3 and all(r["permission"] == "device.remote_access.web" for r in web)
assert "DEVICE_REMOTE_ACCESS_WEB" in authz and "DEVICE_REMOTE_ACCESS_SSH" in authz
print(json.dumps({"phase": "E4", "static_secure_defaults": "PASS", "route_contract_current": route_count}, sort_keys=True))
