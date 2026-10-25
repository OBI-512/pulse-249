from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from ..settings import settings
from .secrets import resolve_secret_reference


def _pem(value: str) -> str:
    return value.strip().replace("\\n", "\n") + "\n"


def main() -> None:
    kwargs: dict[str, object] = {
        "host": "0.0.0.0",
        "port": 8010,
        "access_log": False,
        "proxy_headers": False,
    }
    if settings.remote_access_gateway_tls_enabled:
        cert = _pem(resolve_secret_reference(settings.remote_access_gateway_tls_certificate_reference))
        key = _pem(resolve_secret_reference(settings.remote_access_gateway_tls_private_key_reference))
        target = Path("/tmp/fttw-remote")
        target.mkdir(parents=True, exist_ok=True)
        cert_path = target / "gateway.crt"
        key_path = target / "gateway.key"
        cert_path.write_text(cert, encoding="utf-8")
        key_path.write_text(key, encoding="utf-8")
        os.chmod(cert_path, 0o600)
        os.chmod(key_path, 0o600)
        kwargs["ssl_certfile"] = str(cert_path)
        kwargs["ssl_keyfile"] = str(key_path)
    uvicorn.run("app.remote_gateway.main:app", **kwargs)


if __name__ == "__main__":
    main()
