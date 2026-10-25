from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from app.models import IntegrationConnector
from app.settings import settings
from .schemas import CustomerSyncBatch
from .secrets import resolve_secret_reference


class IntegrationConnectorError(RuntimeError):
    pass


def _endpoint(connector: IntegrationConnector, path: str) -> str:
    base = connector.base_url.strip().rstrip("/") + "/"
    parsed = urlparse(base)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise IntegrationConnectorError("INTEGRATION_BASE_URL_INVALID")
    if parsed.scheme != "https" and not settings.integration_allow_insecure_http:
        raise IntegrationConnectorError("INTEGRATION_HTTPS_REQUIRED")
    allowed_hosts = set(str(x).casefold() for x in (connector.config or {}).get("allowed_hosts", []))
    if allowed_hosts and parsed.hostname.casefold() not in allowed_hosts:
        raise IntegrationConnectorError("INTEGRATION_DESTINATION_NOT_ALLOWLISTED")
    return urljoin(base, path.lstrip("/"))


def _auth_headers(connector: IntegrationConnector) -> dict[str, str]:
    mode = connector.auth_mode.upper()
    if mode == "NONE":
        return {}
    secret = resolve_secret_reference(connector.credential_reference)
    if not secret:
        raise IntegrationConnectorError("INTEGRATION_CREDENTIAL_MISSING")
    if mode == "BEARER":
        return {"Authorization": f"Bearer {secret}"}
    if mode == "BASIC":
        encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {encoded}"}
    if mode == "OAUTH2_CLIENT_CREDENTIALS":
        raise IntegrationConnectorError("OAUTH2_OUTBOUND_ADAPTER_NOT_CONFIGURED")
    raise IntegrationConnectorError("INTEGRATION_AUTH_MODE_UNSUPPORTED")


@dataclass
class RestCustomerSourceAdapter:
    connector: IntegrationConnector

    async def fetch_full(self, *, cursor: str | None = None) -> CustomerSyncBatch:
        path = str((self.connector.config or {}).get("full_sync_path") or "/customers")
        params = {"cursor": cursor} if cursor else {}
        return await self._get(path, params=params)

    async def fetch_changes(self, *, since: str | None = None, cursor: str | None = None) -> CustomerSyncBatch:
        path = str((self.connector.config or {}).get("changes_path") or "/changes")
        params: dict[str, str] = {}
        if since:
            params["since"] = since
        if cursor:
            params["cursor"] = cursor
        return await self._get(path, params=params)

    async def _get(self, path: str, *, params: dict[str, str]) -> CustomerSyncBatch:
        config = self.connector.config or {}
        timeout = float(config.get("timeout_seconds") or 10.0)
        attempts = max(1, min(int(config.get("retry_attempts") or 3), 5))
        base_delay = max(0.1, min(float(config.get("retry_base_seconds") or 0.5), 5.0))
        url = _endpoint(self.connector, path)
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(timeout),
                    verify=bool(self.connector.verify_tls),
                    follow_redirects=False,
                    headers=_auth_headers(self.connector),
                ) as client:
                    response = await client.get(url, params=params, headers={"Accept": "application/json"})
                response.raise_for_status()
                return CustomerSyncBatch.model_validate(response.json())
            except httpx.HTTPStatusError as exc:
                last_error = exc
                # Retry throttling and server failures only; permanent 4xx contracts fail immediately.
                if exc.response.status_code != 429 and exc.response.status_code < 500:
                    break
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_error = exc
            except ValueError as exc:
                last_error = exc
                break
            if attempt + 1 < attempts:
                await asyncio.sleep(base_delay * (2 ** attempt))
        raise IntegrationConnectorError(str(last_error or "INTEGRATION_REQUEST_FAILED")[:500]) from last_error
