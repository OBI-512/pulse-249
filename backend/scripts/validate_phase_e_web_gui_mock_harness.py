"""Runtime qualification for the deterministic Phase-E mock vendor GUI.

This validates the harness transports themselves (HTTP, HTTPS, redirects,
cookies, forms/assets and WebSocket echo). TLS verification is deliberately
disabled only for the ephemeral self-signed mock harness; product proxy TLS
verification remains fail-closed and is tested separately.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import ssl
from urllib.parse import urlsplit

import httpx
from websockets.asyncio.client import connect as websocket_connect


def _ws_url(base: str) -> str:
    parts = urlsplit(base)
    scheme = "wss" if parts.scheme == "https" else "ws"
    return f"{scheme}://{parts.netloc}/ws"


async def _check_http(base: str, *, verify: bool | ssl.SSLContext) -> dict[str, object]:
    async with httpx.AsyncClient(base_url=base, verify=verify, follow_redirects=False, timeout=10) as client:
        root = await client.get("/")
        assert root.status_code == 200 and "FTTW mock device GUI" in root.text
        redirect = await client.get("/redirect")
        assert redirect.status_code == 302 and redirect.headers.get("location") == "/cookie"
        external = await client.get("/external-redirect")
        assert external.status_code == 302 and "example.invalid" in external.headers.get("location", "")
        cookie = await client.get("/cookie")
        assert cookie.status_code == 200 and "vendor_session" in client.cookies
        cookie_check = await client.get("/cookie-check")
        assert cookie_check.json().get("vendor_cookie_present") is True
        form = await client.post("/form", content=b"value=ok", headers={"content-type": "application/x-www-form-urlencoded"})
        assert form.status_code == 200 and form.json().get("received") is True
        css = await client.get("/asset.css")
        assert css.status_code == 200 and "url('/image.svg')" in css.text
        referer_denied = await client.get("/referer-required.css")
        assert referer_denied.status_code == 403
        referer_css = await client.get("/referer-required.css", headers={"Referer": base.rstrip("/") + "/"})
        assert referer_css.status_code == 200 and "referer-ok" in referer_css.text
        state = await client.get("/api/state")
        assert state.json() == {"state": "ready"}
    return {"base": base, "http": "PASS"}


async def _check_ws(base: str, *, insecure_mock_tls: bool) -> dict[str, object]:
    ssl_context = None
    if insecure_mock_tls:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    async with websocket_connect(_ws_url(base), ssl=ssl_context, open_timeout=10) as ws:
        await ws.send("fttw-phase-e4")
        echoed = await ws.recv()
        assert echoed == "fttw-phase-e4"
    return {"base": base, "websocket": "PASS"}


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--http-base", required=True)
    parser.add_argument("--https-base", required=True)
    args = parser.parse_args()

    insecure_https = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure_https.check_hostname = False
    insecure_https.verify_mode = ssl.CERT_NONE

    results = []
    results.append(await _check_http(args.http_base.rstrip("/"), verify=True))
    results.append(await _check_ws(args.http_base.rstrip("/"), insecure_mock_tls=False))
    results.append(await _check_http(args.https_base.rstrip("/"), verify=insecure_https))
    results.append(await _check_ws(args.https_base.rstrip("/"), insecure_mock_tls=True))
    print(json.dumps({"phase": "E4", "mock_web_gui_harness": "PASS", "checks": results}, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
