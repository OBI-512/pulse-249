from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import ipaddress
import re
import time
from dataclasses import dataclass

import httpx
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .tp_link_mr_web_auth import (
    TPLinkMRWebAuthenticationError,
    _aes_cbc_base64,
    authenticate_tp_link_mr_rsa_aes_session,
)


_READ_ONLY_QUERY = (
    "1&1&1&8\r\n"
    "[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\n"
    "modelName\r\n"
)


@dataclass(frozen=True)
class RequestShape:
    method: str
    path: str
    content_type: str
    token_id_present: bool
    cookie_present: bool
    body_bytes: int
    field_names: tuple[str, ...]
    sign_length: int
    sign_is_hex: bool
    data_length: int
    data_is_base64: bool
    cipher_bytes: int
    cipher_block_aligned: bool


def _validate_host(value: str) -> str:
    parsed = ipaddress.ip_address(value.strip())
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved:
        raise ValueError("target IP is not allowed")
    return str(parsed)


def _parse_body_fields(body: bytes) -> dict[str, str]:
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError:
        return {}
    result: dict[str, str] = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in {"sign", "data"}:
            result[key] = value.strip()
    return result


def summarize_request(request: httpx.Request) -> RequestShape:
    fields = _parse_body_fields(request.content)
    sign = fields.get("sign", "")
    data = fields.get("data", "")
    decoded = b""
    data_is_base64 = False
    if data:
        try:
            decoded = base64.b64decode(data, validate=True)
            data_is_base64 = True
        except (ValueError, base64.binascii.Error):
            pass
    return RequestShape(
        method=request.method.upper(),
        path=request.url.path,
        content_type=request.headers.get("content-type", ""),
        token_id_present=bool(request.headers.get("tokenid")),
        cookie_present=bool(request.headers.get("cookie")),
        body_bytes=len(request.content),
        field_names=tuple(sorted(fields)),
        sign_length=len(sign),
        sign_is_hex=bool(sign) and re.fullmatch(r"[0-9A-Fa-f]+", sign) is not None,
        data_length=len(data),
        data_is_base64=data_is_base64,
        cipher_bytes=len(decoded),
        cipher_block_aligned=bool(decoded) and len(decoded) % 16 == 0,
    )


def _decrypt_response_shape(body: bytes, *, key: str, iv: str) -> tuple[bool, int, int]:
    try:
        encoded = body.decode("ascii").strip()
        ciphertext = base64.b64decode(encoded, validate=True)
        if not ciphertext or len(ciphertext) % 16:
            return False, 0, 0
        decryptor = Cipher(
            algorithms.AES(key.encode("ascii")),
            modes.CBC(iv.encode("ascii")),
        ).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        decoded = plaintext.decode("utf-8")
    except Exception:
        return False, 0, 0
    return True, len(plaintext), len(decoded.splitlines())


def _yn(value: bool) -> str:
    return "yes" if value else "no"


async def diagnose(host: str, password: str, *, port: int = 80, transport=None) -> int:
    target = _validate_host(host)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    default_port = port == 80
    origin = f"http://{target}{'' if default_port else ':' + str(port)}"

    print("=== FTTW MR600 POST-AUTH WIRE DIAGNOSTIC ===")
    print(f"target={target} transport=HTTP port={port}")
    print("mode=READ_ONLY requests=single_post_auth_cgi_gdpr")
    print("secret_output=disabled")

    timeout = httpx.Timeout(10.0, connect=5.0)
    limits = httpx.Limits(max_connections=4, max_keepalive_connections=0, keepalive_expiry=0.0)
    async with httpx.AsyncClient(
        base_url=origin,
        headers={"Connection": "close"},
        follow_redirects=False,
        timeout=timeout,
        limits=limits,
        transport=transport,
    ) as client:
        try:
            auth = await authenticate_tp_link_mr_rsa_aes_session(client, password=password)
        except TPLinkMRWebAuthenticationError as exc:
            print(f"authentication=FAIL code={str(exc)}")
            return 2
        except httpx.HTTPError as exc:
            print(f"authentication=FAIL transport_error={type(exc).__name__}")
            return 2

        protocol = auth.protocol_session
        print(f"authentication=PASS family={protocol.family} landing={auth.landing_path}")

        encrypted_data = _aes_cbc_base64(
            _READ_ONLY_QUERY,
            key=protocol.aes_key,
            iv=protocol.aes_iv,
        )
        browser_shape = client.build_request(
            "POST",
            "/cgi_gdpr",
            headers={
                "Accept": "*/*",
                "Content-Type": "text/plain",
                "Origin": origin,
                "Referer": origin + "/",
                "TokenID": "DIAGNOSTIC_PLACEHOLDER",
            },
            content=f"sign={'0' * 256}\r\ndata={encrypted_data}\r\n".encode("ascii"),
        )
        upstream_request = protocol.prepare_request(browser_shape)
        shape = summarize_request(upstream_request)
        print(
            "request_shape="
            f"method:{shape.method},path:{shape.path},content_type:{shape.content_type},"
            f"token_present:{_yn(shape.token_id_present)},cookie_present:{_yn(shape.cookie_present)},"
            f"body_bytes:{shape.body_bytes},fields:{','.join(shape.field_names)},"
            f"sign_len:{shape.sign_length},sign_hex:{_yn(shape.sign_is_hex)},"
            f"data_len:{shape.data_length},data_base64:{_yn(shape.data_is_base64)},"
            f"cipher_bytes:{shape.cipher_bytes},block_aligned:{_yn(shape.cipher_block_aligned)}"
        )

        started = time.monotonic()
        try:
            response = await client.send(upstream_request)
        except httpx.RemoteProtocolError:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            print(f"cgi_gdpr=FAIL error=RemoteProtocolError elapsed_ms={elapsed_ms}")
            print("diagnosis=UPSTREAM_WIRE_CONTRACT_OR_DEVICE_HTTP_BEHAVIOR")
            return 3
        except httpx.HTTPError as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            print(f"cgi_gdpr=FAIL error={type(exc).__name__} elapsed_ms={elapsed_ms}")
            return 3

        elapsed_ms = int((time.monotonic() - started) * 1000)
        body = await response.aread()
        print(
            f"cgi_gdpr=response status:{response.status_code},"
            f"content_type:{response.headers.get('content-type', '')},body_bytes:{len(body)},"
            f"elapsed_ms:{elapsed_ms}"
        )
        if response.status_code != 200:
            print("diagnosis=UPSTREAM_HTTP_REJECTION")
            return 4

        decrypt_ok, plaintext_bytes, plaintext_lines = _decrypt_response_shape(
            body,
            key=protocol.aes_key,
            iv=protocol.aes_iv,
        )
        print(
            "response_crypto="
            f"aes_decrypt:{_yn(decrypt_ok)},plaintext_bytes:{plaintext_bytes},"
            f"plaintext_lines:{plaintext_lines}"
        )
        if not decrypt_ok:
            print("diagnosis=POST_AUTH_CRYPTO_CONTRACT_MISMATCH")
            return 5

        print("diagnosis=GATEWAY_TO_ROUTER_POST_AUTH_CONTRACT_PASS")
        print("next_focus=BROWSER_PROTOCOL_BOOTSTRAP_OR_BROWSER_REQUEST_BRIDGE")
        return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Bounded read-only TP-Link MR600 post-auth Web diagnostic. "
            "The password is prompted locally and is never accepted as a command-line argument."
        )
    )
    parser.add_argument("--host", default="192.168.0.200", help="Registered MR600 management IP")
    parser.add_argument("--port", type=int, default=80, help="MR600 HTTP management port")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        host = _validate_host(args.host)
    except ValueError as exc:
        print(f"target=FAIL code={str(exc)}")
        return 64
    password = getpass.getpass("MR600 password (local input; not echoed): ")
    if not password:
        print("authentication=FAIL code=PASSWORD_REQUIRED")
        return 64
    try:
        return asyncio.run(diagnose(host, password, port=args.port))
    finally:
        password = ""


if __name__ == "__main__":
    raise SystemExit(main())
