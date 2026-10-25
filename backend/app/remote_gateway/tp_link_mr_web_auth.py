from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import string
import time
from dataclasses import dataclass
from typing import ClassVar

import httpx
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .web_protocol_session import WebProtocolSessionError


TP_LINK_MR_AUTH_FAMILY = "TP_LINK_MR_RSA_AES"
_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


class TPLinkMRWebAuthenticationError(RuntimeError):
    pass


@dataclass(frozen=True)
class TPLinkMRKeyMaterial:
    modulus_hex: str
    exponent_hex: str
    sequence: int


@dataclass(frozen=True)
class TPLinkMRLoginPayload:
    encrypted_data: str
    signature: str
    aes_key: str
    aes_iv: str
    credential_hash: str


@dataclass
class TPLinkMRProtocolSession:
    """Ephemeral post-login state for the MR RSA/AES Web protocol family.

    The password and its derived credential hash stay gateway-side. The proxied
    browser receives only the per-login AES key/IV needed to encrypt/decrypt the
    vendor's post-auth payloads. Browser-generated /cgi_gdpr signatures are never
    trusted: the gateway replaces them using the retained credential hash and
    exact login-time sequence/RSA material before forwarding to the device.
    """

    family: ClassVar[str] = TP_LINK_MR_AUTH_FAMILY
    keys: TPLinkMRKeyMaterial
    aes_key: str
    aes_iv: str
    credential_hash: str
    token: str

    def _cgi_gdpr_signature(self, encrypted_data: str) -> str:
        plaintext = f"h={self.credential_hash}&s={self.keys.sequence + len(encrypted_data)}"
        return _raw_rsa_hex_blocks(
            plaintext,
            modulus_hex=self.keys.modulus_hex,
            exponent_hex=self.keys.exponent_hex,
        )

    @staticmethod
    def _cgi_gdpr_data(body: bytes, request: httpx.Request) -> str:
        try:
            text = body.decode("ascii")
        except UnicodeDecodeError as exc:
            raise WebProtocolSessionError(
                "WEB_PROTOCOL_SESSION_REQUEST_INVALID",
                request=request,
            ) from exc
        values: dict[str, str] = {}
        for line in text.replace("\r\n", "\n").split("\n"):
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in {"sign", "data"}:
                values[key] = value.strip()
        encrypted_data = values.get("data", "")
        if not encrypted_data or len(encrypted_data) > 16_777_216:
            raise WebProtocolSessionError(
                "WEB_PROTOCOL_SESSION_REQUEST_INVALID",
                request=request,
            )
        try:
            base64.b64decode(encrypted_data, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise WebProtocolSessionError(
                "WEB_PROTOCOL_SESSION_REQUEST_INVALID",
                request=request,
            ) from exc
        return encrypted_data

    def _browser_ciphertext_matches_session(self, encrypted_data: str) -> bool:
        """Validate browser ciphertext structurally without exposing plaintext.

        The MR600 will close or destabilize its HTTP service when it receives a
        /cgi_gdpr payload encrypted with a different AES session. FTTW therefore
        verifies that browser-generated ciphertext decrypts under the exact
        gateway-retained login key/IV before it is ever forwarded to the router.
        """

        try:
            ciphertext = base64.b64decode(encrypted_data, validate=True)
            if not ciphertext or len(ciphertext) % 16:
                return False
            decryptor = Cipher(
                algorithms.AES(self.aes_key.encode("ascii")),
                modes.CBC(self.aes_iv.encode("ascii")),
            ).decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
            plaintext.decode("utf-8")
        except Exception:
            return False
        return bool(plaintext)

    def prepare_request(self, request: httpx.Request) -> httpx.Request:
        if request.method.upper() != "POST" or request.url.path != "/cgi_gdpr":
            return request

        encrypted_data = self._cgi_gdpr_data(request.content, request)
        if not self._browser_ciphertext_matches_session(encrypted_data):
            raise WebProtocolSessionError(
                "WEB_PROTOCOL_SESSION_BROWSER_CRYPTO_MISMATCH",
                request=request,
            )
        signature = self._cgi_gdpr_signature(encrypted_data)
        body = f"sign={signature}\r\ndata={encrypted_data}\r\n".encode("ascii")

        headers = httpx.Headers(request.headers)
        headers["Content-Type"] = "text/plain"
        headers["TokenID"] = self.token
        for name in ("Content-Length", "Transfer-Encoding"):
            if name in headers:
                del headers[name]
        return httpx.Request(
            request.method,
            request.url,
            headers=headers,
            content=body,
            extensions=dict(request.extensions),
        )

    def _browser_bootstrap_script(self) -> str:
        # Deliberately exclude the credential hash and password. The browser is
        # given a dummy hash only so the vendor's synchronous AESEncrypt routine
        # can construct its normal request object; FTTW replaces that signature
        # server-side before /cgi_gdpr reaches the router.
        dummy_hash = "0" * 32
        return f"""<script id=\"fttw-web-protocol-session-bootstrap\">(function(){{
'use strict';
const KEY={json.dumps(self.aes_key)};
const IV={json.dumps(self.aes_iv)};
const NN={json.dumps(self.keys.modulus_hex)};
const EE={json.dumps(self.keys.exponent_hex)};
const SEQ={self.keys.sequence};
const DUMMY_HASH={json.dumps(dummy_hash)};
function setState(enc){{
  if(!enc)return false;
  try{{
    if(typeof enc.setAESStringKey==='function')enc.setAESStringKey('key='+KEY+'&iv='+IV);
    else if(typeof enc.setAESKey==='function')enc.setAESKey(KEY,IV);
    else if(enc.aes&&typeof enc.aes.setKey==='function')enc.aes.setKey(KEY,IV);
    else return false;
    if(typeof enc.setRSAKey==='function')enc.setRSAKey(NN,EE);
    if(typeof enc.setSeq==='function')enc.setSeq(SEQ);
    if(typeof enc.setHashString==='function')enc.setHashString(DUMMY_HASH);
    else enc._hash=DUMMY_HASH;
    return true;
  }}catch(_err){{return false;}}
}}
function markWrapped(fn){{
  try{{Object.defineProperty(fn,'__fttwSessionWrapped',{{value:true}});}}catch(_err){{fn.__fttwSessionWrapped=true;}}
  return fn;
}}
function wrapBefore(enc,name){{
  const original=enc&&enc[name];
  if(typeof original!=='function'||original.__fttwSessionWrapped)return;
  enc[name]=markWrapped(function(){{setState(enc);return original.apply(this,arguments);}});
}}
function wrapAfter(enc,name){{
  const original=enc&&enc[name];
  if(typeof original!=='function'||original.__fttwSessionWrapped)return;
  enc[name]=markWrapped(function(){{const result=original.apply(this,arguments);setState(enc);return result;}});
}}
function prepareEncryptor(enc){{
  if(!enc||!setState(enc))return enc;
  try{{
    wrapBefore(enc,'AESEncrypt');
    wrapBefore(enc,'AESDecrypt');
    wrapAfter(enc,'genAESKey');
  }}catch(_err){{}}
  return enc;
}}
function wrapManagerFactory(manager,name){{
  const original=manager&&manager[name];
  if(typeof original!=='function'||original.__fttwSessionWrapped)return;
  manager[name]=markWrapped(function(){{
    const enc=original.apply(this,arguments);
    return prepareEncryptor(enc);
  }});
}}
function prepareManager(jq){{
  const manager=jq&&jq.encrypt&&jq.encrypt.encryptManager;
  if(!manager)return false;
  try{{
    wrapManagerFactory(manager,'genEncryptor');
    wrapManagerFactory(manager,'getEncryptor');
  }}catch(_err){{return false;}}
  return true;
}}
function applySession(){{
  const jq=window.jQuery||window.$;
  if(!jq)return false;
  prepareManager(jq);
  const enc=jq.Iencryptor;
  if(!enc)return false;
  prepareEncryptor(enc);
  return true;
}}
applySession();
let attempts=0;
const timer=setInterval(function(){{applySession();if(++attempts>=250)clearInterval(timer);}},20);
document.addEventListener('DOMContentLoaded',applySession,{{once:true}});
window.addEventListener('load',applySession,{{once:true}});
}})();</script>"""

    @staticmethod
    def _inject_browser_bootstrap(text: str, injection: str) -> str:
        """Inject after TP-Link crypto libraries but before inline page startup.

        MR firmware commonly creates/restores ``$.Iencryptor`` in an inline
        script immediately after loading encrypt.js/tpEncrypt.js/lib.js. Waiting
        until ``</body>`` is too late because that same inline startup can issue
        the first encrypted /cgi_gdpr call synchronously. Place the bridge after
        the last known crypto/runtime library so its manager factory wrappers are
        installed before the vendor creates or restores the encryptor.
        """

        library = re.compile(
            r"<script\b[^>]*\bsrc\s*=\s*([\"'])[^\"']*(?:encrypt|tpencrypt|cryptojs|lib|jquery\.tp)[^\"']*\.js(?:\?[^\"']*)?\1[^>]*>\s*</script\s*>",
            re.IGNORECASE,
        )
        matches = list(library.finditer(text))
        if matches:
            offset = matches[-1].end()
            return text[:offset] + injection + text[offset:]
        if re.search(r"</body\s*>", text, re.IGNORECASE):
            return re.sub(
                r"</body\s*>",
                lambda match: injection + match.group(0),
                text,
                count=1,
                flags=re.IGNORECASE,
            )
        return text + injection

    async def prepare_response(
        self,
        request: httpx.Request,
        response: httpx.Response,
    ) -> httpx.Response:
        if (
            request.method.upper() != "GET"
            or request.url.path != "/"
            or response.status_code >= 400
            or "text/html" not in response.headers.get("content-type", "").lower()
        ):
            return response

        body = await response.aread()
        charset = response.encoding or "utf-8"
        try:
            text = body.decode(charset, errors="replace")
        except LookupError:
            text = body.decode("utf-8", errors="replace")
        marker = 'id="fttw-web-protocol-session-bootstrap"'
        if marker not in text:
            text = self._inject_browser_bootstrap(text, self._browser_bootstrap_script())

        headers = httpx.Headers(response.headers)
        for name in ("Content-Length", "Content-Encoding"):
            if name in headers:
                del headers[name]
        return httpx.Response(
            status_code=response.status_code,
            headers=headers,
            content=text.encode("utf-8"),
            request=request,
            extensions=dict(response.extensions),
        )


@dataclass(frozen=True)
class TPLinkMRAuthenticationResult:
    landing_path: str
    protocol_session: TPLinkMRProtocolSession


def looks_like_tp_link_mr_rsa_aes(page_text: str) -> bool:
    """Recognize the legacy MR-series browser crypto contract without secrets.

    The markers are served by the device login page itself. Detection alone is
    not considered proof: callers must still complete the bounded getParm/login
    exchange successfully before persisting a discovered template.
    """

    lowered = page_text[:2_000_000].lower()
    required = ("cgi/getparm", "cgi/login")
    crypto_markers = ("tpencrypt", "aesencrypt", "iencryptor", "cryptojs")
    return all(marker in lowered for marker in required) and any(marker in lowered for marker in crypto_markers)


def _origin(client: httpx.AsyncClient) -> str:
    return str(client.base_url).rstrip("/")


def _browser_headers(client: httpx.AsyncClient, *, include_origin: bool = False) -> dict[str, str]:
    origin = _origin(client)
    headers = {
        "Accept": "*/*",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Referer": f"{origin}/",
        "User-Agent": _BROWSER_USER_AGENT,
    }
    if include_origin:
        headers["Origin"] = origin
    return headers


def _extract_assignment(text: str, name: str) -> str | None:
    match = re.search(rf"\bvar\s+{re.escape(name)}\s*=\s*\"([^\"]+)\"\s*;", text)
    return match.group(1) if match else None


def _parse_ret(text: str) -> int | None:
    match = re.search(r"\$\.ret\s*=\s*(-?\d+)\s*;", text)
    if match:
        return int(match.group(1))
    match = re.search(r'\"ret\"\s*:\s*(-?\d+)', text)
    return int(match.group(1)) if match else None


def _json_key_material(text: str) -> tuple[str | None, str | None, str | None, int | None] | None:
    try:
        payload = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if "eccPubKey_X_HEX" in payload or "eccPubKey_Y_HEX" in payload:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_VENDOR_CRYPTO_UNSUPPORTED")

    nn_value = payload.get("nn")
    ee_value = payload.get("ee")
    seq_value = payload.get("seq")
    ret_value = payload.get("ret")
    nn = str(nn_value).strip() if nn_value is not None else None
    ee = str(ee_value).strip() if ee_value is not None else None
    seq = str(seq_value).strip() if seq_value is not None else None
    try:
        ret = int(ret_value) if ret_value is not None else None
    except (TypeError, ValueError):
        ret = None
    return nn, ee, seq, ret


def _parse_key_material(text: str) -> TPLinkMRKeyMaterial:
    # Firmware generations expose the same RSA/AES contract either as legacy
    # JavaScript assignments or as a small JSON document. Treat both as one
    # protocol family, but never guess when the device advertises another
    # cryptographic family such as ECIES.
    json_values = _json_key_material(text)
    if json_values is not None:
        nn, ee, seq, ret = json_values
    else:
        if "eccPubKey_X_HEX" in text or "eccPubKey_Y_HEX" in text:
            raise TPLinkMRWebAuthenticationError("WEB_AUTH_VENDOR_CRYPTO_UNSUPPORTED")
        nn = _extract_assignment(text, "nn")
        ee = _extract_assignment(text, "ee")
        seq = _extract_assignment(text, "seq")
        ret = _parse_ret(text)

    if ret not in {None, 0}:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_LOGIN_REQUEST_REJECTED")
    if not nn or not ee or not seq or not seq.isdecimal():
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_VENDOR_CRYPTO_UNSUPPORTED")
    if not re.fullmatch(r"[0-9A-Fa-f]+", nn) or len(nn) % 2 or len(nn) < 128 or len(nn) > 512:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_VENDOR_CRYPTO_UNSUPPORTED")
    if not re.fullmatch(r"[0-9A-Fa-f]{2,16}", ee):
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_VENDOR_CRYPTO_UNSUPPORTED")
    return TPLinkMRKeyMaterial(modulus_hex=nn, exponent_hex=ee, sequence=int(seq))


def _ascii_session_material(length: int = 16) -> str:
    # TP-Link's browser client uses 16 printable ASCII characters for both the
    # AES-128 key and CBC IV. Random digits preserve that wire representation.
    return "".join(secrets.choice(string.digits) for _ in range(length))


def _aes_cbc_base64(plaintext: str, *, key: str, iv: str) -> str:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(key.encode("ascii")),
        modes.CBC(iv.encode("ascii")),
    ).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(encrypted).decode("ascii")


def _raw_rsa_hex_blocks(plaintext: str, *, modulus_hex: str, exponent_hex: str) -> str:
    modulus = int(modulus_hex, 16)
    exponent = int(exponent_hex, 16)
    block_size = len(modulus_hex) // 2
    source = plaintext.encode("utf-8")
    output: list[str] = []
    for offset in range(0, len(source), block_size):
        block = source[offset : offset + block_size].ljust(block_size, b"\x00")
        value = int.from_bytes(block, "big")
        if value >= modulus:
            raise TPLinkMRWebAuthenticationError("WEB_AUTH_VENDOR_CRYPTO_UNSUPPORTED")
        encrypted = pow(value, exponent, modulus)
        output.append(encrypted.to_bytes(block_size, "big").hex())
    return "".join(output)


def _build_login_payload(password: str, keys: TPLinkMRKeyMaterial) -> TPLinkMRLoginPayload:
    # The password-only MR Web UI hides the account name from the operator, but
    # TP-Link's own client-side protocol authenticates its built-in admin account.
    protocol_account = "admin"
    aes_key = _ascii_session_material()
    aes_iv = _ascii_session_material()
    encrypted_data = _aes_cbc_base64(
        f"{protocol_account}\n{password}",
        key=aes_key,
        iv=aes_iv,
    )
    credential_hash = hashlib.new(
        "md5",
        f"{protocol_account}{password}".encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    sign_plaintext = (
        f"key={aes_key}&iv={aes_iv}&h={credential_hash}"
        f"&s={keys.sequence + len(encrypted_data)}"
    )
    signature = _raw_rsa_hex_blocks(
        sign_plaintext,
        modulus_hex=keys.modulus_hex,
        exponent_hex=keys.exponent_hex,
    )
    return TPLinkMRLoginPayload(
        encrypted_data=encrypted_data,
        signature=signature,
        aes_key=aes_key,
        aes_iv=aes_iv,
        credential_hash=credential_hash,
    )


async def authenticate_tp_link_mr_rsa_aes_session(
    client: httpx.AsyncClient,
    *,
    password: str,
) -> TPLinkMRAuthenticationResult:
    """Authenticate MR RSA/AES and preserve its ephemeral post-login session."""

    if not password:
        raise TPLinkMRWebAuthenticationError("WEB_AUTHENTICATION_FAILED")

    try:
        initial = await client.get("/", headers=_browser_headers(client), follow_redirects=False)
    except httpx.HTTPError as exc:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_CONNECT_FAILED") from exc
    if initial.status_code >= 500:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_UPSTREAM_FAILURE")
    if initial.status_code >= 400:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_LOGIN_REQUEST_REJECTED")
    if not looks_like_tp_link_mr_rsa_aes(initial.text):
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_MODE_UNSUPPORTED")

    # The vendor browser keeps this pre-auth state entirely client-side. Mirror
    # it inside the gateway-owned cookie jar without exposing it to the operator.
    if "loginErrorShow" not in client.cookies:
        client.cookies.set("loginErrorShow", "1")

    timestamp = int(time.time() * 1000)
    try:
        key_response = await client.get(
            f"/cgi/getParm?_={timestamp}",
            headers=_browser_headers(client),
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_CONNECT_FAILED") from exc
    if key_response.status_code in {401, 403}:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_LOGIN_REQUEST_REJECTED")
    if key_response.status_code >= 500:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_UPSTREAM_FAILURE")
    if key_response.status_code >= 400:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_LOGIN_REQUEST_REJECTED")

    keys = _parse_key_material(key_response.text)
    payload = _build_login_payload(password, keys)
    params = {
        "data": payload.encrypted_data,
        "sign": payload.signature,
        "Action": "1",
        "LoginStatus": "0",
    }
    try:
        login = await client.post(
            "/cgi/login",
            params=params,
            headers=_browser_headers(client),
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_CONNECT_FAILED") from exc
    if login.status_code >= 500:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_UPSTREAM_FAILURE")
    if login.status_code >= 400:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_LOGIN_REQUEST_REJECTED")

    ret = _parse_ret(login.text)
    if ret == 71233:
        raise TPLinkMRWebAuthenticationError("WEB_AUTHENTICATION_FAILED")
    if ret not in {None, 0}:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_LOGIN_REQUEST_REJECTED")

    try:
        landing = await client.get("/", headers=_browser_headers(client), follow_redirects=False)
    except httpx.HTTPError as exc:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_CONNECT_FAILED") from exc
    if landing.status_code >= 500:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_UPSTREAM_FAILURE")
    if landing.status_code >= 400:
        raise TPLinkMRWebAuthenticationError("WEB_AUTH_LOGIN_REQUEST_REJECTED")

    token_match = re.search(r'\bvar\s+token\s*=\s*"([^\"]+)"\s*;', landing.text[:2_000_000])
    login_still_present = "pc-login-password" in landing.text or "pc-login-btn" in landing.text
    if not token_match or login_still_present or not client.cookies:
        raise TPLinkMRWebAuthenticationError("WEB_AUTHENTICATION_UNCONFIRMED")

    return TPLinkMRAuthenticationResult(
        landing_path="/",
        protocol_session=TPLinkMRProtocolSession(
            keys=keys,
            aes_key=payload.aes_key,
            aes_iv=payload.aes_iv,
            credential_hash=payload.credential_hash,
            token=token_match.group(1),
        ),
    )


async def authenticate_tp_link_mr_rsa_aes(
    client: httpx.AsyncClient,
    *,
    password: str,
) -> str:
    """Backward-compatible wrapper returning only the safe landing path."""

    result = await authenticate_tp_link_mr_rsa_aes_session(client, password=password)
    return result.landing_path
