from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import logging
import re
import secrets
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator
from urllib.parse import urljoin, urlsplit, urlunsplit
from uuid import UUID

import httpx
from fastapi import APIRouter, Header, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from sqlalchemy import select
from websockets.asyncio.client import connect as websocket_connect
from websockets.exceptions import WebSocketException

from ..db.session import AsyncSessionLocal
from ..models import AuthSession, Device, DeviceIP, DeviceRemoteAccessProfile, RemoteAccessSession, User
from ..security.sessions import SESSION_IDLE_TIMEOUT_MINUTES
from ..services.audit import record_audit
from ..services.remote_access import hash_remote_ticket, profile_web_port, web_profile_is_ready
from ..settings import settings
from .secrets import RemoteAccessSecretError, resolve_secret_reference


logger = logging.getLogger("fttw.remote_gateway.web")
router = APIRouter()
COOKIE_NAME = "fttw_web_proxy_session"
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailers", "transfer-encoding", "upgrade",
}
_BROWSER_RESPONSE_DROP = _HOP_BY_HOP | {
    "set-cookie", "content-length", "content-encoding", "content-security-policy",
    "content-security-policy-report-only", "x-frame-options",
}
_REWRITE_CONTENT_TYPES = (
    "text/html", "text/css", "application/javascript", "text/javascript",
    "application/json", "application/xml", "text/xml", "image/svg+xml",
)
_URL_ATTR_RE = re.compile(
    r"(?P<prefix>\b(?:href|src|action|formaction|poster|data)\s*=\s*)(?P<quote>[\"'])(?P<url>.*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
_SRCSET_RE = re.compile(
    r"(?P<prefix>\bsrcset\s*=\s*)(?P<quote>[\"'])(?P<value>.*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
_CSS_URL_RE = re.compile(r"url\(\s*(?P<quote>[\"']?)(?P<url>[^)\"']+)(?P=quote)\s*\)", re.IGNORECASE)
_CSS_IMPORT_RE = re.compile(r"(@import\s+)(?P<quote>[\"'])(?P<url>.*?)(?P=quote)", re.IGNORECASE)
_STYLE_TAG_RE = re.compile(
    r"(?P<open><style\b[^>]*>)(?P<body>.*?)(?P<close></style\s*>)",
    re.IGNORECASE | re.DOTALL,
)
_STYLE_ATTR_RE = re.compile(
    r"(?P<prefix>\bstyle\s*=\s*)(?P<quote>[\"'])(?P<value>.*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
_META_REFRESH_RE = re.compile(
    r"(?P<prefix>content\s*=\s*[\"'][^\"']*?url\s*=\s*)(?P<url>[^\"';>\s]+)",
    re.IGNORECASE,
)
_HTML_TAG_RE = re.compile(r"</?[A-Za-z][^>]*>|<![^>]*>|<\?[^>]*\?>", re.DOTALL)
_SCRIPT_BLOCK_RE = re.compile(r"(?P<open><script\b[^>]*>)(?P<body>.*?)(?P<close></script\s*>)", re.IGNORECASE | re.DOTALL)


@dataclass
class WebProxyState:
    handle: str
    session_id: UUID
    auth_session_id: UUID
    device_id: UUID
    target_scheme: str
    target_host: str
    target_port: int
    tls_mode: str
    ssl_context: ssl.SSLContext | bool
    client: httpx.AsyncClient
    activated_at: datetime
    last_touch_monotonic: float = field(default_factory=time.monotonic)

    @property
    def target_origin(self) -> str:
        default = (self.target_scheme == "HTTP" and self.target_port == 80) or (
            self.target_scheme == "HTTPS" and self.target_port == 443
        )
        suffix = "" if default else f":{self.target_port}"
        return f"{self.target_scheme.lower()}://{_url_host(self.target_host)}{suffix}"

    @property
    def proxy_base(self) -> str:
        return f"/web/s/{self.session_id}"


_states: dict[str, WebProxyState] = {}
_states_lock = asyncio.Lock()
_cleanup_task: asyncio.Task | None = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _url_host(host: str) -> str:
    parsed = ipaddress.ip_address(host)
    return f"[{host}]" if parsed.version == 6 else host


def _allowed_fttw_origins() -> set[str]:
    return {value.strip().rstrip("/") for value in settings.remote_access_allowed_origins.split(",") if value.strip()}


def _normalized_http_origin(value: str | None) -> str | None:
    raw = str(value or "").strip()

    if not raw:
        return None

    try:
        parsed = urlsplit(raw)

        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None

        scheme = parsed.scheme.lower()
        default_port = 443 if scheme == "https" else 80
        port = parsed.port or default_port
        host = parsed.hostname.lower()
        host_text = f"[{host}]" if ":" in host else host
        suffix = "" if port == default_port else f":{port}"

        return f"{scheme}://{host_text}{suffix}"

    except ValueError:
        return None


def _validated_opener_origin(
    requested_origin: str | None,
    referer: str | None,
    allowed_origins: set[str],
) -> str | None:
    allowed = {
        normalized
        for value in allowed_origins
        if (normalized := _normalized_http_origin(value)) is not None
    }

    requested = _normalized_http_origin(requested_origin)
    referrer = _normalized_http_origin(referer)

    if requested is not None:
        if requested not in allowed:
            return None

        if (
            referrer is not None
            and referrer in allowed
            and referrer != requested
        ):
            return None

        return requested

    if referrer is not None and referrer in allowed:
        return referrer

    if len(allowed) == 1:
        return next(iter(allowed))

    return None


def _browser_transport_is_secure(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    if settings.remote_access_gateway_external_tls_terminated:
        return request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower() == "https"
    return False


def _gateway_origin_from_request(request: Request) -> str:
    scheme = request.url.scheme
    if settings.remote_access_gateway_external_tls_terminated:
        forwarded = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
        if forwarded in {"http", "https"}:
            scheme = forwarded
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}".rstrip("/")


def _normalize_pem(value: str) -> str:
    normalized = value.strip().replace("\\n", "\n")
    if "-----BEGIN " not in normalized or "-----END " not in normalized:
        raise RemoteAccessSecretError("REMOTE_ACCESS_TLS_MATERIAL_INVALID")
    return normalized + ("\n" if not normalized.endswith("\n") else "")


def build_web_ssl_context(profile: DeviceRemoteAccessProfile) -> ssl.SSLContext | bool:
    if profile.web_scheme == "HTTP":
        return False
    if profile.web_tls_mode == "SYSTEM":
        return ssl.create_default_context()
    if profile.web_tls_mode == "PRIVATE_CA":
        pem = _normalize_pem(resolve_secret_reference(profile.web_tls_ca_reference))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(cadata=pem)
        return context
    if profile.web_tls_mode == "PINNED_CERT":
        pem = _normalize_pem(resolve_secret_reference(profile.web_tls_pinned_certificate_reference))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # A small class of legacy devices use an otherwise reachable HTTPS stack
        # with an end-entity RSA key rejected by OpenSSL's default security level.
        # Compatibility is deliberately per-device and only legal with exact
        # pinned-certificate trust; SYSTEM/PRIVATE_CA trust is never weakened.
        if profile.web_tls_compat_profile == "LEGACY_WEAK_CERT_KEY":
            context.set_ciphers("DEFAULT:@SECLEVEL=1")
        elif profile.web_tls_compat_profile != "MODERN":
            raise RemoteAccessSecretError("REMOTE_ACCESS_WEB_TLS_COMPAT_INVALID")
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        context.load_verify_locations(cadata=pem)
        if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
            context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        return context
    raise RemoteAccessSecretError("REMOTE_ACCESS_WEB_TLS_MODE_INVALID")


def validate_management_target(value: str) -> str:
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("REMOTE_ACCESS_WEB_TARGET_INVALID") from exc
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved:
        raise ValueError("REMOTE_ACCESS_WEB_TARGET_FORBIDDEN")
    return str(parsed)


def _authority(url: str) -> tuple[str, str, int] | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.hostname or parts.scheme.lower() not in {"http", "https", "ws", "wss"}:
        return None
    scheme = parts.scheme.lower()
    normalized_scheme = "https" if scheme == "wss" else "http" if scheme == "ws" else scheme
    default_port = 443 if normalized_scheme == "https" else 80
    try:
        port = parts.port or default_port
    except ValueError:
        return None
    return normalized_scheme, parts.hostname, port


def _target_authority(state: WebProxyState) -> tuple[str, str, int]:
    return state.target_scheme.lower(), state.target_host, state.target_port


def _browser_ws_origin(browser_origin: str) -> str:
    parts = urlsplit(browser_origin)
    return urlunsplit(("wss" if parts.scheme == "https" else "ws", parts.netloc, "", "", ""))


def rewrite_reference(
    value: str,
    state: WebProxyState,
    browser_origin: str,
    base_target_url: str | None = None,
) -> str:
    """Map a vendor URL into the active proxy session without target escape.

    Relative references must be resolved against the *device response URL*, not
    the browser's gateway URL.  Legacy GUIs commonly emit paths such as
    ``../css/main.css`` and ``./js/app.js``; leaving those untouched makes the
    browser resolve them outside ``/web/s/<session>/`` and breaks rendering.
    """
    raw = html.unescape(value.strip())
    lowered = raw.lower()
    if not raw or raw.startswith("#") or lowered.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:")):
        return value

    if raw.startswith("//"):
        raw = f"{state.target_scheme.lower()}:{raw}"
        lowered = raw.lower()

    is_absolute = lowered.startswith(("http://", "https://", "ws://", "wss://"))
    if is_absolute:
        resolved = raw
    elif raw.startswith("/"):
        return f"{state.proxy_base}{raw}"
    else:
        resolved = urljoin(base_target_url or (state.target_origin + "/"), raw)

    authority = _authority(resolved)
    if authority != _target_authority(state):
        return "#fttw-blocked-external"
    parts = urlsplit(resolved)
    path = parts.path or "/"
    if not is_absolute:
        return f"{state.proxy_base}{path}" + (f"?{parts.query}" if parts.query else "") + (f"#{parts.fragment}" if parts.fragment else "")
    if parts.scheme.lower() in {"ws", "wss"}:
        base = _browser_ws_origin(browser_origin)
    else:
        base = browser_origin
    return f"{base}{state.proxy_base}{path}" + (f"?{parts.query}" if parts.query else "") + (f"#{parts.fragment}" if parts.fragment else "")


def _rewrite_srcset(
    value: str,
    state: WebProxyState,
    browser_origin: str,
    base_target_url: str | None = None,
) -> str:
    items: list[str] = []
    for item in value.split(","):
        bits = item.strip().split()
        if not bits:
            continue
        bits[0] = rewrite_reference(bits[0], state, browser_origin, base_target_url)
        items.append(" ".join(bits))
    return ", ".join(items)


def _rewrite_css_fragment(
    text: str,
    state: WebProxyState,
    browser_origin: str,
    base_target_url: str | None = None,
) -> str:
    text = _CSS_URL_RE.sub(
        lambda m: f"url({m.group('quote')}{rewrite_reference(m.group('url').strip(), state, browser_origin, base_target_url)}{m.group('quote')})",
        text,
    )
    return _CSS_IMPORT_RE.sub(
        lambda m: f"{m.group(1)}{m.group('quote')}{rewrite_reference(m.group('url'), state, browser_origin, base_target_url)}{m.group('quote')}",
        text,
    )


def _runtime_rewrite_script(state: WebProxyState, browser_origin: str) -> str:
    target = state.target_origin
    proxy_base = state.proxy_base
    return f"""<script>(function(){{
'use strict';
const TARGET={json.dumps(target)};
const BASE={json.dumps(proxy_base)};
const ABS={json.dumps(browser_origin + proxy_base)};
const WSABS={json.dumps(_browser_ws_origin(browser_origin) + proxy_base)};
const TARGETWS=TARGET.replace(/^https:/,'wss:').replace(/^http:/,'ws:');
const SESSION_UUID_RE=/^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[1-5][0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$/i;
const SESSION_MARKER_KEY='fttw.remoteWeb.sessionBase';
try{{sessionStorage.setItem(SESSION_MARKER_KEY,BASE);window.name='fttw-remote-web:'+BASE;}}catch(_err){{}}
function currentTargetUrl(){{
  const path=window.location.pathname;
  const suffix=(path===BASE||path.startsWith(BASE+'/'))?(path.slice(BASE.length)||'/'):'/';
  return TARGET+suffix+window.location.search;
}}
function repairOrphanProxyPath(parsed){{
  if(parsed.origin!==window.location.origin||!parsed.pathname.startsWith('/web/s/'))return null;
  if(parsed.pathname===BASE||parsed.pathname.startsWith(BASE+'/'))return parsed.pathname+parsed.search+parsed.hash;
  const tail=parsed.pathname.slice('/web/s/'.length);
  const first=(tail.split('/',1)[0]||'').trim();
  // Never retarget another valid remote-session UUID. The compatibility repair
  // applies only to legacy relative paths such as /web/s/js/... created when
  // '../js/...' is resolved by the browser before an asynchronous observer runs.
  if(SESSION_UUID_RE.test(first))return null;
  return BASE+'/'+tail+parsed.search+parsed.hash;
}}
function mapUrl(value){{
  if(typeof value!=='string'||!value)return value;
  if(value.startsWith('#')||/^(?:data|blob|javascript|mailto|tel):/i.test(value))return value;
  try{{
    const browserParsed=new URL(value,window.location.href);
    if(browserParsed.origin===window.location.origin&&(browserParsed.pathname===BASE||browserParsed.pathname.startsWith(BASE+'/')))
      return browserParsed.pathname+browserParsed.search+browserParsed.hash;
    const repaired=repairOrphanProxyPath(browserParsed);
    if(repaired)return repaired;
    if(browserParsed.origin===window.location.origin&&browserParsed.pathname.startsWith('/web/s/'))
      return '#fttw-blocked-external';
    // Vendor scripts frequently construct root-absolute URLs from location.origin
    // (for example /cgi/getParm). Inside the isolated gateway origin those would
    // otherwise escape /web/s/<session>/ and hit the gateway root. Treat any
    // same-origin vendor URL outside an existing remote-session namespace as a
    // device URL and contain it inside this exact session.
    if(browserParsed.origin===window.location.origin)
      return BASE+browserParsed.pathname+browserParsed.search+browserParsed.hash;
    const parsed=new URL(value,currentTargetUrl());
    if(parsed.origin===TARGET)return ABS+parsed.pathname+parsed.search+parsed.hash;
  }}catch(_err){{}}
  return value;
}}
const nativeSetAttribute=Element.prototype.setAttribute;
const URL_ATTRS=new Set(['href','src','action','formaction','poster','data']);
Element.prototype.setAttribute=function(name,value){{
  const key=String(name||'').toLowerCase();
  if(URL_ATTRS.has(key)&&value!=null)value=mapUrl(String(value));
  else if(key==='srcset'&&value!=null)value=String(value).split(',').map(x=>{{const p=x.trim().split(/\\s+/);if(p[0])p[0]=mapUrl(p[0]);return p.join(' ');}}).join(', ');
  return nativeSetAttribute.call(this,name,value);
}};
function patchUrlProperty(proto,prop,mapper){{
  if(!proto)return;
  const descriptor=Object.getOwnPropertyDescriptor(proto,prop);
  if(!descriptor||typeof descriptor.set!=='function'||typeof descriptor.get!=='function')return;
  try{{
    Object.defineProperty(proto,prop,{{
      configurable:descriptor.configurable,
      enumerable:descriptor.enumerable,
      get:descriptor.get,
      set:function(value){{return descriptor.set.call(this,mapper(String(value)));}}
    }});
  }}catch(_err){{}}
}}
for(const [proto,prop] of [
  [window.HTMLScriptElement?.prototype,'src'],
  [window.HTMLImageElement?.prototype,'src'],
  [window.HTMLLinkElement?.prototype,'href'],
  [window.HTMLAnchorElement?.prototype,'href'],
  [window.HTMLFormElement?.prototype,'action'],
  [window.HTMLInputElement?.prototype,'formAction'],
  [window.HTMLButtonElement?.prototype,'formAction'],
  [window.HTMLSourceElement?.prototype,'src'],
  [window.HTMLVideoElement?.prototype,'poster'],
  [window.HTMLObjectElement?.prototype,'data'],
  [window.HTMLIFrameElement?.prototype,'src']
])patchUrlProperty(proto,prop,mapUrl);
const nativeFetch=window.fetch.bind(window);
window.fetch=function(input,init){{
  if(typeof input==='string')return nativeFetch(mapUrl(input),init);
  if(input instanceof Request)return nativeFetch(new Request(mapUrl(input.url),input),init);
  return nativeFetch(input,init);
}};
const nativeOpen=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(method,url,...rest){{return nativeOpen.call(this,method,mapUrl(String(url)),...rest);}};
function mapWsUrl(value){{
  if(typeof value!=='string'||!value)return value;
  try{{
    const parsed=new URL(value,currentTargetUrl().replace(/^https:/,'wss:').replace(/^http:/,'ws:'));
    if(parsed.origin===TARGETWS)return WSABS+parsed.pathname+parsed.search+parsed.hash;
  }}catch(_err){{}}
  return value;
}}
const NativeWebSocket=window.WebSocket;
window.WebSocket=function(url,protocols){{const mapped=mapWsUrl(String(url));return protocols===undefined?new NativeWebSocket(mapped):new NativeWebSocket(mapped,protocols);}};
window.WebSocket.prototype=NativeWebSocket.prototype;
const nativeWindowOpen=window.open.bind(window);
window.open=function(url,...rest){{return nativeWindowOpen(url?mapUrl(String(url)):url,...rest);}};
// Vendor alert() is presentation-only and can be rendered without the browser's
// native chrome. Keep confirm()/prompt() untouched because their synchronous
// return semantics are device behavior and must not be faked by an async modal.
let fttwAlertQueue=[]; let fttwAlertOpen=false;
function ensureFttwAlertUi(){{
  let overlay=document.getElementById('fttw-proxy-alert-overlay');
  if(overlay)return overlay;
  const style=document.createElement('style');
  style.textContent='#fttw-proxy-alert-overlay{{position:fixed;inset:0;z-index:2147483647;display:none;align-items:center;justify-content:center;background:rgba(15,23,42,.42);font-family:Inter,Segoe UI,Arial,sans-serif}}#fttw-proxy-alert-box{{width:min(460px,calc(100vw - 40px));background:#fff;color:#253858;border:1px solid #d8e2f0;border-radius:14px;box-shadow:0 20px 56px rgba(15,23,42,.28);overflow:hidden}}#fttw-proxy-alert-head{{padding:16px 20px 10px;font-size:17px;font-weight:700;color:#17365d}}#fttw-proxy-alert-message{{padding:4px 20px 18px;line-height:1.5;white-space:pre-wrap;word-break:break-word}}#fttw-proxy-alert-actions{{display:flex;justify-content:flex-end;padding:12px 16px 16px;border-top:1px solid #edf2f7}}#fttw-proxy-alert-ok{{min-width:86px;border:0;border-radius:8px;padding:9px 18px;background:#2f80d0;color:#fff;font-weight:700;cursor:pointer}}#fttw-proxy-alert-ok:focus{{outline:3px solid rgba(47,128,208,.25);outline-offset:2px}}';
  document.head.appendChild(style);
  overlay=document.createElement('div'); overlay.id='fttw-proxy-alert-overlay'; overlay.setAttribute('role','presentation');
  overlay.innerHTML='<div id="fttw-proxy-alert-box" role="alertdialog" aria-modal="true" aria-labelledby="fttw-proxy-alert-head" aria-describedby="fttw-proxy-alert-message"><div id="fttw-proxy-alert-head">Device message</div><div id="fttw-proxy-alert-message"></div><div id="fttw-proxy-alert-actions"><button id="fttw-proxy-alert-ok" type="button">OK</button></div></div>';
  document.documentElement.appendChild(overlay);
  overlay.querySelector('#fttw-proxy-alert-ok').addEventListener('click',()=>{{overlay.style.display='none';fttwAlertOpen=false;showNextFttwAlert();}});
  return overlay;
}}
function showNextFttwAlert(){{
  if(fttwAlertOpen||!fttwAlertQueue.length)return;
  fttwAlertOpen=true; const overlay=ensureFttwAlertUi(); const message=fttwAlertQueue.shift();
  overlay.querySelector('#fttw-proxy-alert-message').textContent=message; overlay.style.display='flex';
  setTimeout(()=>overlay.querySelector('#fttw-proxy-alert-ok').focus(),0);
}}
window.alert=function(message){{fttwAlertQueue.push(String(message??''));showNextFttwAlert();}};
function rewriteNode(node){{
  if(!(node instanceof Element))return;
  for(const attr of ['href','src','action','formaction','poster','data']){{if(node.hasAttribute(attr))node.setAttribute(attr,node.getAttribute(attr));}}
  if(node.hasAttribute('srcset'))node.setAttribute('srcset',node.getAttribute('srcset'));
  node.querySelectorAll?.('[href],[src],[action],[formaction],[poster],[data],[srcset]').forEach(rewriteNode);
}}
new MutationObserver(records=>records.forEach(r=>r.addedNodes.forEach(rewriteNode))).observe(document.documentElement,{{subtree:true,childList:true,attributes:false}});
}})();</script>"""


def rewrite_text_payload(
    text: str,
    content_type: str,
    state: WebProxyState,
    browser_origin: str,
    base_target_url: str | None = None,
) -> str:
    normalized_type = content_type.lower()
    is_html = "text/html" in normalized_type
    if is_html:
        # Rewrite URL-bearing *HTML tags only*. Running attribute regexes across
        # the complete HTML source can accidentally match JavaScript variables
        # such as `src = "..."` or `data = "..."` inside inline <script> blocks,
        # changing vendor code and in some cases producing invalid JavaScript.
        def rewrite_tag_text(tag):
            tag = _URL_ATTR_RE.sub(
                lambda m: f"{m.group('prefix')}{m.group('quote')}{html.escape(rewrite_reference(m.group('url'), state, browser_origin, base_target_url), quote=True)}{m.group('quote')}",
                tag,
            )
            tag = _SRCSET_RE.sub(
                lambda m: f"{m.group('prefix')}{m.group('quote')}{html.escape(_rewrite_srcset(m.group('value'), state, browser_origin, base_target_url), quote=True)}{m.group('quote')}",
                tag,
            )
            tag = _META_REFRESH_RE.sub(
                lambda m: f"{m.group('prefix')}{rewrite_reference(m.group('url'), state, browser_origin, base_target_url)}",
                tag,
            )
            return _STYLE_ATTR_RE.sub(
                lambda m: f"{m.group('prefix')}{m.group('quote')}{_rewrite_css_fragment(m.group('value'), state, browser_origin, base_target_url)}{m.group('quote')}",
                tag,
            )

        def rewrite_tag(match):
            return rewrite_tag_text(match.group(0))

        # Do not run tag matching over inline JavaScript bodies. Some vendor
        # code contains comparison expressions that look tag-like to regexes.
        chunks = []
        cursor = 0
        for script_match in _SCRIPT_BLOCK_RE.finditer(text):
            chunks.append(_HTML_TAG_RE.sub(rewrite_tag, text[cursor:script_match.start()]))
            chunks.append(rewrite_tag_text(script_match.group("open")))
            chunks.append(script_match.group("body"))
            chunks.append(script_match.group("close"))
            cursor = script_match.end()
        chunks.append(_HTML_TAG_RE.sub(rewrite_tag, text[cursor:]))
        text = "".join(chunks)
        # Restrict CSS URL rewriting to actual CSS regions. Applying the
        # case-insensitive url(...) regex to the whole HTML document would
        # corrupt JavaScript identifiers such as URL() and mapUrl().
        text = _STYLE_TAG_RE.sub(
            lambda m: f"{m.group('open')}{_rewrite_css_fragment(m.group('body'), state, browser_origin, base_target_url)}{m.group('close')}",
            text,
        )
    elif "text/css" in normalized_type:
        text = _rewrite_css_fragment(text, state, browser_origin, base_target_url)

    # Replace remaining explicit device origins in vendor JavaScript/JSON only
    # before injecting FTTW's runtime mapper. Doing this after injection would
    # corrupt the mapper's own TARGET constant and break dynamic relative URLs.
    target = state.target_origin
    proxied = browser_origin + state.proxy_base
    text = text.replace(target, proxied)
    ws_target = target.replace("https://", "wss://").replace("http://", "ws://")
    text = text.replace(ws_target, _browser_ws_origin(browser_origin) + state.proxy_base)

    if is_html:
        injection = _runtime_rewrite_script(state, browser_origin)
        if re.search(r"<head\b", text, re.IGNORECASE):
            text = re.sub(
                r"(<head\b[^>]*>)",
                lambda match: match.group(1) + injection,
                text,
                count=1,
                flags=re.IGNORECASE,
            )
        else:
            text = injection + text
    return text


def _security_headers() -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        "Content-Security-Policy": (
            "default-src 'self' data: blob:; img-src 'self' data: blob:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; "
            "connect-src 'self' ws: wss:; font-src 'self' data:; object-src 'none'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        ),
    }


def _safe_response_headers(upstream: httpx.Response) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in upstream.headers.items():
        if key.lower() in _BROWSER_RESPONSE_DROP or key.lower() == "location":
            continue
        headers[key] = value
    headers.update(_security_headers())
    return headers


def _request_header_value(request_headers, name: str) -> str | None:
    """Read an HTTP request header case-insensitively from any mapping-like object.

    RFC HTTP field names are case-insensitive. Starlette's Headers object already
    provides that behavior, but this gateway helper also accepts ordinary mappings
    used by tests and internal callers without depending on their key casing.
    """
    try:
        value = request_headers.get(name)
    except AttributeError:
        value = None
    if value is not None:
        return value
    wanted = name.lower()
    for key, candidate in request_headers.items():
        if str(key).lower() == wanted:
            return candidate
    return None


def _mapped_upstream_referer(request_headers, state: WebProxyState) -> str:
    """Return a device-origin Referer without trusting a browser destination.

    Some legacy vendor GUIs reject CSS/JavaScript/image requests unless a same-device
    Referer is present. FTTW deliberately sends ``Referrer-Policy: no-referrer`` to the
    browser so the management address is never exposed there. The gateway therefore
    synthesizes the upstream Referer itself. A browser Referer is used only as a path
    hint when it belongs to this exact proxy-session namespace; its host/scheme are
    never forwarded.
    """
    raw = _request_header_value(request_headers, "referer")
    if raw:
        try:
            parsed = urlsplit(raw)
            marker = state.proxy_base.rstrip("/")
            if parsed.path == marker or parsed.path.startswith(marker + "/"):
                suffix = parsed.path[len(marker):] or "/"
                if not suffix.startswith("/"):
                    suffix = "/" + suffix
                mapped = state.target_origin + suffix
                if parsed.query:
                    mapped += "?" + parsed.query
                return mapped
        except (TypeError, ValueError):
            pass
    return state.target_origin + "/"


_UPSTREAM_REQUEST_HEADER_BLOCK = _HOP_BY_HOP | {
    # The gateway owns routing, framing, cookie isolation, and proxy identity.
    "host", "cookie", "content-length", "accept-encoding", "origin", "referer",
    "forwarded", "via", "x-real-ip",
}
_UPSTREAM_REQUEST_HEADER_BLOCK_PREFIXES = (
    "proxy-",
    "x-forwarded-",
    "x-fttw-",
    "x-remote-access-",
)


def _upstream_headers(request_headers, state: WebProxyState) -> dict[str, str]:
    """Forward safe end-to-end browser/device headers without vendor allowlists.

    Device Web UIs commonly use application-defined headers for CSRF/session/bootstrap
    state. A fixed allowlist silently breaks such protocols. The gateway therefore
    preserves end-to-end headers generically while removing hop-by-hop, routing,
    framing, FTTW-internal, forwarding-identity, and browser-cookie headers that are
    owned by the proxy boundary. Origin/Referer are reconstructed against the
    registered device target and upstream cookies remain gateway-side.
    """
    connection_tokens = {
        token.strip().lower()
        for token in str(_request_header_value(request_headers, "connection") or "").split(",")
        if token.strip()
    }
    blocked = _UPSTREAM_REQUEST_HEADER_BLOCK | connection_tokens
    headers: dict[str, str] = {}
    for key, value in request_headers.items():
        lowered = key.lower()
        if lowered in blocked:
            continue
        if any(lowered.startswith(prefix) for prefix in _UPSTREAM_REQUEST_HEADER_BLOCK_PREFIXES):
            continue
        headers[key] = value

    # httpx/device transport owns representation framing. Device compression is
    # disabled because response rewriting requires a deterministic decoded body.
    headers["Accept-Encoding"] = "identity"
    if _request_header_value(request_headers, "origin"):
        headers["Origin"] = state.target_origin
    # Never depend on the browser to reveal or retain the device-management
    # address. Legacy vendor anti-hotlink/CSRF checks receive a same-device
    # Referer synthesized entirely inside the access gateway.
    headers["Referer"] = _mapped_upstream_referer(request_headers, state)
    return headers


async def _audit_web(session: RemoteAccessSession, action: str, description: str, metadata: dict | None = None) -> None:
    async with AsyncSessionLocal() as db:
        fresh = await db.get(RemoteAccessSession, session.id)
        if fresh is None:
            return
        actor = await db.get(User, fresh.actor_user_id) if fresh.actor_user_id else None
        await record_audit(
            db,
            action=action,
            entity_type="Device",
            entity_id=fresh.device_id,
            actor_user_id=fresh.actor_user_id,
            actor_username_snapshot=getattr(actor, "username", None),
            actor_display_name_snapshot=getattr(actor, "display_name", None),
            description=description,
            metadata={"remote_access_session_id": str(fresh.id), **(metadata or {})},
        )
        await db.commit()


async def _mark_web_failed(session_id: UUID, code: str) -> None:
    async with AsyncSessionLocal() as db:
        session = await db.scalar(select(RemoteAccessSession).where(RemoteAccessSession.id == session_id).with_for_update())
        if session is None:
            return
        now = _utcnow()
        if session.status not in {"REVOKED", "CLOSED"}:
            session.status = "FAILED"
            session.ended_at = now
            session.error_message = code[:500]
        actor = await db.get(User, session.actor_user_id) if session.actor_user_id else None
        await record_audit(
            db,
            action="REMOTE_ACCESS_WEB_FAILED",
            entity_type="Device",
            entity_id=session.device_id,
            actor_user_id=session.actor_user_id,
            actor_username_snapshot=getattr(actor, "username", None),
            actor_display_name_snapshot=getattr(actor, "display_name", None),
            description="Brokered native Web-GUI session failed.",
            metadata={"remote_access_session_id": str(session.id), "failure_code": code[:120]},
        )
        await db.commit()


async def _mark_web_ended(session_id: UUID, reason: str) -> None:
    async with AsyncSessionLocal() as db:
        session = await db.scalar(select(RemoteAccessSession).where(RemoteAccessSession.id == session_id).with_for_update())
        if session is None:
            return
        now = _utcnow()
        if session.status == "ACTIVE":
            session.status = "CLOSED"
            session.ended_at = now
        actor = await db.get(User, session.actor_user_id) if session.actor_user_id else None
        await record_audit(
            db,
            action="REMOTE_ACCESS_WEB_ENDED",
            entity_type="Device",
            entity_id=session.device_id,
            actor_user_id=session.actor_user_id,
            actor_username_snapshot=getattr(actor, "username", None),
            actor_display_name_snapshot=getattr(actor, "display_name", None),
            description="Brokered native Web-GUI session ended.",
            metadata={"remote_access_session_id": str(session.id), "reason": reason[:120]},
        )
        await db.commit()


async def _record_web_denied(db, session: RemoteAccessSession, code: str) -> tuple[None, str]:
    actor = await db.get(User, session.actor_user_id) if session.actor_user_id else None
    await record_audit(
        db,
        action="REMOTE_ACCESS_WEB_DENIED",
        entity_type="Device",
        entity_id=session.device_id,
        actor_user_id=session.actor_user_id,
        actor_username_snapshot=getattr(actor, "username", None),
        actor_display_name_snapshot=getattr(actor, "display_name", None),
        description="Brokered native Web-GUI launch was denied.",
        metadata={"remote_access_session_id": str(session.id), "denial_code": code[:120]},
    )
    await db.commit()
    return None, code


async def _consume_web_ticket(ticket: str):
    now = _utcnow()
    async with AsyncSessionLocal() as db:
        session = await db.scalar(
            select(RemoteAccessSession).where(RemoteAccessSession.ticket_hash == hash_remote_ticket(ticket)).with_for_update()
        )
        if session is None:
            return None, "REMOTE_ACCESS_TICKET_INVALID"
        if session.mode != "WEB":
            return await _record_web_denied(db, session, "REMOTE_ACCESS_TICKET_MODE_INVALID")
        if session.status != "ISSUED" or session.consumed_at is not None:
            return await _record_web_denied(db, session, "REMOTE_ACCESS_TICKET_ALREADY_USED")
        if session.revoked_at is not None or session.expires_at <= now:
            return await _record_web_denied(db, session, "REMOTE_ACCESS_TICKET_EXPIRED")

        auth = await db.get(AuthSession, session.auth_session_id) if session.auth_session_id else None
        if auth is None:
            return await _record_web_denied(db, session, "AUTH_SESSION_REQUIRED")
        auth_last = auth.last_user_activity_at or auth.created_at
        if auth.revoked_at is not None or auth.expires_at <= now or auth_last <= now - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES):
            return await _record_web_denied(db, session, "AUTH_SESSION_EXPIRED")

        device = await db.get(Device, session.device_id)
        if device is None or device.deleted_at is not None or device.lifecycle_state == "DECOMMISSIONED":
            return await _record_web_denied(db, session, "DEVICE_NOT_AVAILABLE")
        profile = await db.scalar(select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device.id))
        if not web_profile_is_ready(profile):
            return await _record_web_denied(db, session, "REMOTE_ACCESS_WEB_NOT_CONFIGURED")
        assert profile is not None
        try:
            target_port = profile_web_port(profile)
        except ValueError:
            return await _record_web_denied(db, session, "REMOTE_ACCESS_WEB_PORT_INVALID")

        ip = await db.scalar(
            select(DeviceIP.ip_address)
            .where(DeviceIP.device_id == device.id, DeviceIP.deleted_at.is_(None), DeviceIP.is_management.is_(True))
            .order_by(DeviceIP.is_primary.desc(), DeviceIP.created_at.asc())
            .limit(1)
        )
        if not ip:
            return await _record_web_denied(db, session, "DEVICE_MANAGEMENT_IP_REQUIRED")
        try:
            target_host = validate_management_target(ip)
            ssl_context = build_web_ssl_context(profile)
        except (ValueError, RemoteAccessSecretError) as exc:
            return await _record_web_denied(db, session, str(exc))

        # Starting a child remote session is authenticated operator activity.
        # Refresh the linked FTTW auth-session timestamp so a freshly launched
        # Web-GUI session cannot inherit an almost-expired parent idle timer.
        auth.last_user_activity_at = now
        session.status = "ACTIVE"
        session.consumed_at = now
        session.activated_at = now
        session.last_activity_at = now
        session.gateway_instance = socket.gethostname()[:120]
        actor = await db.get(User, session.actor_user_id) if session.actor_user_id else None
        await record_audit(
            db,
            action="REMOTE_ACCESS_WEB_STARTED",
            entity_type="Device",
            entity_id=device.id,
            actor_user_id=session.actor_user_id,
            actor_username_snapshot=getattr(actor, "username", None),
            actor_display_name_snapshot=getattr(actor, "display_name", None),
            description="Brokered native Web-GUI session started.",
            metadata={
                "remote_access_session_id": str(session.id),
                "scheme": profile.web_scheme,
                "port": target_port,
                "tls_mode": profile.web_tls_mode,
            },
        )
        await db.commit()
        return {
            "session": session,
            "device_id": device.id,
            "auth_session_id": auth.id,
            "target_host": target_host,
            "scheme": profile.web_scheme,
            "port": target_port,
            "tls_mode": profile.web_tls_mode,
            "ssl_context": ssl_context,
            "activated_at": now,
        }, None


async def _create_state(context: dict) -> WebProxyState:
    handle = secrets.token_urlsafe(32)
    scheme = context["scheme"].lower()
    port = context["port"]
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    origin = f"{scheme}://{_url_host(context['target_host'])}{'' if default else ':' + str(port)}"
    client = httpx.AsyncClient(
        base_url=origin,
        verify=context["ssl_context"],
        follow_redirects=False,
        timeout=httpx.Timeout(30.0, connect=10.0),
        limits=httpx.Limits(max_connections=16, max_keepalive_connections=8),
    )
    state = WebProxyState(
        handle=handle,
        session_id=context["session"].id,
        auth_session_id=context["auth_session_id"],
        device_id=context["device_id"],
        target_scheme=context["scheme"],
        target_host=context["target_host"],
        target_port=context["port"],
        tls_mode=context["tls_mode"],
        ssl_context=context["ssl_context"],
        client=client,
        activated_at=context["activated_at"],
    )
    async with _states_lock:
        _states[handle] = state
    return state


async def _drop_state(handle: str, *, end_reason: str | None = None) -> None:
    async with _states_lock:
        state = _states.pop(handle, None)
    if state is not None:
        await state.client.aclose()
        if end_reason:
            await _mark_web_ended(state.session_id, end_reason)


async def _state_for_handle(handle: str | None, session_id: UUID) -> WebProxyState | None:
    if not handle:
        return None
    async with _states_lock:
        state = _states.get(handle)
    if state is None or state.session_id != session_id:
        return None
    return state


async def _validate_active_state(state: WebProxyState, *, touch: bool = False) -> tuple[bool, str | None]:
    now = _utcnow()
    async with AsyncSessionLocal() as db:
        remote = await db.scalar(select(RemoteAccessSession).where(RemoteAccessSession.id == state.session_id).with_for_update())
        auth = await db.get(AuthSession, state.auth_session_id)
        if remote is None or remote.mode != "WEB" or remote.status != "ACTIVE" or remote.revoked_at is not None:
            return False, "REMOTE_ACCESS_SESSION_REVOKED"
        if now >= state.activated_at + timedelta(seconds=max(60, settings.remote_access_session_max_seconds)):
            remote.status = "REVOKED"
            remote.revoked_at = now
            remote.ended_at = now
            remote.revoked_reason = "MAX_SESSION_DURATION"
            await db.commit()
            return False, "REMOTE_ACCESS_SESSION_EXPIRED"
        last_remote = remote.last_activity_at or remote.activated_at or remote.issued_at
        if last_remote <= now - timedelta(seconds=max(60, settings.remote_access_idle_timeout_seconds)):
            remote.status = "REVOKED"
            remote.revoked_at = now
            remote.ended_at = now
            remote.revoked_reason = "REMOTE_IDLE_TIMEOUT"
            await db.commit()
            return False, "REMOTE_ACCESS_SESSION_IDLE_TIMEOUT"
        if auth is None:
            return False, "AUTH_SESSION_REQUIRED"
        auth_last = auth.last_user_activity_at or auth.created_at
        if auth.revoked_at is not None or auth.expires_at <= now or auth_last <= now - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES):
            remote.status = "REVOKED"
            remote.revoked_at = now
            remote.ended_at = now
            remote.revoked_reason = "AUTH_SESSION_EXPIRED"
            await db.commit()
            return False, "AUTH_SESSION_EXPIRED"
        if touch and time.monotonic() - state.last_touch_monotonic >= 2:
            # Browser traffic inside the brokered Web-GUI is authenticated
            # operator activity. Touch both the child session and its linked
            # FTTW auth session. The remote idle/max limits remain authoritative.
            remote.last_activity_at = now
            auth.last_user_activity_at = now
            state.last_touch_monotonic = time.monotonic()
            await db.commit()
    return True, None


async def _cleanup_loop() -> None:
    while True:
        await asyncio.sleep(15)
        async with _states_lock:
            states = list(_states.values())
        for state in states:
            ok, reason = await _validate_active_state(state)
            if not ok:
                await _drop_state(state.handle, end_reason=reason or "SESSION_ENDED")
                logger.info("remote_access_web_state_closed session_id=%s reason=%s", state.session_id, reason)


async def start_web_proxy_cleanup() -> None:
    global _cleanup_task
    if _cleanup_task is None or _cleanup_task.done():
        _cleanup_task = asyncio.create_task(_cleanup_loop())


async def stop_web_proxy_cleanup() -> None:
    global _cleanup_task
    if _cleanup_task is not None:
        _cleanup_task.cancel()
        try:
            await _cleanup_task
        except asyncio.CancelledError:
            pass
        _cleanup_task = None
    async with _states_lock:
        handles = list(_states)
    for handle in handles:
        await _drop_state(handle, end_reason="GATEWAY_SHUTDOWN")


@router.get("/web/launch", response_class=HTMLResponse)
async def web_launch_page(
    request: Request,
    channel: str = "",
    device: str = "",
    opener_origin: str = "",
):
    if not settings.remote_access_enabled:
        return HTMLResponse("Remote access is disabled.", status_code=503)
    if settings.fttw_env.lower() == "production" and not _browser_transport_is_secure(request):
        return HTMLResponse("Secure HTTPS access to the remote gateway is required.", status_code=503)
    channel = re.sub(r"[^A-Za-z0-9_-]", "", channel)[:80]
    safe_device = html.escape(device[:160])

    opener = _validated_opener_origin(
        opener_origin,
        request.headers.get("referer"),
        _allowed_fttw_origins(),
    )

    if opener is None:
        denied_headers = _security_headers()
        denied_headers["Cross-Origin-Opener-Policy"] = "unsafe-none"
        denied_headers["Cache-Control"] = "no-store"

        return HTMLResponse(
            "The FTTW opener origin is not allowed for this Secure Web-GUI launch.",
            status_code=403,
            headers=denied_headers,
        )

    page = f"""<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>{safe_device or 'Device'} · Secure Web GUI</title><style>body{{font:14px system-ui;margin:0;display:grid;place-items:center;min-height:100vh;background:#111;color:#eee}}main{{max-width:520px;padding:28px}}code{{word-break:break-word}}</style></head>
<body><main><h2>Opening secure device GUI…</h2><p id=\"status\">Waiting for the one-time launch ticket.</p></main><script>
const channel={json.dumps(channel)}; const openerOrigin={json.dumps(opener)}; const status=document.getElementById('status');
if(!window.opener){{status.textContent='This launch window must be opened from FTTW.';}}
else{{window.opener.postMessage({{type:'fttw-web-gui-ready',channel}},openerOrigin);}}
window.addEventListener('message',async(event)=>{{
  if(event.origin!==openerOrigin||event.source!==window.opener||event.data?.type!=='fttw-web-gui-launch'||event.data?.channel!==channel)return;
  const ticket=String(event.data.ticket||''); if(!ticket)return;
  try{{
    const response=await fetch('/web/bootstrap',{{method:'POST',headers:{{'X-Remote-Access-Ticket':ticket,'X-FTTW-Web-Bootstrap':'1'}},credentials:'same-origin'}});
    const body=await response.json().catch(()=>({{}}));
    if(!response.ok)throw new Error(body?.detail?.message||body?.message||'Unable to initialize secure Web GUI.');
    window.location.replace(body.launch_path);
  }}catch(error){{status.textContent=error instanceof Error?error.message:'Unable to initialize secure Web GUI.';}}
}},{{once:true}});
</script></body></html>"""
    launch_headers = _security_headers()
    # The launch page must retain its cross-origin opener long enough to receive
    # the one-time ticket. The proxied vendor GUI itself is isolated with COOP.
    launch_headers["Cross-Origin-Opener-Policy"] = "unsafe-none"
    launch_headers["Cache-Control"] = "no-store"
    return HTMLResponse(page, headers=launch_headers)


def _navigation_rescue_page() -> str:
    # Vendor GUIs sometimes complete login by assigning location.href = "/".
    # Because the device is intentionally isolated behind /web/s/<session>, that
    # hard navigation would otherwise escape to the access-gateway root. The
    # active tab already records its opaque proxy path in tab-local storage and
    # window.name; restore only a syntactically valid session path. The actual
    # session cookie remains path-scoped and is still validated on the next hop.
    return r"""<!doctype html><html><head><meta charset="utf-8"><title>Remote Web GUI</title></head><body>
<script>
(function(){
'use strict';
const KEY='fttw.remoteWeb.sessionBase';
const VALID=/^\/web\/s\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
let base='';
try{base=sessionStorage.getItem(KEY)||'';}catch(_err){}
if(!VALID.test(base)){
  const name=String(window.name||'');
  if(name.startsWith('fttw-remote-web:'))base=name.slice('fttw-remote-web:'.length);
}
if(VALID.test(base)){window.location.replace(base+'/');return;}
document.body.textContent='Remote Web-GUI session path is unavailable.';
})();
</script></body></html>"""


@router.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def web_navigation_rescue(request: Request):
    # Keep the gateway root non-functional as a generic proxy. It exists only to
    # recover a same-tab vendor hard navigation back into the already-issued
    # opaque session path. No destination host, IP, or port is accepted here.
    if request.method == "HEAD":
        return Response(status_code=404, headers=_security_headers())
    return HTMLResponse(_navigation_rescue_page(), status_code=404, headers=_security_headers())


@router.post("/web/bootstrap")
async def web_bootstrap(
    request: Request,
    x_remote_access_ticket: str | None = Header(default=None, alias="X-Remote-Access-Ticket"),
    x_fttw_web_bootstrap: str | None = Header(default=None, alias="X-FTTW-Web-Bootstrap"),
):
    if not settings.remote_access_enabled:
        return JSONResponse({"message": "Remote access is disabled."}, status_code=503)
    if settings.fttw_env.lower() == "production" and not _browser_transport_is_secure(request):
        return JSONResponse({"message": "HTTPS is required for native Web-GUI sessions."}, status_code=503)
    if x_fttw_web_bootstrap != "1" or not x_remote_access_ticket:
        return JSONResponse({"message": "One-time launch ticket required."}, status_code=401)

    context, error = await _consume_web_ticket(x_remote_access_ticket.strip())
    if error:
        return JSONResponse({"message": "Remote Web-GUI launch was denied.", "code": error}, status_code=401)
    state = await _create_state(context)
    response = JSONResponse({"session_id": str(state.session_id), "launch_path": f"{state.proxy_base}/"})
    response.set_cookie(
        COOKIE_NAME,
        state.handle,
        max_age=max(60, settings.remote_access_session_max_seconds),
        httponly=True,
        secure=_browser_transport_is_secure(request),
        samesite="strict",
        path=state.proxy_base,
    )
    response.headers.update(_security_headers())
    return response


async def _proxy_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    limit = max(1024, settings.remote_access_web_max_request_bytes)
    if declared:
        try:
            if int(declared) > limit:
                raise ValueError("REMOTE_ACCESS_WEB_REQUEST_TOO_LARGE")
        except ValueError as exc:
            if str(exc) == "REMOTE_ACCESS_WEB_REQUEST_TOO_LARGE":
                raise
    body = await request.body()
    if len(body) > limit:
        raise ValueError("REMOTE_ACCESS_WEB_REQUEST_TOO_LARGE")
    return body


async def _stream_and_close(upstream: httpx.Response) -> AsyncIterator[bytes]:
    try:
        async for chunk in upstream.aiter_raw():
            yield chunk
    finally:
        await upstream.aclose()


@router.api_route(
    "/web/s/{session_id}/{proxy_path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy_web_gui(request: Request, session_id: UUID, proxy_path: str):
    state = await _state_for_handle(request.cookies.get(COOKIE_NAME), session_id)
    if state is None:
        return HTMLResponse("Remote Web-GUI session is unavailable or expired.", status_code=401, headers=_security_headers())
    ok, reason = await _validate_active_state(state, touch=True)
    if not ok:
        await _drop_state(state.handle, end_reason=reason or "SESSION_ENDED")
        return HTMLResponse("Remote Web-GUI session expired or was revoked.", status_code=401, headers=_security_headers())

    path = "/" + proxy_path
    query = request.url.query
    target_url = path + (f"?{query}" if query else "")
    try:
        body = b"" if request.method in {"GET", "HEAD"} else await _proxy_body(request)
    except ValueError:
        return Response("Request body exceeds the Web-GUI proxy limit.", status_code=413, headers=_security_headers())

    try:
        upstream_request = state.client.build_request(
            request.method,
            target_url,
            headers=_upstream_headers(request.headers, state),
            content=body,
        )
        upstream = await state.client.send(upstream_request, stream=True)
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, ssl.SSLError) as exc:
        code = "REMOTE_ACCESS_WEB_TLS_OR_CONNECT_FAILURE" if state.target_scheme == "HTTPS" else "REMOTE_ACCESS_WEB_CONNECT_FAILURE"
        logger.warning("remote_access_web_upstream_failure session_id=%s code=%s type=%s", session_id, code, type(exc).__name__)
        await _mark_web_failed(session_id, code)
        await _drop_state(state.handle)
        return Response("The registered device Web GUI could not be reached securely.", status_code=502, headers=_security_headers())
    except httpx.HTTPError as exc:
        logger.warning("remote_access_web_http_failure session_id=%s type=%s", session_id, type(exc).__name__)
        await _mark_web_failed(session_id, "REMOTE_ACCESS_WEB_PROXY_FAILURE")
        await _drop_state(state.handle)
        return Response("Remote Web-GUI proxy failure.", status_code=502, headers=_security_headers())

    browser_origin = _gateway_origin_from_request(request)
    if "location" in upstream.headers:
        location = upstream.headers["location"]
        rewritten = rewrite_reference(location, state, browser_origin, str(upstream.url))
        if rewritten == "#fttw-blocked-external":
            await upstream.aclose()
            return Response("Blocked device redirect outside the registered management target.", status_code=502, headers=_security_headers())
        headers = _safe_response_headers(upstream)
        headers["Location"] = rewritten
        await upstream.aclose()
        return Response(status_code=upstream.status_code, headers=headers)

    content_type = upstream.headers.get("content-type", "").lower()
    rewrite = any(kind in content_type for kind in _REWRITE_CONTENT_TYPES)
    headers = _safe_response_headers(upstream)
    if rewrite:
        body_bytes = await upstream.aread()
        await upstream.aclose()
        if len(body_bytes) <= max(1024, settings.remote_access_web_rewrite_max_bytes):
            charset = upstream.encoding or "utf-8"
            try:
                text = body_bytes.decode(charset, errors="replace")
            except LookupError:
                text = body_bytes.decode("utf-8", errors="replace")
            rewritten = rewrite_text_payload(text, content_type, state, browser_origin, str(upstream.url)).encode("utf-8")
            if "content-type" in headers:
                base_type = headers["content-type"].split(";", 1)[0]
                headers["content-type"] = f"{base_type}; charset=utf-8"
            return Response(rewritten, status_code=upstream.status_code, headers=headers)
        return Response(body_bytes, status_code=upstream.status_code, headers=headers)

    return StreamingResponse(
        _stream_and_close(upstream),
        status_code=upstream.status_code,
        headers=headers,
    )


async def _ws_session_watchdog(websocket: WebSocket, upstream, state: WebProxyState) -> None:
    while True:
        await asyncio.sleep(2)
        ok, reason = await _validate_active_state(state)
        if not ok:
            try:
                await upstream.close(code=1008, reason="Remote-access session ended.")
            finally:
                await websocket.close(code=4003, reason=reason or "Remote-access session ended.")
            return


@router.websocket("/web/s/{session_id}/{proxy_path:path}")
async def proxy_websocket(websocket: WebSocket, session_id: UUID, proxy_path: str):
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host")
    try:
        parsed_origin = urlsplit(origin or "")
    except ValueError:
        parsed_origin = None
    if not origin or parsed_origin is None or parsed_origin.netloc != host:
        await websocket.close(code=4403, reason="Web-GUI WebSocket origin is not allowed.")
        return

    state = await _state_for_handle(websocket.cookies.get(COOKIE_NAME), session_id)
    if state is None:
        await websocket.close(code=4401, reason="Remote Web-GUI session unavailable.")
        return
    ok, reason = await _validate_active_state(state, touch=True)
    if not ok:
        await _drop_state(state.handle, end_reason=reason or "SESSION_ENDED")
        await websocket.close(code=4401, reason=reason or "Remote Web-GUI session unavailable.")
        return

    ws_scheme = "wss" if state.target_scheme == "HTTPS" else "ws"
    default = (ws_scheme == "ws" and state.target_port == 80) or (ws_scheme == "wss" and state.target_port == 443)
    authority_host = _url_host(state.target_host)
    authority = authority_host if default else f"{authority_host}:{state.target_port}"
    query = websocket.url.query
    uri = f"{ws_scheme}://{authority}/{proxy_path}" + (f"?{query}" if query else "")
    cookie_header = state.client.build_request("GET", state.target_origin + "/" + proxy_path).headers.get("cookie", "")
    protocols = [p.strip() for p in websocket.headers.get("sec-websocket-protocol", "").split(",") if p.strip()]
    additional_headers = {}
    if cookie_header:
        additional_headers["Cookie"] = cookie_header
    try:
        async with websocket_connect(
            uri,
            origin=state.target_origin,
            additional_headers=additional_headers,
            subprotocols=protocols or None,
            ssl=state.ssl_context if ws_scheme == "wss" else None,
            open_timeout=10,
            max_size=16 * 1024 * 1024,
        ) as upstream:
            await websocket.accept(subprotocol=upstream.subprotocol)

            async def browser_to_device():
                while True:
                    message = await websocket.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    if message.get("text") is not None:
                        await upstream.send(message["text"])
                    elif message.get("bytes") is not None:
                        await upstream.send(message["bytes"])
                    await _validate_active_state(state, touch=True)

            async def device_to_browser():
                async for message in upstream:
                    if isinstance(message, bytes):
                        await websocket.send_bytes(message)
                    else:
                        await websocket.send_text(message)
                    await _validate_active_state(state, touch=True)

            tasks = {
                asyncio.create_task(browser_to_device()),
                asyncio.create_task(device_to_browser()),
                asyncio.create_task(_ws_session_watchdog(websocket, upstream, state)),
            }
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                try:
                    task.result()
                except (WebSocketDisconnect, asyncio.CancelledError):
                    pass
    except (OSError, ssl.SSLError, WebSocketException) as exc:
        logger.warning("remote_access_websocket_failure session_id=%s type=%s", session_id, type(exc).__name__)
        try:
            await websocket.close(code=1011, reason="Device WebSocket proxy failed.")
        except Exception:
            pass
