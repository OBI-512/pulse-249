import asyncio
import re
import socket
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler, urlopen

from ..base import DiscoveryAdapter
from ..models import DiscoveryContext, DiscoveryResult
from ...web_management import effective_web_port, web_management_url

_MAX_BODY = 16384
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _clean_title(value: str | None) -> str | None:
    if not value:
        return None
    value = re.sub(r"\s+", " ", value).strip()
    return value[:200] or None


def _reverse_dns(ip_address: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname or None
    except (socket.herror, socket.gaierror, OSError):
        return None


class HTTPDiscoveryAdapter(DiscoveryAdapter):
    name = "HTTP"
    method = "HTTP"

    async def discover(self, context: DiscoveryContext) -> DiscoveryResult:
        return await self._request(context, "http")

    async def _request(self, context: DiscoveryContext, scheme: str) -> DiscoveryResult:
        configured_port = context.https_port if scheme == "https" else context.http_port
        port = effective_web_port(scheme, configured_port)
        url = f"{web_management_url(scheme, context.ip_address, configured_port)}/"
        started = time.perf_counter()

        def do_request():
            request = Request(
                url,
                method="GET",
                headers={"User-Agent": "FTTW-Discovery/1.0"},
            )
            # HTTP/HTTPS discovery is intentionally limited to a GET of "/".
            # No login form is submitted and no credentials are sent.
            if scheme == "https":
                context_ssl = ssl._create_unverified_context()
                with urlopen(request, timeout=context.timeout_seconds, context=context_ssl) as response:
                    body = response.read(_MAX_BODY)
                    return response.status, response.headers, body, response.geturl()
            with urlopen(request, timeout=context.timeout_seconds) as response:
                body = response.read(_MAX_BODY)
                return response.status, response.headers, body, response.geturl()

        try:
            status, headers, body, final_url = await asyncio.to_thread(do_request)
            elapsed = round((time.perf_counter() - started) * 1000, 2)
            server = headers.get("Server")
            title = _clean_title(_TITLE_RE.search(body.decode("utf-8", errors="ignore")).group(1)
                                 if _TITLE_RE.search(body.decode("utf-8", errors="ignore")) else None)
            hostname = _reverse_dns(context.ip_address)

            return DiscoveryResult(
                success=True,
                method=self.method,
                ip_address=context.ip_address,
                hostname=hostname,
                management_protocol=scheme.upper(),
                response_time_ms=elapsed,
                message=f"{scheme.upper()} endpoint responded with status {status}.",
                raw_data={
                    "status_code": status,
                    "server": server,
                    "content_type": headers.get("Content-Type"),
                    "content_length": len(body),
                    "title": title,
                    "final_url": final_url,
                    "requested_url": url,
                    "port": port,
                },
            )
        except HTTPError as exc:
            elapsed = round((time.perf_counter() - started) * 1000, 2)
            hostname = _reverse_dns(context.ip_address)
            try:
                body = exc.read(_MAX_BODY)
            except Exception:
                body = b""
            decoded = body.decode("utf-8", errors="ignore")
            title_match = _TITLE_RE.search(decoded)
            title = _clean_title(title_match.group(1) if title_match else None)
            return DiscoveryResult(
                success=True,
                method=self.method,
                ip_address=context.ip_address,
                hostname=hostname,
                management_protocol=scheme.upper(),
                response_time_ms=elapsed,
                message=f"{scheme.upper()} endpoint responded with status {exc.code}.",
                raw_data={
                    "status_code": exc.code,
                    "server": exc.headers.get("Server"),
                    "content_type": exc.headers.get("Content-Type"),
                    "content_length": len(body),
                    "title": title,
                    "requested_url": url,
                    "port": port,
                },
            )
        except (URLError, TimeoutError, socket.timeout) as exc:
            elapsed = round((time.perf_counter() - started) * 1000, 2)
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol=scheme.upper(),
                response_time_ms=elapsed,
                message=f"{scheme.upper()} endpoint unavailable: {exc}",
            )
        except Exception as exc:
            elapsed = round((time.perf_counter() - started) * 1000, 2)
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol=scheme.upper(),
                response_time_ms=elapsed,
                message=f"{scheme.upper()} discovery failed: {exc}",
            )


class HTTPSDiscoveryAdapter(HTTPDiscoveryAdapter):
    name = "HTTPS"
    method = "HTTPS"

    async def discover(self, context: DiscoveryContext) -> DiscoveryResult:
        return await self._request(context, "https")
