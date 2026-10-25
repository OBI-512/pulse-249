from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class ClientMetadata:
    user_agent: str | None
    browser_name: str | None
    browser_version: str | None
    os_name: str | None
    os_version: str | None
    device_type: str


def _match(pattern: str, value: str) -> str | None:
    match = re.search(pattern, value, re.IGNORECASE)
    return match.group(1) if match else None


def parse_client_metadata(user_agent: str | None) -> ClientMetadata:
    """Parse conservative browser/OS metadata from a standard User-Agent.

    Browser UAs do not expose a reliable workstation/host name, so this module
    intentionally reports only information the browser actually sends.
    """

    raw = (user_agent or "").strip()
    if not raw:
        return ClientMetadata(None, None, None, None, None, "UNKNOWN")
    raw = raw[:1024]

    browser_name: str | None = None
    browser_version: str | None = None
    browser_patterns = (
        ("Microsoft Edge", r"(?:Edg|EdgiOS|EdgA)/([\d.]+)"),
        ("Opera", r"(?:OPR|Opera)/([\d.]+)"),
        ("Firefox", r"(?:Firefox|FxiOS)/([\d.]+)"),
        ("Chrome", r"(?:Chrome|CriOS)/([\d.]+)"),
        ("Safari", r"Version/([\d.]+).*Safari/"),
    )
    for name, pattern in browser_patterns:
        version = _match(pattern, raw)
        if version:
            browser_name, browser_version = name, version
            break

    os_name: str | None = None
    os_version: str | None = None
    if "Windows NT" in raw:
        os_name = "Windows"
        nt = _match(r"Windows NT ([\d.]+)", raw)
        windows_versions = {
            "10.0": "10/11",
            "6.3": "8.1",
            "6.2": "8",
            "6.1": "7",
        }
        os_version = windows_versions.get(nt or "", nt)
    elif "Android" in raw:
        os_name = "Android"
        os_version = _match(r"Android ([\d.]+)", raw)
    elif "iPhone" in raw or "iPad" in raw or "iPod" in raw:
        os_name = "iOS/iPadOS"
        version = _match(r"OS ([\d_]+)", raw)
        os_version = version.replace("_", ".") if version else None
    elif "Mac OS X" in raw:
        os_name = "macOS"
        version = _match(r"Mac OS X ([\d_]+)", raw)
        os_version = version.replace("_", ".") if version else None
    elif "Linux" in raw:
        os_name = "Linux"

    if "iPad" in raw or "Tablet" in raw:
        device_type = "TABLET"
    elif any(marker in raw for marker in ("Mobile", "iPhone", "Android")):
        device_type = "MOBILE"
    else:
        device_type = "DESKTOP"

    return ClientMetadata(
        user_agent=raw,
        browser_name=browser_name or "Other",
        browser_version=browser_version,
        os_name=os_name or "Other",
        os_version=os_version,
        device_type=device_type,
    )
