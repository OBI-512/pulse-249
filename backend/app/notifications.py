from __future__ import annotations

import asyncio
from dataclasses import dataclass
from email.message import EmailMessage
import os
import re
import smtplib
import json
from urllib.parse import urlparse

import httpx


_ENV_REF = re.compile(r"^env://([A-Za-z_][A-Za-z0-9_]*)$")


@dataclass(frozen=True)
class DeliveryResult:
    success: bool
    error_code: str | None = None
    response_status: int | None = None


def resolve_env_reference(reference: str) -> str | None:
    match = _ENV_REF.fullmatch(reference.strip())
    if not match:
        return None
    return os.getenv(match.group(1))


def validate_destination(channel_type: str, destination: str) -> None:
    channel = channel_type.strip().upper()
    value = destination.strip()
    if channel == "EMAIL":
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("EMAIL_DESTINATION_INVALID")
        return
    if channel == "WEBHOOK":
        if _ENV_REF.fullmatch(value) is None:
            raise ValueError("WEBHOOK_DESTINATION_MUST_BE_ENV_REFERENCE")
        return
    raise ValueError("NOTIFICATION_CHANNEL_UNSUPPORTED")


def _smtp_send(destination: str, payload: dict, idempotency_key: str, attachment: tuple[str, bytes, str] | None = None) -> None:
    host = os.getenv("FTTW_SMTP_HOST", "").strip()
    sender = os.getenv("FTTW_SMTP_FROM", "").strip()
    if not host or not sender:
        raise RuntimeError("SMTP_CONFIG_MISSING")
    try:
        port = int(os.getenv("FTTW_SMTP_PORT", "587"))
    except ValueError as exc:
        raise RuntimeError("SMTP_PORT_INVALID") from exc
    username = os.getenv("FTTW_SMTP_USERNAME", "").strip() or None
    password = os.getenv("FTTW_SMTP_PASSWORD", "") if username else None
    starttls = os.getenv("FTTW_SMTP_STARTTLS", "true").strip().lower() not in {"0", "false", "no"}

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = destination
    if payload.get("kind") == "REPORT":
        msg["Subject"] = f"[FTTW][REPORT] {payload.get('report_name') or payload.get('report_type') or 'Scheduled report'}"
    else:
        msg["Subject"] = f"[FTTW][{payload.get('severity', 'INFO')}] {payload.get('summary', 'Network alarm')}"
    # Stable Message-ID helps downstream mail systems deduplicate a retry after
    # a worker crash, while the database remains the primary idempotency guard.
    safe_key = re.sub(r"[^A-Za-z0-9_.-]", "-", idempotency_key)
    msg["Message-ID"] = f"<{safe_key}@fttw.local>"
    if payload.get("kind") == "REPORT":
        msg.set_content("\n".join([
            f"Report: {payload.get('report_name') or payload.get('report_type', '-')}",
            f"Format: {payload.get('format', '-')}",
            f"Rows: {payload.get('row_count', '-')}",
            f"Generated at: {payload.get('generated_at', '-')}",
            f"Delivery key: {idempotency_key}",
        ]))
    else:
        msg.set_content(
            "\n".join([
                f"Alarm: {payload.get('alarm_type', '-')}",
                f"Severity: {payload.get('severity', '-')}",
                f"Summary: {payload.get('summary', '-')}",
                f"Device ID: {payload.get('device_id', '-')}",
                f"Occurrence: {payload.get('occurrence_number', '-')}",
                f"Raised at: {payload.get('raised_at', '-')}",
                f"Correlation: {payload.get('correlation_key', '-')}",
                f"Delivery key: {idempotency_key}",
            ])
        )
    if attachment is not None:
        filename, content, media_type = attachment
        maintype, _, subtype = media_type.partition("/")
        msg.add_attachment(content, maintype=maintype or "application", subtype=subtype or "octet-stream", filename=filename)
    with smtplib.SMTP(host=host, port=port, timeout=10) as client:
        client.ehlo()
        if starttls:
            client.starttls()
            client.ehlo()
        if username:
            client.login(username, password or "")
        client.send_message(msg)


async def deliver_notification(
    *,
    channel_type: str,
    destination: str,
    payload: dict,
    idempotency_key: str,
    attachment: tuple[str, bytes, str] | None = None,
) -> DeliveryResult:
    channel = channel_type.strip().upper()
    try:
        validate_destination(channel, destination)
    except ValueError as exc:
        return DeliveryResult(False, str(exc))

    if channel == "EMAIL":
        try:
            await asyncio.to_thread(_smtp_send, destination.strip(), payload, idempotency_key, attachment)
            return DeliveryResult(True)
        except RuntimeError as exc:
            return DeliveryResult(False, str(exc)[:120])
        except (OSError, smtplib.SMTPException) as exc:
            return DeliveryResult(False, f"SMTP_{type(exc).__name__.upper()}"[:120])

    if channel == "WEBHOOK":
        url = resolve_env_reference(destination)
        if not url:
            return DeliveryResult(False, "WEBHOOK_ENV_REFERENCE_UNRESOLVED")
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return DeliveryResult(False, "WEBHOOK_URL_INVALID")
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                headers = {
                    "X-FTTW-Delivery-Key": idempotency_key,
                    "User-Agent": "FTTW-Notification/1.0",
                }
                if attachment is None:
                    response = await client.post(url, json=payload, headers=headers)
                else:
                    filename, content, media_type = attachment
                    response = await client.post(
                        url,
                        data={"payload": json.dumps(payload, separators=(",", ":"))},
                        files={"file": (filename, content, media_type)},
                        headers=headers,
                    )
            if 200 <= response.status_code < 300:
                return DeliveryResult(True, response_status=response.status_code)
            return DeliveryResult(False, f"WEBHOOK_HTTP_{response.status_code}", response.status_code)
        except httpx.TimeoutException:
            return DeliveryResult(False, "WEBHOOK_TIMEOUT")
        except httpx.HTTPError as exc:
            return DeliveryResult(False, f"WEBHOOK_{type(exc).__name__.upper()}"[:120])

    return DeliveryResult(False, "NOTIFICATION_CHANNEL_UNSUPPORTED")
