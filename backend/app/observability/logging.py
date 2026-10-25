"""Sanitized JSON operational logging with per-service bounded persistence."""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from ..core.audit_context import get_audit_context
from ..core.audit_redaction import redact_audit_value
from ..settings import settings


_CONFIGURED = False
_SERVICE = os.getenv("FTTW_SERVICE_NAME", "backend")
OPERATIONAL_LOG_SERVICES = frozenset({"backend", "worker", "scheduler", "maintenance", "configuration-worker"})
_ALLOWED_SERVICES = OPERATIONAL_LOG_SERVICES


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        context = get_audit_context()
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": _SERVICE,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if context.request_id:
            payload["request_id"] = context.request_id
        if context.actor_user_id:
            payload["user_id"] = str(context.actor_user_id)
        for key in ("entity_id", "task_id", "event", "error_code"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = str(value)
        if record.exc_info:
            payload["exception_class"] = record.exc_info[0].__name__
        return json.dumps(redact_audit_value(payload), sort_keys=True, default=str)


def log_directory() -> Path:
    path = Path(settings.data_root).resolve() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def service_log_path(service: str) -> Path:
    if service not in _ALLOWED_SERVICES:
        raise ValueError("Unknown operational-log service.")
    return log_directory() / f"{service}.jsonl"


def configure_operational_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    formatter = JsonFormatter()
    root = logging.getLogger()
    root.setLevel(os.getenv("FTTW_LOG_LEVEL", "INFO").upper())
    # Do not attach duplicate handlers when Uvicorn imports/reloads modules.
    stdout = logging.StreamHandler(sys.stdout)
    stdout.setFormatter(formatter)
    file_handler = RotatingFileHandler(
        service_log_path(_SERVICE), maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    root.addHandler(stdout)
    root.addHandler(file_handler)
    _CONFIGURED = True


def sanitize_operational_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Defensive API/read-path redaction for both new and legacy log lines."""

    return redact_audit_value(payload)
