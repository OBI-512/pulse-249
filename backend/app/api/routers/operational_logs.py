from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from ...observability.logging import OPERATIONAL_LOG_SERVICES, sanitize_operational_event, service_log_path
from ...schemas.operational_logs import OperationalLogPage, OperationalLogRead
from ...schemas.log_filters import LogFilterOption
from ...schemas.pagination import PageResult
from ...security.authorization import authorize_request


router = APIRouter(
    prefix="/operational-logs", tags=["Operational Logs"], dependencies=[Depends(authorize_request)]
)
_SERVICES = OPERATIONAL_LOG_SERVICES
_ALL_SERVICES = "all"
_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_MAX_LINES = 5000
_MAX_BYTES = 10 * 1024 * 1024


def _read_single_service_events(service: str) -> list[dict]:
    path: Path = service_log_path(service)
    if not path.exists():
        return []
    # Read only the bounded tail; this endpoint cannot become unrestricted file
    # access or consume an unbounded persistent log.
    with path.open("rb") as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size - _MAX_BYTES))
        data = stream.read().decode("utf-8", errors="replace")
    events: list[dict] = []
    for line in data.splitlines()[-_MAX_LINES:]:
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            event = sanitize_operational_event(parsed)
            event.setdefault("service", service)
            events.append(event)
    return events


def _read_events(service: str) -> list[dict]:
    if service == _ALL_SERVICES:
        events: list[dict] = []
        for current_service in sorted(_SERVICES):
            events.extend(_read_single_service_events(current_service))
        events.sort(key=lambda event: str(event.get("timestamp", "")))
        return events
    if service not in _SERVICES:
        raise HTTPException(422, detail={"code": "LOG_SERVICE_INVALID", "message": "Unknown log service."})
    return _read_single_service_events(service)


def _filter_events(
    events: list[dict], *, level: str | None, request_id: str | None, logger: str | None, user_id: str | None,
    search: str | None, since: datetime | None, until: datetime | None,
) -> list[dict]:
    if level:
        normalized = level.upper()
        if normalized not in _LEVELS:
            raise HTTPException(422, detail={"code": "LOG_LEVEL_INVALID", "message": "Unknown log level."})
        events = [event for event in events if event.get("level") == normalized]
    if request_id:
        events = [event for event in events if event.get("request_id") == request_id]
    if logger:
        events = [event for event in events if event.get("logger") == logger]
    if user_id:
        events = [event for event in events if str(event.get("user_id") or "") == user_id]
    if since:
        events = [event for event in events if event.get("timestamp", "") >= since.isoformat()]
    if until:
        events = [event for event in events if event.get("timestamp", "") <= until.isoformat()]
    if search:
        needle = search.casefold()
        events = [event for event in events if needle in json.dumps(event, sort_keys=True).casefold()]
    return events


def _serialize_events(events: list[dict], service: str) -> list[OperationalLogRead]:
    return [
        OperationalLogRead(
            timestamp=str(event.get("timestamp", "")), level=str(event.get("level", "INFO")),
            service=str(event.get("service", service)), logger=str(event.get("logger", "")),
            message=str(event.get("message", "")), request_id=event.get("request_id"),
            user_id=event.get("user_id"), exception_class=event.get("exception_class"),
            context={key: value for key, value in event.items() if key not in {"timestamp", "level", "service", "logger", "message", "request_id", "user_id", "exception_class"}},
        )
        for event in events
    ]


@router.get("", response_model=list[OperationalLogRead])
async def list_operational_logs(
    service: str = Query("backend"),
    level: str | None = None,
    request_id: str | None = Query(None, max_length=128),
    logger: str | None = Query(None, max_length=200),
    user_id: str | None = Query(None, max_length=200),
    search: str | None = Query(None, max_length=200),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
):
    """Compatibility endpoint retained for existing clients and tests."""
    events = _filter_events(_read_events(service), level=level, request_id=request_id, logger=logger, user_id=user_id, search=search, since=since, until=until)
    events.reverse()
    return _serialize_events(events[:limit], service)


@router.get("/page", response_model=OperationalLogPage)
async def page_operational_logs(
    service: str = Query("backend"),
    level: str | None = None,
    request_id: str | None = Query(None, max_length=128),
    logger: str | None = Query(None, max_length=200),
    user_id: str | None = Query(None, max_length=200),
    search: str | None = Query(None, max_length=200),
    since: datetime | None = None,
    until: datetime | None = None,
    sort_by: str = Query("timestamp", max_length=40),
    sort_direction: str = Query("desc", pattern="^(?i:asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
):
    if since and until and since > until:
        raise HTTPException(422, detail={"code":"LOG_TIME_RANGE_INVALID","message":"since must be earlier than or equal to until."})
    events = _filter_events(_read_events(service), level=level, request_id=request_id, logger=logger, user_id=user_id, search=search, since=since, until=until)
    sort_map = {
        "timestamp": lambda event: str(event.get("timestamp", "")),
        "level": lambda event: str(event.get("level", "")),
        "service": lambda event: str(event.get("service", service)),
        "logger": lambda event: str(event.get("logger", "")),
        "message": lambda event: str(event.get("message", "")),
        "request_id": lambda event: str(event.get("request_id") or ""),
        "user_id": lambda event: str(event.get("user_id") or ""),
    }
    key = sort_map.get(sort_by)
    if key is None:
        raise HTTPException(422, detail={"code":"INVALID_OPERATIONAL_LOG_SORT","message":"Unsupported operational-log sort column."})
    events.sort(key=key, reverse=sort_direction.lower() == "desc")
    total = len(events)
    start = (page - 1) * page_size
    items = _serialize_events(events[start:start + page_size], service)
    return OperationalLogPage(items=items, total=total, page=page, page_size=page_size)


@router.get("/filter-options/{kind}", response_model=PageResult[LogFilterOption])
async def operational_log_filter_options(
    kind: str, service: str = Query("backend"), search: str | None = Query(None, max_length=200),
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=100),
):
    events = _read_events(service)
    if kind not in {"logger", "request-id", "user"}:
        raise HTTPException(422, detail={"code":"LOG_FILTER_KIND_INVALID","message":"Unsupported operational-log filter option."})
    field = {"logger":"logger", "request-id":"request_id", "user":"user_id"}[kind]
    needle = (search or "").strip().casefold()
    values = sorted({str(event.get(field)) for event in events if event.get(field) is not None and (not needle or needle in str(event.get(field)).casefold())})
    total = len(values)
    start = (page - 1) * page_size
    page_values = values[start:start + page_size]
    return PageResult(items=[LogFilterOption(id=value, label=value) for value in page_values], total=total, page=page, page_size=page_size)


@router.get("/export")
async def export_operational_logs(
    service: str = Query("backend"), level: str | None = None,
    request_id: str | None = Query(None, max_length=128), logger: str | None = Query(None, max_length=200), user_id: str | None = Query(None, max_length=200),
    search: str | None = Query(None, max_length=200),
    since: datetime | None = None, until: datetime | None = None,
):
    events = _filter_events(_read_events(service), level=level, request_id=request_id, logger=logger, user_id=user_id, search=search, since=since, until=until)[:_MAX_LINES]
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=["timestamp", "level", "service", "logger", "message", "request_id", "user_id", "exception_class"])
    writer.writeheader()
    for event in events:
        row = {key: str(event.get(key, "")) for key in writer.fieldnames}
        # Avoid spreadsheet formula interpretation in exported diagnostic text.
        for key, value in row.items():
            if value.startswith(("=", "+", "-", "@")):
                row[key] = "'" + value
        writer.writerow(row)
    return Response(stream.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=operational-logs.csv"})
