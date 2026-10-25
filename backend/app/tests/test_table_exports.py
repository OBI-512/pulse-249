from __future__ import annotations

import asyncio
from contextlib import contextmanager

from fastapi import FastAPI, Header
from starlette.requests import Request

from app.services.table_exports import ColumnSpec, TABLE_EXPORTS, TableSpec, collect_table_rows, export_table_bytes


@contextmanager
def _temporary_table(name: str, spec: TableSpec):
    previous = TABLE_EXPORTS.get(name)
    TABLE_EXPORTS[name] = spec
    try:
        yield
    finally:
        if previous is None:
            TABLE_EXPORTS.pop(name, None)
        else:
            TABLE_EXPORTS[name] = previous


def _request(app: FastAPI) -> Request:
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/data-exchange/exports",
        "raw_path": b"/api/data-exchange/exports",
        "query_string": b"",
        "headers": [(b"authorization", b"Bearer table-export-test")],
        "client": ("test", 1),
        "server": ("test", 80),
        "app": app,
    })


def test_table_export_registry_covers_operator_table_families():
    required = {
        "device_inventory", "device_management", "device_ips", "device_interfaces",
        "networks", "cities", "locations", "sectors", "customers", "customer_services",
        "groups", "group_members", "group_items", "candidates", "discovery_jobs", "discovery_results",
        "alarms", "maintenance", "notification_deliveries", "audit_logs", "operational_logs",
        "recycle_batches", "restore_points", "users", "user_sessions", "online_sessions",
        "account_sessions", "settings", "telemetry_profiles", "telemetry_states", "retention_policies",
        "lifecycle_runs", "import_preview_records", "import_jobs", "report_jobs", "report_schedules",
        "report_deliveries",
    }
    assert required <= set(TABLE_EXPORTS)


def test_complete_table_export_walks_all_pages_and_forwards_auth():
    app = FastAPI()
    seen: list[tuple[int, int, str | None, str | None]] = []

    @app.get("/api/test/page")
    async def page(page: int = 1, page_size: int = 50, search: str | None = None, authorization: str | None = Header(default=None)):
        seen.append((page, page_size, search, authorization))
        total = 1_203
        start = (page - 1) * page_size
        stop = min(total, start + page_size)
        return {"items": [{"name": f"row-{index:04d}"} for index in range(start, stop)], "total": total, "page": page, "page_size": page_size}

    spec = TableSpec(
        path="/api/test/page",
        columns=(ColumnSpec("Name", ("name",)),),
        page_size=500,
        allowed_params=frozenset({"search", "sort_by", "sort_direction"}),
    )
    with _temporary_table("test_complete", spec):
        columns, rows = asyncio.run(collect_table_rows(
            _request(app),
            "test_complete",
            {"table_id": "test_complete", "search": "row", "page": 99, "page_size": 50},
        ))

    assert columns == ["Name"]
    assert len(rows) == 1_203
    assert rows[0]["Name"] == "row-0000"
    assert rows[-1]["Name"] == "row-1202"
    assert [row[0] for row in seen] == [1, 2, 3]
    assert all(row[1] == 500 for row in seen)
    assert all(row[2] == "row" for row in seen)
    assert all(row[3] == "Bearer table-export-test" for row in seen)


def test_table_export_formats_are_csv_and_excel_only():
    app = FastAPI()

    @app.get("/api/test/all")
    async def all_rows():
        return [{"name": "One"}, {"name": "Two"}]

    spec = TableSpec(path="/api/test/all", columns=(ColumnSpec("Name", ("name",)),), pagination="none")
    with _temporary_table("test_formats", spec):
        csv_data, csv_name, csv_media, count = asyncio.run(export_table_bytes(_request(app), "test_formats", "CSV", {}))
        xlsx_data, xlsx_name, xlsx_media, xlsx_count = asyncio.run(export_table_bytes(_request(app), "test_formats", "XLSX", {}))
        try:
            asyncio.run(export_table_bytes(_request(app), "test_formats", "JSON", {}))
        except ValueError as exc:
            assert "CSV and XLSX only" in str(exc)
        else:
            raise AssertionError("JSON table export must be rejected")

    assert count == xlsx_count == 2
    assert csv_name.endswith(".csv") and csv_media == "text/csv"
    assert csv_data.decode("utf-8-sig").startswith("Name")
    assert xlsx_name.endswith(".xlsx") and "spreadsheetml" in xlsx_media
    assert xlsx_data.startswith(b"PK")


def test_paginated_post_process_preserves_local_sort():
    app = FastAPI()

    @app.get("/api/test/post-process")
    async def page(page: int = 1, page_size: int = 50):
        all_rows = [
            {"status": "SENT", "metadata": {"summary": "Zulu"}},
            {"status": "FAILED", "metadata": {"summary": "Alpha"}},
            {"status": "PENDING", "metadata": {"summary": "Mike"}},
        ]
        start = (page - 1) * page_size
        stop = min(len(all_rows), start + page_size)
        return {"items": all_rows[start:stop], "total": len(all_rows), "page": page, "page_size": page_size}

    spec = TableSpec(
        path="/api/test/post-process",
        columns=(ColumnSpec("Summary", ("metadata.summary",)),),
        page_size=2,
        post_process=True,
    )
    with _temporary_table("test_post_process", spec):
        columns, rows = asyncio.run(collect_table_rows(
            _request(app),
            "test_post_process",
            {"sort_by": "summary", "sort_direction": "asc"},
        ))

    assert columns == ["Summary"]
    assert [row["Summary"] for row in rows] == ["Alpha", "Mike", "Zulu"]
