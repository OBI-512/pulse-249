from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
import uvicorn

app = FastAPI(title="FTTW Mock OSS", docs_url=None, redoc_url=None, openapi_url=None)
_mode = "normal"


def _ts():
    return datetime.now(timezone.utc).isoformat()


@app.post("/control/{mode}")
async def control(mode: str):
    global _mode
    if mode not in {"normal", "error", "malformed", "slow"}:
        return JSONResponse(status_code=400, content={"error": "invalid mode"})
    _mode = mode
    return {"mode": _mode}


async def _behavior():
    if _mode == "slow":
        await asyncio.sleep(2.0)
    if _mode == "error":
        return JSONResponse(status_code=503, content={"error": "mock unavailable"})
    if _mode == "malformed":
        return PlainTextResponse("not-json", media_type="application/json")
    return None


@app.get("/customers")
async def customers(cursor: str | None = None):
    failure = await _behavior()
    if failure:
        return failure
    return {
        "customers": [
            {"external_customer_id": "OSS-CUST-001", "customer_code": "OSS-CUST-001", "name": "Mock Customer One", "status": "ACTIVE", "source_updated_at": _ts(), "attributes": {}},
            {"external_customer_id": "OSS-CUST-002", "customer_code": "OSS-CUST-002", "name": "Mock Customer Two", "status": "ACTIVE", "source_updated_at": _ts(), "attributes": {}},
        ],
        "services": [
            {"external_service_id": "OSS-SVC-001", "external_customer_id": "OSS-CUST-001", "service_code": "OSS-SVC-001", "status": "ACTIVE", "customer_vlan_id": 3001, "source_updated_at": _ts(), "attributes": {}},
        ],
        "cursor": cursor,
        "next_cursor": None,
        "has_more": False,
    }


@app.get("/changes")
async def changes(since: str | None = None, cursor: str | None = None):
    failure = await _behavior()
    if failure:
        return failure
    return {
        "customers": [{"external_customer_id": "OSS-CUST-001", "customer_code": "OSS-CUST-001", "name": "Mock Customer One Updated", "status": "ACTIVE", "source_updated_at": _ts(), "attributes": {}}],
        "services": [],
        "cursor": cursor,
        "next_cursor": None,
        "has_more": False,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8090)
