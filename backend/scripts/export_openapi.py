"""Emit a deterministic OpenAPI document for deployment contract comparison."""
import json
from pathlib import Path
import sys

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from fastapi import FastAPI
from app.api.router import api_router

app = FastAPI()
app.include_router(api_router)
print(json.dumps(app.openapi(), sort_keys=True, separators=(",", ":")))
