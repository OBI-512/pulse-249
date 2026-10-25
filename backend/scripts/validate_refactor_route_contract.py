"""Validate the behavior-preserving refactor against the pre-refactor API route contract."""
from __future__ import annotations

import inspect
import json
from pathlib import Path
import sys
import typing

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.api.router import api_router


def _model_label(value):
    if value is None:
        return None
    origin = typing.get_origin(value)
    if origin is not None:
        label = getattr(origin, "__name__", str(origin).replace("typing.", ""))
        args = ",".join(_model_label(arg) or "None" for arg in typing.get_args(value))
        return f"{label}[{args}]"
    return getattr(value, "__name__", str(value).replace("typing.", ""))


def _current_manifest():
    rows = []
    for route in api_router.routes:
        dependant = getattr(route, "dependant", None)
        dependencies = [] if dependant is None else [
            getattr(getattr(item, "call", None), "__name__", str(getattr(item, "call", None)))
            for item in dependant.dependencies
        ]
        signature = [
            {"name": parameter.name, "kind": parameter.kind.name, "has_default": parameter.default is not inspect._empty}
            for parameter in inspect.signature(route.endpoint).parameters.values()
        ]
        rows.append({
            "path": route.path,
            "methods": sorted(method for method in (getattr(route, "methods", []) or []) if method not in {"HEAD", "OPTIONS"}),
            "name": route.name,
            "status_code": route.status_code,
            "response_model": _model_label(getattr(route, "response_model", None)),
            "dependencies": dependencies,
            "signature": signature,
        })
    return rows


def main() -> int:
    baseline_path = Path(__file__).with_name("refactor_route_contract_baseline.json")
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    current = _current_manifest()
    if current != baseline:
        print("[FAIL] Refactor API route contract differs from the validated R1.2 baseline.")
        limit = max(len(baseline), len(current))
        for index in range(limit):
            expected = baseline[index] if index < len(baseline) else None
            actual = current[index] if index < len(current) else None
            if expected != actual:
                print(f"First difference at route index {index}:")
                print("EXPECTED:", json.dumps(expected, sort_keys=True))
                print("ACTUAL:  ", json.dumps(actual, sort_keys=True))
                break
        return 1
    print(f"[PASS] Refactor API route contract: {len(current)} operations unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
