"""CI blocker for the current FTTW route + authorization contract.

This is intentionally separate from the historical refactor route baseline.
It inventories the current application after Scoped Access and fails closed if:
- a non-auth API route has no known authorization boundary;
- a centrally authorized route has no explicit WHAT permission;
- a permission is outside the controlled permission catalog;
- an administration route loses its GLOBAL-scope dependency;
- a dynamic Template Package route loses its explicit authenticated boundary; or
- the current route/permission manifest differs from the committed CI baseline.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from types import SimpleNamespace

from starlette.requests import Request

from app.api.router import api_router
from app.security.authorization import permission_for_request
from app.security.permissions import ALL_PERMISSIONS


BASELINE = Path(__file__).with_name("ci_route_permission_contract_baseline.json")
CONTRACT_EXTENSIONS = (
    Path(__file__).with_name("ci_route_permission_contract_0040_extension.json"),
    Path(__file__).with_name("ci_route_permission_contract_batch_a_extension.json"),
    Path(__file__).with_name("ci_route_permission_contract_0041_extension.json"),
    Path(__file__).with_name("ci_route_permission_contract_0042_extension.json"),
    Path(__file__).with_name("ci_route_permission_contract_0043_extension.json"),
    Path(__file__).with_name("ci_route_permission_contract_tp1_p4_a0_extension.json"),
    Path(__file__).with_name("ci_route_permission_contract_tp2_extension.json"),
    Path(__file__).with_name("ci_route_permission_contract_tp3_extension.json"),
    Path(__file__).with_name("ci_route_permission_contract_tp4_extension.json"),
)

# Administration endpoints use explicit per-handler permission checks instead
# of the central authorize_request dependency.  Keep that exception set closed
# and auditable.  Conditional secondary permissions (role/permission assignment)
# are covered by the existing user-security regression suite.
ADMIN_PERMISSION_CONTRACT: dict[tuple[str, str], str] = {
    ("GET", "/api/admin/resource-scope-options"): "user.scopes.read",
    ("GET", "/api/admin/users/{user_id}/resource-scopes"): "user.scopes.read",
    ("PUT", "/api/admin/users/{user_id}/resource-scopes"): "user.scopes.manage",
    ("GET", "/api/admin/security-options"): "user.read",
    ("GET", "/api/admin/users/page"): "user.read",
    ("GET", "/api/admin/users"): "user.read",
    ("POST", "/api/admin/users"): "user.create",
    ("PATCH", "/api/admin/users/{user_id}"): "user.update",
    ("POST", "/api/admin/users/{user_id}/password-reset"): "user.password.reset",
    ("DELETE", "/api/admin/users/{user_id}"): "user.deactivate",
    ("GET", "/api/admin/users/{user_id}/sessions"): "user.sessions.read",
    ("DELETE", "/api/admin/users/{user_id}/sessions/{session_id}"): "user.sessions.manage",
    ("POST", "/api/admin/users/{user_id}/sessions/revoke-all"): "user.sessions.manage",
    ("GET", "/api/admin/sessions/online"): "user.sessions.read",
    ("GET", "/api/admin/settings"): "settings.read",
    ("PUT", "/api/admin/settings/{key}"): "settings.manage",
}

TEMPLATE_PACKAGE_PERMISSION_CONTRACT: dict[tuple[str, str], tuple[str, ...]] = {
    (
        "GET",
        "/api/template-packages/export/{template_kind}/{template_id}",
    ): (
        "access_template.read",
        "device.configuration.template.read",
    ),
    (
        "POST",
        "/api/template-packages/preview",
    ): (
        "access_template.manage",
        "device.configuration.template.manage",
    ),
    (
        "POST",
        "/api/template-packages/import",
    ): (
        "access_template.manage",
        "device.configuration.template.manage",
    ),
}

CENTRAL_GLOBAL_SCOPE_PREFIXES = (
    "/api/configuration-templates",
)

RECYCLE_PREVIEW_CONTRACT = {
    "NETWORK": "network.delete",
    "CITY": "geo.delete",
    "LOCATION": "geo.delete",
    "SECTOR": "geo.delete",
    "DEVICE": "device.delete",
    "CUSTOMER": "customer.delete",
    "CUSTOMER_SERVICE": "customer.delete",
    "DEVICE_GROUP": "group.delete",
    "DEVICE_RELATIONSHIP": "relationship.delete",
    "DEVICE_IP": "device.delete",
    "DEVICE_INTERFACE": "device.delete",
}


def _call_name(call: object) -> str:
    module = getattr(call, "__module__", "")
    qualname = getattr(call, "__qualname__", getattr(call, "__name__", str(call)))
    return f"{module}.{qualname}" if module else str(qualname)


def _dependency_names(dependant: object) -> set[str]:
    names: set[str] = set()
    stack = list(getattr(dependant, "dependencies", []) or [])
    seen: set[int] = set()
    while stack:
        item = stack.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        call = getattr(item, "call", None)
        if call is not None:
            names.add(_call_name(call))
        stack.extend(getattr(item, "dependencies", []) or [])
    return names


def _request(path: str, method: str, query: str = "") -> Request:
    route = SimpleNamespace(path=path)
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": query.encode("utf-8"),
        "headers": [],
        "client": ("ci-contract", 0),
        "server": ("ci-contract", 80),
        "route": route,
    })


def _central_permission(path: str, method: str, query: str = "") -> str | None:
    return permission_for_request(_request(path, method, query))


def _assert_catalog(permission: str, *, context: str) -> None:
    if permission not in ALL_PERMISSIONS:
        raise RuntimeError(f"Unknown permission '{permission}' in {context}.")


def current_manifest() -> dict[str, object]:
    rows: list[dict[str, object]] = []
    seen_admin: set[tuple[str, str]] = set()
    seen_template_packages: set[tuple[str, str]] = set()

    for route in api_router.routes:
        path = route.path
        methods = sorted(
            method for method in (getattr(route, "methods", []) or [])
            if method not in {"HEAD", "OPTIONS"}
        )
        dependency_names = _dependency_names(getattr(route, "dependant", None))
        centrally_authorized = any(name.endswith(".authorize_request") for name in dependency_names)
        global_scope_dependency = any(name.endswith(".require_global_request_scope") for name in dependency_names)
        authenticated_dependency = any(name.endswith(".get_current_user") for name in dependency_names)

        for method in methods:
            row: dict[str, object] = {"method": method, "path": path}

            if path.startswith("/api/auth/"):
                row.update({"mode": "AUTH_FLOW", "permission": None})
            elif path in {"/api", "/api/health"}:
                row.update({"mode": "PUBLIC", "permission": None})
            elif path.startswith("/api/admin/"):
                key = (method, path)
                permission = ADMIN_PERMISSION_CONTRACT.get(key)
                if permission is None:
                    raise RuntimeError(f"Unclassified administration route: {method} {path}")
                if not global_scope_dependency:
                    raise RuntimeError(f"Administration route lost GLOBAL-scope dependency: {method} {path}")
                _assert_catalog(permission, context=f"{method} {path}")
                seen_admin.add(key)
                row.update({"mode": "ADMIN_EXPLICIT", "permission": permission, "global_scope": True})
            elif path.startswith("/api/template-packages"):
                key = (method, path)
                permissions = TEMPLATE_PACKAGE_PERMISSION_CONTRACT.get(key)
                if permissions is None:
                    raise RuntimeError(f"Unclassified Template Package route: {method} {path}")
                if not authenticated_dependency:
                    raise RuntimeError(
                        f"Template Package route lost authenticated explicit boundary: {method} {path}"
                    )
                if centrally_authorized:
                    raise RuntimeError(
                        f"Template Package dynamic permission route must not use a static central permission: {method} {path}"
                    )
                for permission in permissions:
                    _assert_catalog(permission, context=f"{method} {path}")
                seen_template_packages.add(key)
                row.update(
                    {
                        "mode": "TEMPLATE_PACKAGE_EXPLICIT",
                        "permissions": list(permissions),
                        "global_scope": "CONFIGURATION_ONLY",
                    }
                )
            elif centrally_authorized:
                permission = _central_permission(path, method)
                if permission is None:
                    raise RuntimeError(f"Centrally protected route has no explicit permission: {method} {path}")
                _assert_catalog(permission, context=f"{method} {path}")
                requires_global = any(
                    path.startswith(prefix) for prefix in CENTRAL_GLOBAL_SCOPE_PREFIXES
                )
                if requires_global and not global_scope_dependency:
                    raise RuntimeError(
                        f"Centrally protected global route lost GLOBAL-scope dependency: {method} {path}"
                    )
                row.update({"mode": "CENTRAL", "permission": permission})
                if requires_global:
                    row["global_scope"] = True
            else:
                raise RuntimeError(f"Route has no recognized authorization boundary: {method} {path}")

            rows.append(row)

    unused_admin = sorted(set(ADMIN_PERMISSION_CONTRACT) - seen_admin)
    if unused_admin:
        formatted = ", ".join(f"{method} {path}" for method, path in unused_admin)
        raise RuntimeError(f"Stale administration contract entries: {formatted}")

    unused_template_packages = sorted(
        set(TEMPLATE_PACKAGE_PERMISSION_CONTRACT) - seen_template_packages
    )
    if unused_template_packages:
        formatted = ", ".join(
            f"{method} {path}" for method, path in unused_template_packages
        )
        raise RuntimeError(f"Stale Template Package contract entries: {formatted}")

    preview_rows: list[dict[str, str]] = []
    for entity_type, expected in sorted(RECYCLE_PREVIEW_CONTRACT.items()):
        actual = _central_permission(
            "/api/recycle-bin/preview",
            "GET",
            f"entity_type={entity_type}",
        )
        if actual != expected:
            raise RuntimeError(
                f"Recycle preview contract mismatch for {entity_type}: expected={expected} actual={actual}"
            )
        _assert_catalog(expected, context=f"recycle preview {entity_type}")
        preview_rows.append({"entity_type": entity_type, "permission": expected})

    rows.sort(key=lambda item: (str(item["path"]), str(item["method"])))
    return {
        "schema": 1,
        "route_count": len(rows),
        "routes": rows,
        "recycle_preview": preview_rows,
    }


def expected_manifest() -> dict[str, object]:
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    if baseline.get("schema") != 1:
        raise RuntimeError("Unsupported route/permission baseline schema.")

    routes = list(baseline.get("routes", []))
    keys = {(str(row.get("path")), str(row.get("method"))) for row in routes}
    for extension_path in CONTRACT_EXTENSIONS:
        if not extension_path.exists():
            raise RuntimeError(f"Route/permission contract extension is missing: {extension_path}")
        extension = json.loads(extension_path.read_text(encoding="utf-8"))
        if extension.get("schema") != 1:
            raise RuntimeError(f"Unsupported contract extension schema: {extension_path}")
        for row in extension.get("routes", []):
            key = (str(row.get("path")), str(row.get("method")))
            if key in keys:
                raise RuntimeError(f"Duplicate route contract entry across baseline/extensions: {key[1]} {key[0]}")
            permission = row.get("permission")
            if isinstance(permission, str):
                _assert_catalog(permission, context=f"contract extension {key[1]} {key[0]}")
            permissions = row.get("permissions")
            if isinstance(permissions, list):
                if not permissions or not all(isinstance(item, str) for item in permissions):
                    raise RuntimeError(
                        f"Invalid dynamic permission list in contract extension: {key[1]} {key[0]}"
                    )
                for item in permissions:
                    _assert_catalog(item, context=f"contract extension {key[1]} {key[0]}")
            keys.add(key)
            routes.append(row)

    routes.sort(key=lambda item: (str(item["path"]), str(item["method"])))
    return {
        "schema": 1,
        "route_count": len(routes),
        "routes": routes,
        "recycle_preview": baseline.get("recycle_preview", []),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()

    current = current_manifest()
    if args.write_baseline:
        if os.getenv("FTTW_ALLOW_CONTRACT_BASELINE_WRITE") != "1":
            print("[FAIL] Baseline writing requires FTTW_ALLOW_CONTRACT_BASELINE_WRITE=1.")
            return 2
        if any(path.exists() for path in CONTRACT_EXTENSIONS):
            print("[FAIL] Fold committed contract extensions into the primary baseline before using --write-baseline.")
            return 2
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[PASS] Wrote CI route/permission contract baseline: {current['route_count']} operations.")
        return 0

    if not BASELINE.exists():
        print(f"[FAIL] CI route/permission baseline is missing: {BASELINE}")
        return 2

    expected = expected_manifest()
    if current != expected:
        print("[FAIL] Current route/permission contract differs from the committed CI baseline/extension set.")
        expected_rows = expected.get("routes", [])
        actual_rows = current.get("routes", [])
        for index in range(max(len(expected_rows), len(actual_rows))):
            expected_row = expected_rows[index] if index < len(expected_rows) else None
            actual_row = actual_rows[index] if index < len(actual_rows) else None
            if expected_row != actual_row:
                print(f"First route difference at index {index}:")
                print("EXPECTED:", json.dumps(expected_row, sort_keys=True))
                print("ACTUAL:  ", json.dumps(actual_row, sort_keys=True))
                break
        if expected.get("recycle_preview") != current.get("recycle_preview"):
            print("Recycle preview permission contract also differs.")
        return 1

    print(f"[PASS] CI route/permission contract: {current['route_count']} approved operations.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())