"""Fail-fast runtime safety checks for environment-specific dangerous defaults."""
from __future__ import annotations

import os


def _environment(value: str | None = None) -> str:
    return (value if value is not None else os.getenv("FTTW_ENV", "development")).strip().lower()


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def ensure_runtime_safety(
    *,
    environment: str | None = None,
    seed_demo_data: str | None = None,
) -> None:
    env = _environment(environment)
    seed = seed_demo_data if seed_demo_data is not None else os.getenv("SEED_DEMO_DATA", "false")
    if env in {"production", "prod"} and _truthy(seed):
        raise RuntimeError(
            "Unsafe production configuration: SEED_DEMO_DATA must be false when FTTW_ENV=production."
        )


def ensure_demo_seed_allowed(*, environment: str | None = None) -> None:
    if _environment(environment) in {"production", "prod"}:
        raise RuntimeError("Deterministic demo data must never be seeded in a production environment.")
