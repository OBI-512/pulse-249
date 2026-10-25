"""Validate fail-fast runtime safety before migrations or application startup."""
from app.security.runtime_safety import ensure_runtime_safety


if __name__ == "__main__":
    ensure_runtime_safety()
    print("[FTTW] Runtime safety checks passed.")
