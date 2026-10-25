from __future__ import annotations


_OPERATION_TRANSITIONS: dict[str, frozenset[str]] = {
    "QUEUED": frozenset({"RUNNING", "FAILED", "CANCELLED"}),
    "RUNNING": frozenset({"SUCCEEDED", "FAILED", "ROLLING_BACK"}),
    "ROLLING_BACK": frozenset({"ROLLED_BACK", "ROLLBACK_FAILED"}),
    "SUCCEEDED": frozenset(),
    "FAILED": frozenset(),
    "ROLLED_BACK": frozenset(),
    "ROLLBACK_FAILED": frozenset(),
    "CANCELLED": frozenset(),
}

_STEP_TRANSITIONS: dict[str, frozenset[str]] = {
    "PENDING": frozenset({"RUNNING", "SKIPPED"}),
    "RUNNING": frozenset({"SUCCEEDED", "FAILED", "ROLLING_BACK"}),
    "ROLLING_BACK": frozenset({"ROLLED_BACK", "ROLLBACK_FAILED"}),
    "SUCCEEDED": frozenset(),
    "FAILED": frozenset(),
    "SKIPPED": frozenset(),
    "ROLLED_BACK": frozenset(),
    "ROLLBACK_FAILED": frozenset(),
}


def ensure_operation_transition(current: str, target: str) -> None:
    allowed = _OPERATION_TRANSITIONS.get(current)
    if allowed is None or target not in allowed:
        raise ValueError("CONFIGURATION_OPERATION_TRANSITION_INVALID")


def ensure_step_transition(current: str, target: str) -> None:
    allowed = _STEP_TRANSITIONS.get(current)
    if allowed is None or target not in allowed:
        raise ValueError("CONFIGURATION_OPERATION_STEP_TRANSITION_INVALID")
