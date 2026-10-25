from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from app.models.availability import AVAILABILITY_STATES


class ProbeOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class ProbeObservation:
    outcome: ProbeOutcome
    result_code: str
    latency_ms: float | None = None


@dataclass(frozen=True)
class AvailabilityTransition:
    status: str
    consecutive_failures: int
    last_check_at: datetime
    last_success_at: datetime | None
    last_failure_at: datetime | None
    latency_ms: float | None
    result_code: str


def transition_availability(
    *,
    current_status: str,
    current_failures: int,
    last_success_at: datetime | None,
    last_failure_at: datetime | None,
    lifecycle_state: str,
    observation: ProbeObservation,
    failure_threshold: int,
    checked_at: datetime | None = None,
) -> AvailabilityTransition:
    """Compute the deterministic C1 state transition for one completed check.

    Probe/configuration failures that are not evidence of device reachability are
    INDETERMINATE. They never manufacture failure counts or an OFFLINE state.
    MAINTENANCE continues collecting measurements while masking the externally
    visible availability state until the lifecycle leaves maintenance.
    """

    now = checked_at or datetime.now(timezone.utc)
    status = current_status.upper()
    if status not in AVAILABILITY_STATES:
        status = "UNKNOWN"
    lifecycle = lifecycle_state.upper()
    failures = max(0, int(current_failures))
    threshold = max(2, int(failure_threshold))
    success_at = last_success_at
    failure_at = last_failure_at

    if lifecycle == "DECOMMISSIONED":
        return AvailabilityTransition(
            status="UNKNOWN",
            consecutive_failures=0,
            last_check_at=now,
            last_success_at=success_at,
            last_failure_at=failure_at,
            latency_ms=None,
            result_code="DECOMMISSIONED",
        )

    if observation.outcome is ProbeOutcome.SUCCESS:
        failures = 0
        success_at = now
        measured_status = "ONLINE"
    elif observation.outcome is ProbeOutcome.FAILURE:
        failures += 1
        failure_at = now
        measured_status = "OFFLINE" if failures >= threshold else "SUSPECT"
    else:
        # Keep the last determinate state. A device never becomes OFFLINE merely
        # because the local probe utility/credential/configuration is unusable.
        measured_status = status if status in {"ONLINE", "SUSPECT", "OFFLINE"} else "UNKNOWN"

    if lifecycle == "MAINTENANCE":
        measured_status = "MAINTENANCE"

    return AvailabilityTransition(
        status=measured_status,
        consecutive_failures=failures,
        last_check_at=now,
        last_success_at=success_at,
        last_failure_at=failure_at,
        latency_ms=observation.latency_ms,
        result_code=observation.result_code[:80],
    )
