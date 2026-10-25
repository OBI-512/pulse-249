from datetime import datetime, timezone

from app.availability.state import ProbeObservation, ProbeOutcome, transition_availability


NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def transition(status, failures, outcome, *, lifecycle="ACTIVE", threshold=2):
    return transition_availability(
        current_status=status,
        current_failures=failures,
        last_success_at=None,
        last_failure_at=None,
        lifecycle_state=lifecycle,
        observation=ProbeObservation(outcome, outcome.value, 4.2),
        failure_threshold=threshold,
        checked_at=NOW,
    )


def test_failure_confirmation_and_recovery_are_deterministic():
    first = transition("ONLINE", 0, ProbeOutcome.FAILURE)
    assert first.status == "SUSPECT"
    assert first.consecutive_failures == 1

    second = transition(first.status, first.consecutive_failures, ProbeOutcome.FAILURE)
    assert second.status == "OFFLINE"
    assert second.consecutive_failures == 2

    recovered = transition(second.status, second.consecutive_failures, ProbeOutcome.SUCCESS)
    assert recovered.status == "ONLINE"
    assert recovered.consecutive_failures == 0


def test_indeterminate_probe_never_manufactures_offline():
    result = transition("ONLINE", 0, ProbeOutcome.INDETERMINATE)
    assert result.status == "ONLINE"
    assert result.consecutive_failures == 0

    unknown = transition("UNKNOWN", 0, ProbeOutcome.INDETERMINATE)
    assert unknown.status == "UNKNOWN"


def test_maintenance_masks_measurement_but_keeps_failure_counter():
    result = transition("ONLINE", 0, ProbeOutcome.FAILURE, lifecycle="MAINTENANCE")
    assert result.status == "MAINTENANCE"
    assert result.consecutive_failures == 1
    assert result.last_failure_at == NOW


def test_decommissioned_is_unknown_and_not_offline():
    result = transition("OFFLINE", 4, ProbeOutcome.FAILURE, lifecycle="DECOMMISSIONED")
    assert result.status == "UNKNOWN"
    assert result.consecutive_failures == 0
    assert result.result_code == "DECOMMISSIONED"
