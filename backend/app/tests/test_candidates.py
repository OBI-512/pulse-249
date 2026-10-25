from app.services.candidates import _confidence, _suggest_name


class DummyResult:
    discovery_method = "HTTP"
    vendor = "Vendor X"
    model = "Model Y"
    hostname = None
    serial_number = None
    raw_data = {}
    ip_address = "10.0.0.1"


def test_candidate_confidence_uses_discovery_quality():
    assert _confidence(DummyResult()) == 1.0


def test_candidate_name_suggestion_is_deterministic():
    assert _suggest_name(DummyResult()) == "Vendor_X-Model_Y-10-0-0-1"
