from app.services.onboarding import build_display_name, normalize_ip


def test_normalize_ipv4():
    assert normalize_ip("192.168.1.10") == "192.168.1.10"


def test_build_display_name():
    name = build_display_name("CPE", "192.168.1.10", "Vendor X", "Model Y")
    assert name == "CPE-192-168-1-10-VENDOR_X-MODEL_Y"
