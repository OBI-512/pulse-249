from pathlib import Path

import pytest

from app.services.data_exchange import TEMPLATES, _number
from app.services.table_exports import TABLE_EXPORTS


def test_location_table_export_includes_coordinates():
    columns = TABLE_EXPORTS["locations"].columns
    pairs = [(column.label, column.paths) for column in columns]
    assert ("Latitude", ("latitude",)) in pairs
    assert ("Longitude", ("longitude",)) in pairs


def test_geography_import_template_includes_location_coordinates():
    columns = TEMPLATES["geography"]
    assert "address" in columns
    assert "latitude" in columns
    assert "longitude" in columns


def test_coordinate_parser_accepts_zero_and_rejects_non_finite_values():
    assert _number({"latitude": "0"}, "latitude") == 0.0
    assert _number({"longitude": "32.5"}, "longitude") == 32.5
    with pytest.raises(ValueError, match="finite"):
        _number({"latitude": "nan"}, "latitude")


def test_geography_location_export_maps_address_and_coordinates():
    source = Path(__file__).parents[1] / "services" / "data_exchange.py"
    text = source.read_text(encoding="utf-8")
    assert '"address": loc.address' in text
    assert '"latitude": loc.latitude' in text
    assert '"longitude": loc.longitude' in text
    assert 'latitude=data.get("latitude")' in text
    assert 'longitude=data.get("longitude")' in text
    assert 'latitude must be between -90 and 90.' in text
    assert 'longitude must be between -180 and 180.' in text