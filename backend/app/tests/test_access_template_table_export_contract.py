from app.services.access_template_table_exports import register_access_template_table_export
from app.services.table_exports import TABLE_EXPORTS


def test_access_template_table_export_is_registered_and_secret_free():
    register_access_template_table_export()
    spec = TABLE_EXPORTS["access_templates"]

    assert spec.path == "/api/access-templates"
    assert spec.pagination == "none"
    assert "protocol" in spec.allowed_params
    assert "include_inactive" in spec.allowed_params
    assert "search" in spec.allowed_params

    exported_paths = {path for column in spec.columns for path in column.paths}
    assert exported_paths == {
        "name",
        "protocol",
        "protocol_variant",
        "visibility",
        "is_active",
        "description",
        "created_at",
        "updated_at",
    }
    assert not exported_paths.intersection(
        {
            "settings",
            "settings_json",
            "secret_providers",
            "reference",
            "encrypted_payload",
            "value",
        }
    )
