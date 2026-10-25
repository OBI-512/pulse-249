from __future__ import annotations

from .table_exports import TABLE_EXPORTS, TableSpec, _c


def register_access_template_table_export() -> None:
    """Register the safe Access Templates operator-table export.

    Export columns intentionally omit template settings, secret provider metadata,
    secret references, encrypted payloads, and every secret value. The underlying
    Access Templates API still enforces access_template.read visibility rules, so
    private templates remain owner-only and shared templates remain scoped exactly
    as they are in the UI.
    """

    TABLE_EXPORTS.setdefault(
        "access_templates",
        TableSpec(
            "/api/access-templates",
            (
                _c("Name", "name"),
                _c("Protocol", "protocol"),
                _c("Variant", "protocol_variant"),
                _c("Visibility", "visibility"),
                _c("Active", "is_active"),
                _c("Description", "description"),
                _c("Created", "created_at"),
                _c("Updated", "updated_at"),
            ),
            pagination="none",
            allowed_params=frozenset({"protocol", "include_inactive", "search"}),
        ),
    )


register_access_template_table_export()
