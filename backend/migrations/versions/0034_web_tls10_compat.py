"""Add pinned-only per-device TLS 1.0 Web-GUI compatibility.

Revision ID: 0034_web_tls10_compat
Revises: 0033_web_tls_compat
"""

from alembic import op
import sqlalchemy as sa


revision = "0034_web_tls10_compat"
down_revision = "0033_web_tls_compat"
branch_labels = None
depends_on = None


TABLE = "device_remote_access_profiles"
COMPAT_CHECK = "ck_device_remote_access_profiles_web_tls_compat_profile"
PIN_CHECK = "ck_device_remote_access_profiles_web_tls_legacy_pin"


def _checks(inspector):
    return {item["name"] for item in inspector.get_check_constraints(TABLE)}


def _drop_compat_checks(bind) -> None:
    inspector = sa.inspect(bind)
    checks = _checks(inspector)
    for name in (PIN_CHECK, COMPAT_CHECK):
        if name in checks:
            op.drop_constraint(name, TABLE, type_="check")


def _create_checks(*, include_tls10: bool) -> None:
    allowed = (
        "web_tls_compat_profile IN ('MODERN','LEGACY_WEAK_CERT_KEY','LEGACY_TLS_1_0')"
        if include_tls10
        else "web_tls_compat_profile IN ('MODERN','LEGACY_WEAK_CERT_KEY')"
    )
    op.create_check_constraint(COMPAT_CHECK, TABLE, allowed)
    op.create_check_constraint(
        PIN_CHECK,
        TABLE,
        "web_tls_compat_profile = 'MODERN' OR "
        "(web_scheme = 'HTTPS' AND web_tls_mode = 'PINNED_CERT')",
    )


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table(TABLE):
        return
    _drop_compat_checks(bind)
    _create_checks(include_tls10=True)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table(TABLE):
        return
    _drop_compat_checks(bind)
    # A rollback must never leave a value rejected by the restored 0033
    # constraint. MODERN is the fail-closed compatibility default.
    op.execute(
        sa.text(
            "UPDATE device_remote_access_profiles "
            "SET web_tls_compat_profile = 'MODERN' "
            "WHERE web_tls_compat_profile = 'LEGACY_TLS_1_0'"
        )
    )
    _create_checks(include_tls10=False)
