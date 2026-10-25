"""Initial FTTW domain schema.

This is intentionally the first and only migration in the replacement
baseline. It creates the current application schema from SQLAlchemy metadata;
it is not a transformation of the historical FTTW schema.
"""
from alembic import op
from app.db.base import Base
from app import models  # noqa: F401

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())

def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
