"""Shared tombstone columns for recoverable business records."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column


class RecoverableMixin:
    """Mark an in-place business row as belonging to one recycle batch.

    The batch contains actor/reason/retention metadata.  Keeping only these
    two columns on each business table avoids duplicating policy data while
    retaining typed rows as the restoration source of truth.
    """

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    deletion_batch_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("recycle_bin_batches.id", ondelete="RESTRICT"),
        nullable=True,
    )

