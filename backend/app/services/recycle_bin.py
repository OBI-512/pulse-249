"""Compatibility facade for dependency-aware recycle-bin services.

Implementation is decomposed by lifecycle responsibility while preserving the
public import surface used by routers, workers, and regression tests.
"""
from .recycle_bin_common import (
    RECYCLED, RESTORED, PURGE_FAILED, DEFAULT_RETENTION_DAYS,
    PURGE_CANDIDATE_DEPENDENCY, RecycleBinError, _recycle_audit_action,
)
from .recycle_bin_preview import preview_recycle
from .recycle_bin_recycle import recycle_entity
from .recycle_bin_restore import get_recycle_batch, restore_recycle_batch
from .recycle_bin_purge import purge_recycle_batch, purge_due_batches

__all__ = [
    "RECYCLED", "RESTORED", "PURGE_FAILED", "DEFAULT_RETENTION_DAYS",
    "PURGE_CANDIDATE_DEPENDENCY", "RecycleBinError", "_recycle_audit_action",
    "preview_recycle", "recycle_entity", "get_recycle_batch",
    "restore_recycle_batch", "purge_recycle_batch", "purge_due_batches",
]
