"""Compatibility facade for organizational group services."""
from .group_common import GroupMembershipConflict, get_group, get_device, group_context_key
from .group_membership import (
    find_conflicting_membership, validate_membership, get_existing_membership,
    add_membership, move_membership, remove_membership, reconcile_physical_move_memberships,
)
from .group_nesting import (
    validate_group_nesting, add_child_group, remove_child_group, replace_child_groups,
    descendant_group_ids,
)
from .group_effective import (
    effective_group_context_subquery, direct_group_device_select, effective_group_device_ids,
)

__all__ = [name for name in globals() if not name.startswith("_")]
