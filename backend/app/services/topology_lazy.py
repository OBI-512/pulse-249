"""Compatibility facade for lazy topology query services."""
from .topology_query_models import TopologyQuery, GeographyUniverse, PathScope
from .topology_query_scope import resolve_path_scope
from .topology_query_filters import filter_options
from .topology_query_nodes import hierarchy_children

__all__ = ["TopologyQuery", "GeographyUniverse", "PathScope", "resolve_path_scope", "filter_options", "hierarchy_children"]
