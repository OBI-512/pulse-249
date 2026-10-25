"""Device-candidate router aggregator and compatibility import facade."""
from fastapi import APIRouter, Depends
from ...security.authorization import authorize_request
from . import candidates_query, candidates_review, candidates_registration

router = APIRouter()
_route_options = {
    "prefix": "/device-candidates",
    "tags": ["Device Candidates"],
    "dependencies": [Depends(authorize_request)],
}
router.include_router(candidates_query.router, **_route_options)
router.include_router(candidates_review.router, **_route_options)
router.include_router(candidates_registration.router, **_route_options)

# Compatibility exports retained for tests and internal callers.
from .candidates_query import (
    candidate_summary, list_candidates, candidate_location_options,
    candidate_logical_sector_options, get_candidate,
)
from .candidates_review import update_candidate, approve_candidate, reject_candidate, reopen_candidate
from .candidates_registration import register_candidate, candidate_audit
