"""Shared pytest configuration for domain/API tests.

Business-rule API tests intentionally bypass authentication so they can focus
on domain validation. Authentication and authorization behavior is covered by
dedicated security tests.
"""
from __future__ import annotations

import pytest

from app.main import app
from app.security.authorization import authorize_request


async def _test_authorized_request():
    return None


@pytest.fixture(scope="session", autouse=True)
def bypass_auth_for_domain_api_tests():
    previous = app.dependency_overrides.get(authorize_request)
    app.dependency_overrides[authorize_request] = _test_authorized_request
    try:
        yield
    finally:
        if previous is None:
            app.dependency_overrides.pop(authorize_request, None)
        else:
            app.dependency_overrides[authorize_request] = previous
