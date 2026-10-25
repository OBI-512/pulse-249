from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.exceptions import APIError
from app.models import AuditLog, City, Location, MaintenanceWindow, Network, User, UserResourceScope
from app.security.resource_scope import load_effective_resource_scope
from app.services.maintenance_windows import update_maintenance_window
from app.settings import settings as app_settings


def _factory():
    engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def test_upcoming_maintenance_window_can_be_edited_with_scope_and_audit_preserved():
    async def scenario():
        engine, SessionLocal = _factory()
        try:
            async with SessionLocal() as db:
                tx = await db.begin()
                try:
                    marker = uuid4().hex[:8]
                    user = User(
                        external_subject=f"enh6-{marker}", username=f"enh6-{marker}",
                        display_name="ENH6 Editor", is_active=True, metadata_={},
                    )
                    network = Network(name=f"ENH6 Network {marker}", code=f"E6N-{marker}")
                    db.add_all([user, network]); await db.flush()
                    city = City(network_id=network.id, name=f"ENH6 City {marker}", code=f"E6C-{marker}")
                    db.add(city); await db.flush()
                    location_a = Location(city_id=city.id, name=f"ENH6 A {marker}", code=f"E6A-{marker}", metadata_={})
                    location_b = Location(city_id=city.id, name=f"ENH6 B {marker}", code=f"E6B-{marker}", metadata_={})
                    db.add_all([location_a, location_b]); await db.flush()
                    db.add(UserResourceScope(user_id=user.id, scope_type="NETWORK", network_id=network.id)); await db.flush()
                    scope = await load_effective_resource_scope(db, user.id)

                    now = datetime.now(timezone.utc)
                    row = MaintenanceWindow(
                        name="Before edit", reason="old reason", target_type="LOCATION", target_id=location_a.id,
                        starts_at=now + timedelta(hours=2), ends_at=now + timedelta(hours=3), enabled=True,
                        created_by_user_id=user.id,
                    )
                    db.add(row); await db.flush()
                    created_by = row.created_by_user_id

                    await update_maintenance_window(
                        db, scope=scope, window=row, target_type="LOCATION", target_id=location_b.id,
                        name="After edit", reason="new reason",
                        starts_at=now + timedelta(hours=4), ends_at=now + timedelta(hours=5),
                        actor_user_id=user.id, now=now,
                    )
                    assert row.name == "After edit"
                    assert row.reason == "new reason"
                    assert row.target_id == location_b.id
                    assert row.starts_at == now + timedelta(hours=4)
                    assert row.ends_at == now + timedelta(hours=5)
                    assert row.created_by_user_id == created_by
                    assert row.cancelled_at is None and row.enabled is True
                    audit = await db.scalar(select(AuditLog).where(
                        AuditLog.entity_id == row.id,
                        AuditLog.action == "MAINTENANCE_WINDOW_UPDATED",
                    ).order_by(AuditLog.occurred_at.desc()))
                    assert audit is not None
                    assert audit.actor_user_id == user.id
                    assert audit.before_summary["name"] == "Before edit"
                    assert audit.after_summary["name"] == "After edit"
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_active_past_cancelled_and_no_longer_upcoming_windows_are_immutable():
    async def scenario():
        engine, SessionLocal = _factory()
        try:
            async with SessionLocal() as db:
                tx = await db.begin()
                try:
                    marker = uuid4().hex[:8]
                    user = User(
                        external_subject=f"enh6-lock-{marker}", username=f"enh6-lock-{marker}",
                        display_name="ENH6 Lock", is_active=True, metadata_={},
                    )
                    network = Network(name=f"ENH6 Lock Network {marker}", code=f"E6LN-{marker}")
                    db.add_all([user, network]); await db.flush()
                    db.add(UserResourceScope(user_id=user.id, scope_type="NETWORK", network_id=network.id)); await db.flush()
                    scope = await load_effective_resource_scope(db, user.id)
                    now = datetime.now(timezone.utc)
                    cases = [
                        MaintenanceWindow(name="Active", target_type="NETWORK", target_id=network.id, starts_at=now-timedelta(minutes=5), ends_at=now+timedelta(hours=1), enabled=True),
                        MaintenanceWindow(name="Past", target_type="NETWORK", target_id=network.id, starts_at=now-timedelta(hours=2), ends_at=now-timedelta(hours=1), enabled=True),
                        MaintenanceWindow(name="Cancelled", target_type="NETWORK", target_id=network.id, starts_at=now+timedelta(hours=2), ends_at=now+timedelta(hours=3), enabled=True, cancelled_at=now-timedelta(minutes=1)),
                    ]
                    db.add_all(cases); await db.flush()
                    for row in cases:
                        try:
                            await update_maintenance_window(
                                db, scope=scope, window=row, target_type="NETWORK", target_id=network.id,
                                name="Should not change", reason=None,
                                starts_at=now+timedelta(hours=4), ends_at=now+timedelta(hours=5),
                                actor_user_id=user.id, now=now,
                            )
                        except APIError as exc:
                            assert exc.status_code == 409
                            assert exc.detail["code"] == "MAINTENANCE_WINDOW_NOT_EDITABLE"
                        else:
                            raise AssertionError(f"{row.name} maintenance must be immutable")

                    upcoming = MaintenanceWindow(name="Upcoming", target_type="NETWORK", target_id=network.id, starts_at=now+timedelta(hours=2), ends_at=now+timedelta(hours=3), enabled=True)
                    db.add(upcoming); await db.flush()
                    try:
                        await update_maintenance_window(
                            db, scope=scope, window=upcoming, target_type="NETWORK", target_id=network.id,
                            name="Invalid start", reason=None,
                            starts_at=now, ends_at=now+timedelta(hours=1),
                            actor_user_id=user.id, now=now,
                        )
                    except APIError as exc:
                        assert exc.status_code == 422
                        assert exc.detail["code"] == "INVALID_MAINTENANCE_WINDOW"
                    else:
                        raise AssertionError("edited maintenance must remain upcoming")
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_edit_target_revalidation_hides_out_of_scope_resources():
    async def scenario():
        engine, SessionLocal = _factory()
        try:
            async with SessionLocal() as db:
                tx = await db.begin()
                try:
                    marker = uuid4().hex[:8]
                    user = User(external_subject=f"enh6-scope-{marker}", username=f"enh6-scope-{marker}", display_name="ENH6 Scope", is_active=True, metadata_={})
                    allowed = Network(name=f"Allowed {marker}", code=f"E6A-{marker}")
                    denied = Network(name=f"Denied {marker}", code=f"E6D-{marker}")
                    db.add_all([user, allowed, denied]); await db.flush()
                    db.add(UserResourceScope(user_id=user.id, scope_type="NETWORK", network_id=allowed.id)); await db.flush()
                    scope = await load_effective_resource_scope(db, user.id)
                    now = datetime.now(timezone.utc)
                    row = MaintenanceWindow(name="Scoped", target_type="NETWORK", target_id=allowed.id, starts_at=now+timedelta(hours=2), ends_at=now+timedelta(hours=3), enabled=True)
                    db.add(row); await db.flush()
                    try:
                        await update_maintenance_window(
                            db, scope=scope, window=row, target_type="NETWORK", target_id=denied.id,
                            name="Scoped", reason=None,
                            starts_at=now+timedelta(hours=2), ends_at=now+timedelta(hours=3),
                            actor_user_id=user.id, now=now,
                        )
                    except APIError as exc:
                        assert exc.status_code == 404
                        assert exc.detail["code"] == "RESOURCE_NOT_FOUND"
                    else:
                        raise AssertionError("out-of-scope edit target must be hidden")
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()
    asyncio.run(scenario())
