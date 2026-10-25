from __future__ import annotations

import asyncio
from types import SimpleNamespace

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models import DeviceType, TelemetryProfile
from app.settings import settings as app_settings
from scripts import seed_demo_data


EXPECTED_CODES = {code for _, code in seed_demo_data.CONTROLLED}


def _run(scenario):
    async def execute():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                await scenario(db)
                await db.rollback()
        finally:
            await engine.dispose()

    asyncio.run(execute())


def _assert_default_profile(profile: TelemetryProfile, code: str) -> None:
    assert profile.name == f"{code} Standard"
    assert profile.enabled is False
    assert profile.protocol == "SNMP"
    assert profile.interval_seconds == 900
    assert profile.timeout_seconds == 5
    assert profile.retries == 1
    assert profile.max_metrics == 32
    assert profile.metric_definitions == [
        dict(metric) for metric in seed_demo_data.BASELINE_TELEMETRY_METRICS
    ]
    assert profile.vendor_extensions == {}
    assert profile.description == seed_demo_data.BASELINE_TELEMETRY_DESCRIPTION


def test_empty_profile_bootstrap_produces_all_required_types_and_profiles():
    async def scenario(db):
        await db.execute(delete(TelemetryProfile))
        await db.flush()

        types, profiles = await seed_demo_data.ensure_baseline_telemetry_catalog(db)

        assert set(types) == EXPECTED_CODES
        assert set(profiles) == EXPECTED_CODES
        assert await db.scalar(select(func.count(TelemetryProfile.id))) == len(EXPECTED_CODES)
        for code in EXPECTED_CODES:
            assert types[code].code == code
            assert profiles[code].device_type_id == types[code].id
            _assert_default_profile(profiles[code], code)

    _run(scenario)


def test_telemetry_profile_bootstrap_is_idempotent():
    async def scenario(db):
        await db.execute(delete(TelemetryProfile))
        await db.flush()

        _, first = await seed_demo_data.ensure_baseline_telemetry_catalog(db)
        first_ids = {code: profile.id for code, profile in first.items()}
        _, second = await seed_demo_data.ensure_baseline_telemetry_catalog(db)

        assert {code: profile.id for code, profile in second.items()} == first_ids
        assert await db.scalar(select(func.count(TelemetryProfile.id))) == len(EXPECTED_CODES)

    _run(scenario)


def test_telemetry_profile_bootstrap_preserves_customized_profile():
    async def scenario(db):
        types, _ = await seed_demo_data.ensure_baseline_telemetry_catalog(db)
        profile = await db.scalar(
            select(TelemetryProfile).where(
                TelemetryProfile.device_type_id == types["CPE"].id
            )
        )
        profile.name = "Custom CPE collection"
        profile.enabled = True
        profile.interval_seconds = 1800
        profile.timeout_seconds = 17
        profile.retries = 3
        profile.max_metrics = 7
        profile.metric_definitions = [{"key": "custom", "oid": "1.3.6.1.4.1.999.1"}]
        profile.vendor_extensions = {"vendor": "custom"}
        profile.description = "Operator-owned profile"
        await db.flush()

        original_id = profile.id
        _, reconciled = await seed_demo_data.ensure_baseline_telemetry_catalog(db)
        preserved = reconciled["CPE"]

        assert preserved.id == original_id
        assert preserved.name == "Custom CPE collection"
        assert preserved.enabled is True
        assert preserved.interval_seconds == 1800
        assert preserved.timeout_seconds == 17
        assert preserved.retries == 3
        assert preserved.max_metrics == 7
        assert preserved.metric_definitions == [{"key": "custom", "oid": "1.3.6.1.4.1.999.1"}]
        assert preserved.vendor_extensions == {"vendor": "custom"}
        assert preserved.description == "Operator-owned profile"

    _run(scenario)


def test_telemetry_profile_bootstrap_backfills_only_missing_profile():
    async def scenario(db):
        type_rows = (
            await db.execute(
                select(DeviceType.code, DeviceType).where(
                    DeviceType.code.in_(EXPECTED_CODES)
                )
            )
        ).all()
        types = dict(type_rows)
        assert set(types) == EXPECTED_CODES
        retained_ids = dict(
            (
                await db.execute(
                    select(DeviceType.code, TelemetryProfile.id)
                    .join(
                        TelemetryProfile,
                        TelemetryProfile.device_type_id == DeviceType.id,
                    )
                    .where(DeviceType.code != "OTHER")
                )
            ).all()
        )
        assert set(retained_ids) == EXPECTED_CODES - {"OTHER"}
        await db.execute(
            delete(TelemetryProfile).where(
                TelemetryProfile.device_type_id == types["OTHER"].id
            )
        )
        await db.flush()

        _, reconciled = await seed_demo_data.ensure_baseline_telemetry_catalog(db)

        assert {
            code: reconciled[code].id for code in retained_ids
        } == retained_ids
        assert reconciled["OTHER"].device_type_id == types["OTHER"].id
        _assert_default_profile(reconciled["OTHER"], "OTHER")
        assert await db.scalar(select(func.count(TelemetryProfile.id))) == len(EXPECTED_CODES)

    _run(scenario)


def test_demo_seed_marker_does_not_skip_telemetry_reconciliation(monkeypatch):
    calls = []

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def commit(self):
            calls.append("commit")

    async def fake_one(db, model, *conditions):
        return SimpleNamespace(key=seed_demo_data.DEMO_SEED_MARKER_KEY)

    async def fake_catalog(db):
        calls.append("catalog")
        return {}, {}

    monkeypatch.setattr(seed_demo_data, "AsyncSessionLocal", lambda: FakeSession())
    monkeypatch.setattr(seed_demo_data, "one", fake_one)
    monkeypatch.setattr(seed_demo_data, "ensure_baseline_telemetry_catalog", fake_catalog)

    asyncio.run(seed_demo_data.seed())

    assert calls == ["catalog", "commit"]
