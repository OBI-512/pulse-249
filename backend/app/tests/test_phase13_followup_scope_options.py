import asyncio
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.routers.geo import list_geography_scope_options
from app.models import City, Location, Network, Sector
from app.settings import settings


def test_scope_options_include_geography_from_multiple_networks():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                transaction = await db.begin()
                try:
                    suffix = uuid4().hex[:10]
                    network_a = Network(name=f"Scope Network A {suffix}", code=f"SNA-{suffix}")
                    network_b = Network(name=f"Scope Network B {suffix}", code=f"SNB-{suffix}")
                    db.add_all([network_a, network_b])
                    await db.flush()

                    city_a = City(network_id=network_a.id, name=f"Scope City A {suffix}", code=f"SCA-{suffix}")
                    city_b = City(network_id=network_b.id, name=f"Scope City B {suffix}", code=f"SCB-{suffix}")
                    db.add_all([city_a, city_b])
                    await db.flush()

                    location_a = Location(city_id=city_a.id, name=f"Scope Location A {suffix}", code=f"SLA-{suffix}", metadata_={})
                    location_b = Location(city_id=city_b.id, name=f"Scope Location B {suffix}", code=f"SLB-{suffix}", metadata_={})
                    db.add_all([location_a, location_b])
                    await db.flush()

                    sector_a = Sector(location_id=location_a.id, name=f"Scope Sector A {suffix}", code=f"SSA-{suffix}", metadata_={})
                    sector_b = Sector(location_id=location_b.id, name=f"Scope Sector B {suffix}", code=f"SSB-{suffix}", metadata_={})
                    db.add_all([sector_a, sector_b])
                    await db.flush()

                    options = await list_geography_scope_options(db)

                    assert {network_a.id, network_b.id} <= {item.id for item in options.networks}
                    assert {city_a.id, city_b.id} <= {item.id for item in options.cities}
                    assert {location_a.id, location_b.id} <= {item.id for item in options.locations}
                    assert {sector_a.id, sector_b.id} <= {item.id for item in options.sectors}

                    cities = {item.id: item for item in options.cities}
                    locations = {item.id: item for item in options.locations}
                    sectors = {item.id: item for item in options.sectors}
                    assert cities[city_a.id].network_id == network_a.id
                    assert cities[city_b.id].network_id == network_b.id
                    assert locations[location_a.id].city_id == city_a.id
                    assert locations[location_b.id].city_id == city_b.id
                    assert sectors[sector_a.id].location_id == location_a.id
                    assert sectors[sector_b.id].location_id == location_b.id
                finally:
                    await transaction.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())
