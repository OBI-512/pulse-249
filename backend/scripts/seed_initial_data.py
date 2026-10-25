"""Backward-compatible entry point for the deterministic demo dataset."""
import asyncio

from seed_demo_data import seed
from seed_tp3_permissions import reconcile_tp3_seed_permissions


async def main() -> None:
    await seed()
    await reconcile_tp3_seed_permissions()


if __name__ == "__main__":
    asyncio.run(main())
