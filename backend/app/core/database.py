from collections.abc import AsyncGenerator

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.session import AsyncSessionLocal


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    session = AsyncSessionLocal()
    try:
        yield session
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def commit_or_rollback(session: AsyncSession) -> None:
    try:
        await session.commit()
    except SQLAlchemyError:
        await session.rollback()
        raise
