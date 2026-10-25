from sqlalchemy import event
from sqlalchemy.orm import Session, with_loader_criteria
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..models.recoverable import RecoverableMixin
from ..settings import settings

engine = create_async_engine(settings.database_url, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@event.listens_for(Session, "do_orm_execute")
def _hide_recycled_rows(execute_state) -> None:
    """Exclude tombstoned business rows from every ordinary ORM SELECT.

    Recycle/restore/purge code must opt in explicitly with the statement
    execution option ``include_recycled=True``.  Applying this at the session
    boundary protects topology and validation queries added elsewhere from
    accidentally treating recycled rows as active.
    """

    if (
        execute_state.is_select
        and not execute_state.is_column_load
        and not execute_state.is_relationship_load
        and not execute_state.execution_options.get("include_recycled", False)
    ):
        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(
                RecoverableMixin,
                lambda model: model.deleted_at.is_(None),
                include_aliases=True,
            )
        )
