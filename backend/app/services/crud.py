from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def get_or_404(db: AsyncSession, model, object_id):
    # Use an explicit SELECT rather than AsyncSession.get().  ``get`` may
    # return an already-loaded identity without issuing SQL, which would let a
    # row tombstoned earlier in the same request bypass the global active-row
    # loader criterion.
    obj = await db.scalar(select(model).where(model.id == object_id))
    if obj is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "RESOURCE_NOT_FOUND",
                "message": f"{model.__name__} not found.",
            },
        )
    return obj


async def get_including_recycled(db: AsyncSession, model, object_id):
    """Load one row while bypassing the default recycle visibility filter."""

    return await db.scalar(
        select(model)
        .where(model.id == object_id)
        .execution_options(include_recycled=True)
    )


async def get_active_for_update_or_404(db: AsyncSession, model, object_id):
    """Lock and return one active row, rejecting missing/recycled parents."""

    obj = await db.scalar(
        select(model)
        .where(model.id == object_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if obj is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "RESOURCE_NOT_FOUND",
                "message": f"{model.__name__} not found.",
            },
        )
    return obj


async def lock_active_rows(db: AsyncSession, model, object_ids):
    """Lock active rows in deterministic UUID order and return them by id."""

    ordered_ids = sorted(set(object_ids), key=str)
    if not ordered_ids:
        return {}
    rows = (
        await db.scalars(
            select(model)
            .where(model.id.in_(ordered_ids))
            .order_by(model.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).all()
    return {row.id: row for row in rows}
