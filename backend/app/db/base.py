from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass

# Import mapped classes so Alembic sees the complete metadata.
from .. import models  # noqa: E402,F401
