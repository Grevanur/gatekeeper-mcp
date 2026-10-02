"""Shared SQLAlchemy model base.

Concrete audit and approval models are deliberately introduced in Phase 4.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for gateway persistence models."""

