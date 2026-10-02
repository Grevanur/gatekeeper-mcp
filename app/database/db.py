"""SQLite engine and session management."""

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.database.models import Base


def _prepare_sqlite_path(database_url: str) -> None:
    """Create the parent directory for a relative file-backed SQLite database."""

    prefix = "sqlite:///"
    if not database_url.startswith(prefix) or database_url == "sqlite:///:memory:":
        return

    database_path = Path(database_url.removeprefix(prefix))
    if not database_path.is_absolute():
        database_path.parent.mkdir(parents=True, exist_ok=True)


def create_database_engine(database_url: str | None = None) -> Engine:
    """Create an engine suitable for SQLite-backed V1 persistence."""

    url = database_url or get_settings().database_url
    _prepare_sqlite_path(url)
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


engine = create_database_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def initialize_database() -> None:
    """Create declared gateway tables during application startup."""

    Base.metadata.create_all(bind=engine)


def get_db_session() -> Generator[Session, None, None]:
    """Yield a request-scoped database session."""

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

