"""SQLite engine and session management."""

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, text
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
    """Create tables and apply the small additive V2 SQLite migration."""

    Base.metadata.create_all(bind=engine)
    additions = {
        "approval_requests": {
            "workflow_id": "VARCHAR(128)",
            "stage": "VARCHAR(32) DEFAULT 'PRIMARY'",
            "primary_expires_at": "DATETIME",
            "fallback_started_at": "DATETIME",
            "fallback_expires_at": "DATETIME",
            "break_glass_expires_at": "DATETIME",
            "break_glass_by": "VARCHAR(128)",
            "break_glass_reason": "TEXT",
        },
        "audit_events": {"metadata": "JSON DEFAULT '{}'"},
    }
    with engine.begin() as connection:
        for table_name, columns in additions.items():
            existing = {row[1] for row in connection.execute(text(f"PRAGMA table_info({table_name})"))}
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {name} {definition}"))


def get_db_session() -> Generator[Session, None, None]:
    """Yield a request-scoped database session."""

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
