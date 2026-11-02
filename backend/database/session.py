"""Database engine and session management for AGENTGUARD."""

from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.core.config import get_settings
from backend.core.logging import get_logger
from backend.database.base import Base

logger = get_logger("database")


def _get_engine_args(database_url: str) -> dict:
    """Prepare engine connection parameters depending on the database backend."""
    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        # Ensure SQLite target directory exists if a file path is specified
        if "///" in database_url:
            db_path = database_url.split("///")[-1]
            if db_path and db_path != ":memory:":
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    return connect_args


settings = get_settings()
engine = create_engine(
    settings.database_url,
    connect_args=_get_engine_args(settings.database_url),
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding an isolated database session per request."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Initialize database schemas defined by SQLAlchemy Base metadata."""
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialization completed.")

