"""Unit tests for database session and connection."""

from sqlalchemy import text
from sqlalchemy.orm import Session
from backend.database.session import SessionLocal, get_db


def test_db_session_lifecycle() -> None:
    """Verify session generator properly opens and closes a session."""
    generator = get_db()
    session = next(generator)
    assert isinstance(session, Session)

    # Perform a probe query
    result = session.execute(text("SELECT 1")).scalar()
    assert result == 1

    # Close session via generator termination
    try:
        next(generator)
    except StopIteration:
        pass


def test_session_local_instantiation() -> None:
    """Verify SessionLocal produces a usable session."""
    session = SessionLocal()
    try:
        res = session.execute(text("SELECT 100")).scalar()
        assert res == 100
    finally:
        session.close()

