"""Global pytest configuration and fixtures."""

from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.core.config import Settings, get_settings
from backend.database.base import Base
from backend.database.session import get_db
from backend.main import create_app


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Provide deterministic settings for test runs."""
    return Settings(
        app_name="AGENTGUARD-TEST",
        app_env="testing",
        debug=True,
        log_level="DEBUG",
        database_url="sqlite:///:memory:",
        cors_origins=["http://testserver"],
    )


@pytest.fixture(scope="session")
def test_db_engine(test_settings: Settings):
    """Create an in-memory SQLite engine for tests."""
    engine = create_engine(
        test_settings.database_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(test_db_engine) -> Generator[Session, None, None]:
    """Yield an isolated database session per test with automatic rollback."""
    connection = test_db_engine.connect()
    transaction = connection.begin()
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=connection)
    session = session_factory()

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def client(test_settings: Settings, db_session: Session) -> Generator[TestClient, None, None]:
    """Provide a FastAPI TestClient with overridden dependencies for testing."""
    app = create_app(settings=test_settings)

    # Override get_db dependency to point to the test session
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_settings] = lambda: test_settings

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()

