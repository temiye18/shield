import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

# ── SQLite compatibility for PostgreSQL types ──────────────────
# Must be imported and registered BEFORE any models are loaded
from sqlalchemy.dialects.postgresql import JSONB, INET
from sqlalchemy import JSON, String, Text
from sqlalchemy.types import TypeDecorator

# Register compilation overrides so JSONB → JSON and INET → String on SQLite
import sqlalchemy.dialects.sqlite.base as sqlite_dialect

# Monkey-patch: teach SQLite how to compile JSONB and INET
from sqlalchemy.ext.compiler import compiles

@compiles(JSONB, "sqlite")
def compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"

@compiles(INET, "sqlite")
def compile_inet_sqlite(type_, compiler, **kw):
    return "VARCHAR(45)"

# ── Now import app modules ─────────────────────────────────────
from app.database import Base, get_db
from app.main import app

# Use in-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="function", autouse=True)
def setup_database():
    """Create all tables before each test, drop after."""

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    # Import models to register them with Base.metadata
    from app.models import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    """Provide a test HTTP client."""
    return TestClient(app)


@pytest.fixture
def db_session():
    """Provide a test database session."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def auth_headers(client):
    """Register a test user and return auth headers."""
    response = client.post(
        "/v1/auth/register",
        json={
            "email": "test@example.com",
            "password": "testpassword123",
            "full_name": "Test User",
            "organization_name": "Test Org",
        },
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def regular_user_headers(client, auth_headers):
    """Register a regular (non-admin) user and return auth headers."""
    response = client.post(
        "/v1/auth/register",
        json={
            "email": "regular@example.com",
            "password": "testpassword123",
            "full_name": "Regular User",
        },
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
