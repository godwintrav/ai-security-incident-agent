
import os
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db.base import Base

# Import all ORM models so SQLAlchemy registers their tables.
import app.db.models  # noqa: F401


TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://security:security_dev_password"
    "@localhost:5432/security_incidents_test",
)

# Never allow tests to target the application's development database.
if not TEST_DATABASE_URL.startswith("postgresql+asyncpg://"):
    raise RuntimeError("Tests require a PostgreSQL asyncpg database.")

database_name = TEST_DATABASE_URL.split("?", 1)[0].rsplit("/", 1)[-1]

if not database_name.endswith("_test"):
    raise RuntimeError(
        "TEST_DATABASE_URL must point to a database ending in '_test'."
    )


@pytest.fixture(scope="session")
def test_database_url() -> str:
    return TEST_DATABASE_URL


@pytest.fixture(scope="session", autouse=True)
def apply_test_migrations(test_database_url: str):
    """
    Apply the application's Alembic migrations to the test database.

    The test database must already exist.
    """
    config = Config("alembic.ini")

    # Alembic's env.py should read this setting or use
    # the environment variable below.
    previous_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = test_database_url

    try:
        command.upgrade(config, "head")
        yield
    finally:
        if previous_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous_url


@pytest_asyncio.fixture
async def test_session(
    apply_test_migrations,
) -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an isolated database session for each test.

    Each test gets a clean database by truncating the application's
    tables before and after execution.
    """
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        pool_pre_ping=True,
    )

    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    async def clean_tables():
        table_names = [
            f'"{table.name}"'
            for table in Base.metadata.sorted_tables
        ]

        if not table_names:
            return

        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "TRUNCATE TABLE "
                    + ", ".join(table_names)
                    + " RESTART IDENTITY CASCADE"
                )
            )

    try:
        await clean_tables()

        async with session_factory() as session:
            yield session

        await clean_tables()
    finally:
        await engine.dispose()
