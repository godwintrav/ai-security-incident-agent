from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.config.settings import get_settings
from app.db.session import AsyncSessionLocal, engine
from app.state.manager import (
    InvestigationNotFoundError,
    InvalidStateTransitionError,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: verify the database connection.
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))

    yield

    # Shutdown: close database connections.
    await engine.dispose()


app = FastAPI(
    title=get_settings().app_name,
    lifespan=lifespan,
)


@app.exception_handler(InvestigationNotFoundError)
async def investigation_not_found_handler(
    request: Request,
    exc: InvestigationNotFoundError,
):
    return JSONResponse(
        status_code=404,
        content={"detail": str(exc)},
    )


@app.exception_handler(InvalidStateTransitionError)
async def invalid_transition_handler(
    request: Request,
    exc: InvalidStateTransitionError,
):
    return JSONResponse(
        status_code=409,
        content={"detail": str(exc)},
    )


@app.get("/health")
async def health():
    async with AsyncSessionLocal() as session:
        await session.execute(text("SELECT 1"))

    return {"status": "healthy"}