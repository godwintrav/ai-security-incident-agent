
# app/api/routes/investigations.py

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    status,
)

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import InvestigationRunner, get_investigation_runner
from app.db.session import get_db_session
from app.schemas.investigation_api_model import CreateInvestigationRequest, CreateInvestigationResponse, InvestigationResponse
from app.state.manager import (
    InvestigationNotFoundError,
    InvestigationStateManager,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/investigations",
    tags=["Investigations"],
)





# ---------------------------------------------------------
# POST /investigations
# ---------------------------------------------------------

@router.post(
    "",
    response_model=CreateInvestigationResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create and start a security investigation",
)
async def create_investigation(
    payload: CreateInvestigationRequest,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db_session),
    investigation_runner: InvestigationRunner = Depends(get_investigation_runner),
) -> CreateInvestigationResponse:
    """
    Create a new investigation and initiate autonomous
    investigation in the background.

    The user provides:
      - description
      - raw logs

    The agent is responsible for:
      - selecting relevant tools
      - extracting evidence
      - investigating suspicious activity

    Incident classification is performed later by the
    fine-tuned specialist model.
    """

    manager = InvestigationStateManager(session)

    investigation = await manager.create_investigation(
        description=payload.description,
        logs=payload.logs,
    )

    logger.info(
        "Investigation created: %s",
        investigation.id,
    )

    # The runner must create its own database session.
    # Never pass the request-scoped session into a
    # background task.
    background_tasks.add_task(
        investigation_runner,
        investigation.id,
    )

    return CreateInvestigationResponse(
        id=investigation.id,
        status=investigation.status.value,
    )


# ---------------------------------------------------------
# GET /investigations/{investigation_id}
# ---------------------------------------------------------

@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
    summary="Retrieve investigation state",
)
async def get_investigation(
    investigation_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> InvestigationResponse:
    """
    Retrieve the latest persisted investigation state.

    Raw logs are intentionally excluded from the response.
    """

    manager = InvestigationStateManager(session)

    try:
        investigation = await manager.get_investigation(
            investigation_id,
        )

    except InvestigationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        ) from exc

    return InvestigationResponse(
        id=investigation.id,
        description=investigation.description,
        incident_type=investigation.incident_type,
        status=investigation.status.value,
        evidence=investigation.evidence,
        tool_results=investigation.tool_results,
        analyses=investigation.analyses,
        iteration=investigation.iteration,
        max_iterations=investigation.max_iterations,
        final_report=investigation.final_report,
        error=investigation.error,
        created_at=investigation.created_at,
        updated_at=investigation.updated_at,
    )
