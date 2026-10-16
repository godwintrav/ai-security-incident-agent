from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.state.manager import InvestigationStateManager


def get_state_manager(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> InvestigationStateManager:
    return InvestigationStateManager(session)