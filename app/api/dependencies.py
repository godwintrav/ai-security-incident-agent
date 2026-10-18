from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.investigation_agent import AutonomousInvestigationAgent
from app.db.session import get_db_session, AsyncSessionLocal
from app.state.manager import InvestigationStateManager

from collections.abc import Awaitable, Callable
from uuid import UUID

InvestigationRunner = Callable[[UUID], Awaitable[None]]


def get_investigation_runner() -> InvestigationRunner:
    return run_investigation


def get_state_manager(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> InvestigationStateManager:
    return InvestigationStateManager(session)

async def run_investigation(investigation_id: UUID) -> None:
    print(f"Investigating: {investigation_id}")
    async with AsyncSessionLocal() as session:
        manager = InvestigationStateManager(session)
        agent = AutonomousInvestigationAgent(investigation_id, manager)
        await agent.run_investigation()