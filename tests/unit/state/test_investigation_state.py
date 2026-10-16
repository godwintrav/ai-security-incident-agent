import pytest

from app.state.manager import (
    InvestigationStateManager,
    InvalidStateTransitionError,
)
from app.state.models import InvestigationStatus


@pytest.mark.asyncio
async def test_create_investigation(test_session):
    manager = InvestigationStateManager(test_session)

    investigation = await manager.create_investigation(
        description="Multiple failed SSH logins"
    )

    assert investigation.id is not None
    assert investigation.status == InvestigationStatus.PENDING


@pytest.mark.asyncio
async def test_valid_status_transition(test_session):
    manager = InvestigationStateManager(test_session)

    investigation = await manager.create_investigation(
        description="Suspicious authentication activity"
    )

    await manager.update_status(
        investigation.id,
        InvestigationStatus.INVESTIGATING,
    )

    updated = await manager.get_investigation(investigation.id)

    assert updated.status == InvestigationStatus.INVESTIGATING


@pytest.mark.asyncio
async def test_invalid_status_transition(test_session):
    manager = InvestigationStateManager(test_session)

    investigation = await manager.create_investigation(
        description="Potential phishing incident"
    )

    with pytest.raises(InvalidStateTransitionError):
        await manager.update_status(
            investigation.id,
            InvestigationStatus.COMPLETED,
        )


@pytest.mark.asyncio
async def test_duplicate_evidence_is_rejected(test_session):
    manager = InvestigationStateManager(test_session)

    investigation = await manager.create_investigation(
        description="Suspicious SSH activity"
    )

    evidence = {
        "id": "ev_001",
        "type": "authentication_log",
        "source": "auth.log",
        "timestamp": None,
        "content": {"message": "Failed SSH login"},
    }

    first = await manager.add_evidence(investigation.id, evidence)
    second = await manager.add_evidence(investigation.id, evidence)

    assert first is True
    assert second is False

    state = await manager.get_investigation(investigation.id)

    assert len(state.evidence) == 1