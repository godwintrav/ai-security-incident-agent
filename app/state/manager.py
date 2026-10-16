from typing import Any
from uuid import UUID

from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    InvestigationDB,
    InvestigationEventDB,
    InvestigationEvidenceDB,
)
from app.state.models import (
    InvestigationState,
    InvestigationStatus,
)


class InvestigationNotFoundError(Exception):
    pass


class InvalidStateTransitionError(Exception):
    pass


ALLOWED_TRANSITIONS = {
    InvestigationStatus.PENDING: {
        InvestigationStatus.INVESTIGATING,
        InvestigationStatus.FAILED,
    },
    InvestigationStatus.INVESTIGATING: {
        InvestigationStatus.ANALYZING,
        InvestigationStatus.FAILED,
        InvestigationStatus.NEEDS_REVIEW,
    },
    InvestigationStatus.ANALYZING: {
        InvestigationStatus.EVALUATING,
        InvestigationStatus.FAILED,
        InvestigationStatus.NEEDS_REVIEW,
    },
    InvestigationStatus.EVALUATING: {
        InvestigationStatus.INVESTIGATING,
        InvestigationStatus.COMPLETED,
        InvestigationStatus.NEEDS_REVIEW,
        InvestigationStatus.FAILED,
    },
    InvestigationStatus.COMPLETED: set(),
    InvestigationStatus.NEEDS_REVIEW: set(),
    InvestigationStatus.FAILED: set(),
}


class InvestigationStateManager:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def _get_locked(self, investigation_id: UUID) -> InvestigationDB:
        statement = (
            select(InvestigationDB)
            .where(InvestigationDB.id == investigation_id)
            .with_for_update()
        )

        result = await self.session.execute(statement)
        investigation = result.scalar_one_or_none()

        if investigation is None:
            raise InvestigationNotFoundError(
                f"Investigation {investigation_id} not found"
            )

        return investigation

    async def _record_event(
        self,
        investigation_id: UUID,
        event_type: str,
        message: str,
        event_data: dict[str, Any] | None = None,
    ) -> None:
        self.session.add(
            InvestigationEventDB(
                investigation_id=investigation_id,
                event_type=event_type,
                message=message,
                event_data=jsonable_encoder(event_data or {}),
            )
        )

    async def create_investigation(
        self,
        description: str,
        incident_type: str | None = None,
    ) -> InvestigationState:
        if not description.strip():
            raise ValueError("Incident description cannot be empty")

        investigation = InvestigationDB(
            description=description,
            incident_type=incident_type,
        )

        self.session.add(investigation)
        await self.session.flush()

        await self._record_event(
            investigation.id,
            "investigation_created",
            "Investigation created",
        )

        await self.session.commit()

        return await self.get_investigation(investigation.id)

    async def get_investigation(
        self,
        investigation_id: UUID,
    ) -> InvestigationState:
        investigation = await self.session.get(
            InvestigationDB,
            investigation_id,
        )

        if investigation is None:
            raise InvestigationNotFoundError(
                f"Investigation {investigation_id} not found"
            )

        result = await self.session.execute(
            select(InvestigationEvidenceDB)
            .where(
                InvestigationEvidenceDB.investigation_id
                == investigation_id
            )
            .order_by(InvestigationEvidenceDB.id)
        )

        evidence = [item.payload for item in result.scalars().all()]

        return InvestigationState(
            id=investigation.id,
            description=investigation.description,
            incident_type=investigation.incident_type,
            status=InvestigationStatus(investigation.status),
            evidence=evidence,
            tool_results=investigation.tool_results,
            cve_results=investigation.cve_results,
            playbook=investigation.playbook,
            analyses=investigation.analyses,
            iteration=investigation.iteration,
            max_iterations=investigation.max_iterations,
            final_report=investigation.final_report,
            error=investigation.error,
            created_at=investigation.created_at,
            updated_at=investigation.updated_at,
        )

    async def update_status(
        self,
        investigation_id: UUID,
        new_status: InvestigationStatus,
    ) -> None:
        try:
            investigation = await self._get_locked(investigation_id)

            current = InvestigationStatus(investigation.status)

            if new_status not in ALLOWED_TRANSITIONS[current]:
                raise InvalidStateTransitionError(
                    f"Cannot transition from {current.value} "
                    f"to {new_status.value}"
                )

            investigation.status = new_status.value

            await self._record_event(
                investigation_id,
                "status_changed",
                f"Investigation status changed to {new_status.value}",
                {"previous": current.value, "current": new_status.value},
            )

            await self.session.commit()
        except Exception:
            await self.session.rollback()
            raise

    async def add_evidence(
        self,
        investigation_id: UUID,
        evidence: dict[str, Any],
    ) -> bool:
        evidence_id = evidence.get("id")

        if not isinstance(evidence_id, str) or not evidence_id.strip():
            raise ValueError("Evidence must have a non-empty string ID")

        try:
            await self._get_locked(investigation_id)

            existing = await self.session.scalar(
                select(InvestigationEvidenceDB.id).where(
                    InvestigationEvidenceDB.investigation_id
                    == investigation_id,
                    InvestigationEvidenceDB.evidence_id == evidence_id,
                )
            )

            if existing is not None:
                await self.session.rollback()
                return False

            self.session.add(
                InvestigationEvidenceDB(
                    investigation_id=investigation_id,
                    evidence_id=evidence_id,
                    payload=jsonable_encoder(evidence),
                )
            )

            await self._record_event(
                investigation_id,
                "evidence_added",
                "New evidence collected",
                {"evidence_id": evidence_id},
            )

            await self.session.commit()
            return True
        except Exception:
            await self.session.rollback()
            raise

    async def add_tool_result(
        self,
        investigation_id: UUID,
        tool_name: str,
        result: dict[str, Any],
    ) -> None:
        try:
            investigation = await self._get_locked(investigation_id)

            investigation.tool_results = [
                *investigation.tool_results,
                {
                    "tool": tool_name,
                    "result": jsonable_encoder(result),
                },
            ]

            await self._record_event(
                investigation_id,
                "tool_completed",
                f"{tool_name} completed",
                {"tool": tool_name},
            )

            await self.session.commit()
        except Exception:
            await self.session.rollback()
            raise

    async def add_analysis(
        self,
        investigation_id: UUID,
        analysis: dict[str, Any],
    ) -> None:
        try:
            investigation = await self._get_locked(investigation_id)

            investigation.analyses = [
                *investigation.analyses,
                jsonable_encoder(analysis),
            ]

            await self._record_event(
                investigation_id,
                "analysis_completed",
                "Incident analysis completed",
            )

            await self.session.commit()
        except Exception:
            await self.session.rollback()
            raise