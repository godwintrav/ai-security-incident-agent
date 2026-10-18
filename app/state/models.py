from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class InvestigationStatus(str, Enum):
    PENDING = "pending"
    INVESTIGATING = "investigating"
    ANALYZING = "analyzing"
    EVALUATING = "evaluating"
    COMPLETED = "completed"
    NEEDS_REVIEW = "needs_review"
    FAILED = "failed"


class InvestigationState(BaseModel):
    id: UUID
    description: str
    incident_type: str | None = None
    logs: str
    status: InvestigationStatus

    evidence: list[dict[str, Any]] = Field(default_factory=list)
    tool_results: list[dict[str, Any]] = Field(default_factory=list)
    analyses: list[dict[str, Any]] = Field(default_factory=list)

    iteration: int = 0
    max_iterations: int = 5

    final_report: dict[str, Any] | None = None
    error: str | None = None

    created_at: datetime
    updated_at: datetime