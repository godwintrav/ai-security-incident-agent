from pydantic import BaseModel, ConfigDict, Field, field_validator
from datetime import datetime
from typing import Any
from uuid import UUID

# ---------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------

class CreateInvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(
        min_length=10,
        max_length=10_000,
        description=(
            "Description of the security incident or suspicious "
            "activity that needs to be investigated."
        ),
        examples=[
            "Investigate suspicious SSH authentication activity "
            "on production server prod-web-01."
        ],
    )

    logs: str = Field(
        min_length=1,
        max_length=2_000_000,
        description=(
            "Raw security logs submitted for investigation. "
            "The autonomous agent will analyze these logs "
            "and extract structured evidence."
        ),
    )

    @field_validator("description", "logs")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Field cannot be empty")

        return value.strip()


# ---------------------------------------------------------
# Response Schemas
# ---------------------------------------------------------

class CreateInvestigationResponse(BaseModel):
    id: UUID
    status: str
    message: str = "Investigation accepted and scheduled."


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    description: str
    incident_type: str | None = None
    status: str

    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    tool_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    iteration: int
    max_iterations: int

    final_report: dict[str, Any] | None = None
    error: str | None = None

    created_at: datetime
    updated_at: datetime