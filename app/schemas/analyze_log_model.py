from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class LogEvidence(BaseModel):
    key: str = Field(
        description="Name of the extracted evidence."
    )

    value: Any = Field(
        description="Value of the extracted evidence."
    )

    timestamp: datetime | None = Field(
        default=None,
        description=(
            "Timestamp associated with this evidence, extracted "
            "from the logs. Use an ISO 8601 timestamp with timezone "
            "when available. Return null if no reliable timestamp "
            "can be determined. Do not invent timestamps."
        ),
    )


class LogAnalysis(BaseModel):
    objective: str = Field(
        description="The investigation objective used to analyze the logs."
    )

    evidence: list[LogEvidence] = Field(
        description="Structured evidence extracted from the logs relevant to the objective."
    )

    observations: list[str] = Field(
        description="Direct observations supported by the logs."
    )