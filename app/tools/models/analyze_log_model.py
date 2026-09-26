from typing import Any

from pydantic import BaseModel, Field


class LogEvidence(BaseModel):
    key: str = Field(
        description="Name of the extracted evidence."
    )

    value: Any = Field(
        description="Value of the extracted evidence."
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