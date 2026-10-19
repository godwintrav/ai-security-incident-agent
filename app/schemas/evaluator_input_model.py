
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ToolName(str, Enum):
    ANALYZE_LOG = "analyze_log"
    GET_INCIDENT_PLAYBOOK = "get_incident_playbook"
    SEARCH_CVE = "search_cve"
    SEARCH_SECURITY_KNOWLEDGE = "search_security_knowledge"


class ToolExecutionStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class ToolOutcome(str, Enum):
    EVIDENCE_FOUND = "evidence_found"
    NO_MATCHING_EVIDENCE = "no_matching_evidence"
    CONTEXT_FOUND = "context_found"
    NO_MATCHING_CONTEXT = "no_matching_context"
    NOT_APPLICABLE = "not_applicable"


class InvestigationAttempt(BaseModel):
    tool_name: ToolName

    arguments: dict[str, Any]

    status: ToolExecutionStatus
    outcome: ToolOutcome

    evidence_ids: list[str] = Field(default_factory=list)

    result_summary: str | None = None

    tool_result_id: str | None = None

    error: str | None = None
    executed_at: datetime


class ToolCapability(BaseModel):
    tool_name: ToolName
    description: str
    available: bool

    required_arguments: list[str]

    capabilities: list[str] = Field(default_factory=list)

    limitations: list[str] = Field(default_factory=list)


class DataSourceAvailability(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class AvailableDataSource(BaseModel):
    name: str
    availability: DataSourceAvailability

    description: str

    log_types: list[str] = Field(default_factory=list)

    limitations: list[str] = Field(default_factory=list)


class PreviousEvaluation(BaseModel):
    decision: str
    reasoning_summary: str

    requested_tasks: list[str] = Field(default_factory=list)

    unresolved_questions: list[str] = Field(default_factory=list)


class IterationBudget(BaseModel):
    specialist_calls_used: int = Field(ge=0)
    specialist_calls_remaining: int = Field(ge=0)

    # Limit the number of tool calls recommended in one evaluation.
    max_new_tasks: int = Field(default=3, ge=0)


class EvaluationInput(BaseModel):
    investigation_id: str
    description: str

    # Latest specialist classification.
    incident_type: str

    # Persisted evidence produced by analyze_log.
    # Each item must contain its ID and relevant source content.
    evidence: list[dict[str, Any]]

    # Latest specialist IncidentAnalysis, including:
    # incident_type, severity, confidence, findings,
    # iocs, missing_evidence and analysis_summary.
    latest_analysis: dict[str, Any]

    # Retrieved incident playbook, if available.
    playbook: dict[str, Any] | None = None

    # Previous tool calls, including empty and failed results.
    tool_history: list[InvestigationAttempt] = Field(
        default_factory=list
    )

    available_tools: list[ToolCapability]

    available_data_sources: list[AvailableDataSource] = Field(
        default_factory=list
    )

    previous_evaluations: list[PreviousEvaluation] = Field(
        default_factory=list
    )

    iteration_budget: IterationBudget
