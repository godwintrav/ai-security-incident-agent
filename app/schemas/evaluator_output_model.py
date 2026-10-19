
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.schemas.evaluator_input_model import ToolName


class EvaluationDecision(str, Enum):
    FINALIZE = "finalize"
    REINVESTIGATE = "reinvestigate"
    REVISE_ANALYSIS = "revise_analysis"
    NEEDS_REVIEW = "needs_review"


class IssueCategory(str, Enum):
    UNSUPPORTED_FINDING = "unsupported_finding"
    INCORRECT_INTERPRETATION = "incorrect_interpretation"
    CONTRADICTORY_EVIDENCE = "contradictory_evidence"
    MISSING_INVESTIGATION = "missing_investigation"
    INCOMPLETE_ANALYSIS = "incomplete_analysis"
    INCORRECT_CLASSIFICATION = "incorrect_classification"
    INCORRECT_SEVERITY = "incorrect_severity"
    INVALID_IOC = "invalid_ioc"


class IssueSeverity(str, Enum):
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"


class EvaluationIssue(BaseModel):
    category: IssueCategory
    severity: IssueSeverity

    description: str

    finding_ids: list[str] = Field(default_factory=list)

    evidence_ids: list[str] = Field(default_factory=list)

    recommended_correction: str | None = None


class TaskPriority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class InvestigationTask(BaseModel):
    tool_name: ToolName

    arguments: dict[str, Any]

    reason: str
    priority: TaskPriority

    investigation_question: str

    expected_result: str


class GapStatus(str, Enum):
    NOT_INVESTIGATED = "not_investigated"
    NO_MATCHING_EVIDENCE = "no_matching_evidence"
    DATA_UNAVAILABLE = "data_unavailable"
    TOOL_UNAVAILABLE = "tool_unavailable"
    EXHAUSTED = "exhausted"


class GapImpact(str, Enum):
    CRITICAL = "critical"
    IMPORTANT = "important"
    MINOR = "minor"


class UnresolvedGap(BaseModel):
    question: str
    status: GapStatus
    impact: GapImpact

    reason: str

    consequence: str


class EvaluationResult(BaseModel):
    decision: EvaluationDecision

    analysis_is_grounded: bool
    analysis_is_complete: bool

    evaluation_confidence: float = Field(ge=0, le=1)

    issues: list[EvaluationIssue] = Field(default_factory=list)

    investigation_tasks: list[InvestigationTask] = Field(
        default_factory=list
    )

    unresolved_gaps: list[UnresolvedGap] = Field(
        default_factory=list
    )

    revision_instructions: list[str] = Field(
        default_factory=list
    )

    reasoning_summary: str

    @model_validator(mode="after")
    def validate_decision(self):
        if (
            self.decision == EvaluationDecision.REINVESTIGATE
            and not self.investigation_tasks
        ):
            raise ValueError(
                "reinvestigate requires at least one investigation task"
            )

        if (
            self.decision == EvaluationDecision.REVISE_ANALYSIS
            and not self.revision_instructions
        ):
            raise ValueError(
                "revise_analysis requires revision instructions"
            )

        if (
            self.decision != EvaluationDecision.REINVESTIGATE
            and self.investigation_tasks
        ):
            raise ValueError(
                "investigation_tasks must be empty unless reinvestigating"
            )

        return self
