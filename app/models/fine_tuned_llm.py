from typing import Literal

from pydantic import BaseModel, Field


IncidentType = Literal[
    "credential_compromise",
    "phishing",
    "malware",
    "suspicious_network_activity",
    "unknown",
]

Severity = Literal[
    "low",
    "medium",
    "high",
    "critical",
]


class IOC(BaseModel):
    type: str = Field(
        description="Type of indicator of compromise, such as IP address, "
        "hostname, username, domain, URL, filename, process, or file hash."
    )

    value: str = Field(
        description="The actual indicator value."
    )

    evidence_ids: list[str] = Field(
        description="IDs of the evidence items that directly support this IOC."
    )

    confidence: float = Field(
        description="Confidence that this indicator is relevant to the incident.",
        ge=0.0,
        le=1.0,
    )


class Finding(BaseModel):
    title: str = Field(
        description="Short title describing the finding."
    )

    description: str = Field(
        description="Brief description of the finding."
    )

    assessment: str = Field(
        description="Evidence-grounded assessment explaining what the evidence supports."
    )

    evidence_ids: list[str] = Field(
        description="IDs of the evidence items supporting this finding."
    )

    confidence: float = Field(
        description="Confidence in the finding.",
        ge=0.0,
        le=1.0,
    )


class MissingEvidence(BaseModel):
    description: str = Field(
        description="Evidence or context that is currently missing."
    )

    reason: str = Field(
        description="Why the missing evidence is important to the investigation."
    )

    priority: Literal["low", "medium", "high"] = Field(
        description="Priority for obtaining the missing evidence."
    )

    suggested_source: str = Field(
        description="Recommended source from which the missing evidence could be obtained."
    )


class IncidentAnalysis(BaseModel):
    incident_type: IncidentType = Field(
        description="Classified type of security incident."
    )

    severity: Severity = Field(
        description="Severity of the incident based on the supplied evidence."
    )

    confidence: float = Field(
        description="Overall confidence in the incident analysis.",
        ge=0.0,
        le=1.0,
    )

    iocs: list[IOC] = Field(
        description="Indicators of compromise identified from the supplied evidence."
    )

    findings: list[Finding] = Field(
        description="Evidence-grounded findings from the investigation."
    )

    missing_evidence: list[MissingEvidence] = Field(
        description="Important evidence that is still missing from the investigation."
    )

    analysis_summary: str = Field(
        description="Concise evidence-grounded summary of the incident analysis."
    )