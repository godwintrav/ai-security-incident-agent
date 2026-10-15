# app/schemas/incident_analysis.py

from typing import Any

from pydantic import BaseModel, Field


class Incident(BaseModel):
    description: str
    incident_type: str | None = None


class Evidence(BaseModel):
    id: str
    type: str
    source: str
    timestamp: str | None = None
    content: dict[str, Any]


class IncidentAnalysisInput(BaseModel):
    incident: Incident
    evidence: list[Evidence] = Field(default_factory=list)
    security_knowledge: list[str] = Field(default_factory=list)
    playbook: dict[str, Any] | None = None
    cve_results: list[dict[str, Any]] = Field(default_factory=list)