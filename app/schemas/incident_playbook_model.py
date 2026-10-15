from pydantic import BaseModel


class IncidentPlaybook(BaseModel):
    incident_type: str
    objective: str
    investigation_steps: list[str]
    evidence_sources: list[str]
    completion_criteria: list[str]