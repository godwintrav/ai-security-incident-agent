from pydantic import BaseModel

class SecurityKnowledgeResult(BaseModel):
    content: str
    source: str
    category: str
    incident_type: str | None = None

class SecurityKnowledgeSearchResult(BaseModel):
    results: list[SecurityKnowledgeResult]