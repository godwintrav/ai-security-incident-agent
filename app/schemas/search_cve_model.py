from pydantic import BaseModel, Field
from typing import Any

class CVEInfo(BaseModel):
    cve_id: str
    description: str
    published: str | None = None
    last_modified: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class CVESearchResult(BaseModel):
    product: str
    version: str | None = None
    total_results: int
    vulnerabilities: list[CVEInfo]