import json
from pathlib import Path
from typing import Any

from app.schemas.incident_playbook_model import IncidentPlaybook

class IncidentPlaybookRetriever():
    """This class is responsible for fetching and returning incident playbooks for specific incidents"""

    def __init__(self):
        self.PLAYBOOK_DIR = Path("data/knowledge_base/playbooks")

    def get_incident_playbook(
        self,
        incident_type: str,
    ) -> IncidentPlaybook:

        playbook_path = self.PLAYBOOK_DIR / f"{incident_type}.json"

        if not playbook_path.exists():
            raise ValueError(
                f"No playbook found for incident type: {incident_type}"
            )

        with playbook_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        return IncidentPlaybook.model_validate(data)

    def collect_tool_result_from_state(self, tool_results: list[dict[str, Any]], iteration: int) -> dict[str, Any] | None:
        for tool_result in tool_results:
            tool_name = tool_result.get("name")
            tool_iteration = tool_result.get("iteration")
            if tool_name == "get_incident_playbook":
                if tool_iteration == iteration:
                    return tool_result

        return None