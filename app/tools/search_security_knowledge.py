from typing import Any

from app.rag.retriever import Retriever
from app.schemas.search_security_knowledge_model import SecurityKnowledgeResult, SecurityKnowledgeSearchResult

class SearchSecurityKnowledge():
    """This class is used to call our rag pipeline and search for information using our rag pipeline"""

    def __init__(self):
        self.retriever = Retriever()

    def search(self, query: str) -> SecurityKnowledgeSearchResult:
        chunks = self.retriever.retrieve_context(query)

        return SecurityKnowledgeSearchResult(
            results=[
                SecurityKnowledgeResult(
                    content=chunk.page_content,
                    source=chunk.metadata["source"],
                    category=chunk.metadata["category"],
                    incident_type=chunk.metadata.get("incident_type"),
                )
                for chunk in chunks
            ]
        )

    def collect_tool_result_from_state(self, tool_results: list[dict[str, Any]], iteration: int) -> list[str] | None:
        for tool_result in tool_results:
            tool_name = tool_result.get("name")
            tool_iteration = tool_result.get("iteration")
            if tool_name == "search_security_knowledge":
                if tool_iteration == iteration:
                    return tool_result

        return []
