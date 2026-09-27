from app.rag.retriever import Retriever
from app.tools.models.search_security_knowledge_model import SecurityKnowledgeResult, SecurityKnowledgeSearchResult

class SearchSecurityKnowledge():
    """This class is used to call our rag pipeline and search for information using our rag pipeline"""

    def __init__(self):
        self.retriever = Retriever()

    def search(self, query: str) -> SecurityKnowledgeSearchResult :
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
