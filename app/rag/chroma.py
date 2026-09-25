import os
from dotenv import load_dotenv
import chromadb

from .chunker import Result

class Chroma():
    """This class is responsible for using chroma to store vectors and retrieve similar vectors"""

    def __init__(self):
        load_dotenv(override=True)
        self.DB_NAME = os.getenv(
                "CHROMA_DB_NAME",
                "knowledge_base_vectorstore"
            )
        self.client = chromadb.PersistentClient(path=self.DB_NAME)
        self.collection_name = 'knowledge_base'

    def store_kb_vectors(self, chunks: list[Result], vectors):
        if self.collection_name in [collection.name for collection in self.client.list_collections()]:
            self.client.delete_collection(self.collection_name)

        collection = self.client.get_or_create_collection(self.DB_NAME)

        texts = [chunk.page_content for chunk in chunks]
        metas = [chunk.metadata for chunk in chunks]
        ids = [f"doc_{i}" for i in range(len(chunks))]
        collection.add(ids=ids, documents=texts, embeddings=vectors, metadatas=metas)

    def similiarity_search(self, vector_query, RETRIEVAL_K = 10) -> list[Result]:
        collection = self.client.get_or_create_collection(self.DB_NAME)
        results = collection.query(query_embeddings=[vector_query], n_results=RETRIEVAL_K)
        chunks = []
        for result in zip(results["documents"][0], results["metadatas"][0]):
            chunks.append(Result(page_content=result[0], metadata=result[1]))
        return chunks
        