
from app.rag.chroma import Chroma
from app.rag.chunker import Chunker
from app.rag.embeddings import Embeddings
from app.rag.loader import Loader


class Ingestion():
    """This class is responsible for ingesting data from the knowldge base and embedding and storing it"""

    def __init__(self):
        self.loader = Loader()
        self.chunker = Chunker()
        self.embedder = Embeddings()
        self.chroma = Chroma()

    def ingest_data(self) -> None:
        documents = self.loader.fetch_documents_langchain()
        chunks = self.chunker.create_chunks_with_markdown_splitter(documents=documents)
        vectors = self.embedder.embed_list_data(chunks=chunks)

        # store vector in chroma DB
        self.chroma.store_kb_vectors(chunks, vectors)
        print("Data ingestion complete")
