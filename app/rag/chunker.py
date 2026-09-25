from typing import Any

from chromadb import Metadata
from pydantic import BaseModel
from langchain_text_splitters import MarkdownTextSplitter
from langchain_core.documents import Document

from app.rag.loader import Loader

class Result(BaseModel):
    page_content: str
    metadata: Metadata

class Chunker():
    """This class only responsibility is chunking documents to smaller chunks to be used by the embedding class"""

    def create_chunks_with_markdown_splitter(self, documents: Document) -> list[Result]:
        text_splitter = MarkdownTextSplitter()
        uncasted_chunks = text_splitter.split_documents(documents)

        chunks: list[Result] = []
        chunk_index_store = {}
        for uncasted_chunk in uncasted_chunks:
            if f"{uncasted_chunk.metadata.get('category')}/{uncasted_chunk.metadata.get('document')}" in chunk_index_store:
                chunk_index_store[uncasted_chunk.metadata.get('document')] = chunk_index_store[uncasted_chunk.metadata.get('document')] + 1
            else:
                chunk_index_store[uncasted_chunk.metadata.get('document')] = 0

            uncasted_chunk.metadata['chunk_index'] = chunk_index_store[uncasted_chunk.metadata.get('document')]
            print(uncasted_chunk.metadata.get('document'), uncasted_chunk.metadata.get('chunk_index'))
            chunk = Result(
                page_content=uncasted_chunk.page_content,
                metadata=uncasted_chunk.metadata
            )
            chunks.append(chunk)
        return chunks


# def main():
#     loader = Loader()
#     documents = loader.fetch_documents_langchain()
#     chunker = Chunker()
#     results = chunker.create_chunks_with_markdown_splitter(documents)

# if __name__ == "__main__":
#     main()
