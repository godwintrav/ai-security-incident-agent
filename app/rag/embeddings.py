import os
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv

from app.rag.chunker import Result

class Embeddings():

    """This class is responsible for embedding data chunks after it has been splitted from the chunker class"""


    def __init__(self):
        load_dotenv(override=True)
        self.__embedding_model = os.getenv(
                "EMBEDDING_MODEL",
                "BAAI/bge-base-en-v1.5",
            )
        self.__encoder = SentenceTransformer(self.__embedding_model)

    def embed_list_data(self, chunks: list[Result]):
        """This function is used to encode multiple chunks of data. Best used when initially encoding knowledge base data"""
        data = [chunk.page_content for chunk in chunks]
        vectors = self.__encoder.encode(data).astype(float).tolist()
        return vectors

    def embed_data(self, data: str):
            """This function is used to encode a single piece of data"""
            vector = self.__encoder.encode(data)
            return vector

    