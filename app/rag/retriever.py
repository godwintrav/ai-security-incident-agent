
from app.prompts.prompts import CHUNKS_RERANKING_SYSTEM_PROMPT, chunks_reranking_user_prompt, rewrite_query_prompt
from app.rag.chroma import Chroma
from app.rag.chunker import Result
from app.rag.embeddings import Embeddings
import os
from openai import OpenAI
from litellm import completion
from pydantic import BaseModel, Field
import time

class RankOrder(BaseModel):
    order: list[int] = Field(
        description="The order of relevance of chunks, from most relevant to least relevant, by chunk id number"
    )


class Retriever():
    """This class is responsible for retrieving data from the vector DB with semantic search"""

    def __init__(self):
        self.embedder = Embeddings()
        self.chroma = Chroma()
        self.RETRIEVAL_K = 5
        self.FINAL_K = 3
        self.APP_ENV = os.getenv(
                        "APP_ENV",
                        "development"
                    )
        if self.APP_ENV == 'production':
            self.API_KEY = os.getenv(
                                    "OPENAI_API_KEY",
                                    "development"
                                )
        else:
            self.API_KEY = "ollama"
        self.MODEL = "ollama/gpt-oss:20b"
        self.openai = OpenAI(base_url="http://localhost:11434/v1", api_key=self.API_KEY) if self.APP_ENV == 'development' else OpenAI(api_key=self.API_KEY)

    def rewrite_query(self, query) -> str:
        prompt = rewrite_query_prompt(query=query)
        response = completion(
            model=self.MODEL,
            messages=[{"role": "system", "content": prompt}]
        )
        return response.choices[0].message.content.strip()

    def rerank_chunks(self, question: str, chunks: list[Result]):
        for index, chunk in enumerate(chunks):
                print(f"# CHUNK ID: {index + 1}")
        
                valid_ids = list(range(1, len(chunks) + 1))

        user_prompt = chunks_reranking_user_prompt(chunks=chunks, question=question, valid_ids=valid_ids)
        messages = [
        {"role": "system", "content": CHUNKS_RERANKING_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
        ]

        response = completion(
            model=self.MODEL,
            messages=messages,
        )

        print("Rerank response:", response.choices[0].message.content)
        reply = response.choices[0].message.content
        order = RankOrder.model_validate_json(reply).order

        expected = set(valid_ids)

        # Remove invalid IDs and duplicates while preserving order
        cleaned = []
        seen = set()

        for chunk_id in order:
            if chunk_id in expected and chunk_id not in seen:
                cleaned.append(chunk_id)
                seen.add(chunk_id)

        # Append any missing IDs
        for chunk_id in valid_ids:
            if chunk_id not in seen:
                cleaned.append(chunk_id)

        order = cleaned

        print("Final order:", order)

        return [chunks[i - 1] for i in order]

    def merge_chunks(chunks, chunks2) -> list[Result]:
        merged = chunks[:]
        existing = [chunk.page_content for chunk in chunks]
        for chunk in chunks2:
            if chunk.page_content not in existing:
                merged.append(chunk)
        return merged

    def retrieve_context_unranked(self, question: str) -> list[Result]:
        vector_query = self.embedder.embed_data(question)
        chunks: list[Result] = self.chroma.similiarity_search(vector_query, self.RETRIEVAL_K)
        return chunks

    def retrieve_context(self, original_question: str):
        start = time.perf_counter()

        t = time.perf_counter()
        rewritten_question = self.rewrite_query(original_question)
        print(f"rewrite_query: {time.perf_counter() - t:.3f}s")

        # t = time.perf_counter()
        # time.sleep(1.5)
        # print(f"sleep 1: {time.perf_counter() - t:.3f}s")

        t = time.perf_counter()
        chunks1 = self.retrieve_context_unranked(original_question)
        print(f"fetch_context_unranked (original): {time.perf_counter() - t:.3f}s")

        t = time.perf_counter()
        chunks2 = self.retrieve_context_unranked(rewritten_question)
        print(f"fetch_context_unranked (rewritten): {time.perf_counter() - t:.3f}s")

        t = time.perf_counter()
        chunks = self.merge_chunks(chunks1, chunks2)
        print(f"merge_chunks: {time.perf_counter() - t:.3f}s")

        t = time.perf_counter()
        reranked = self.rerank_chunks(original_question, chunks)
        print(f"rerank: {time.perf_counter() - t:.3f}s")

        # t = time.perf_counter()
        # time.sleep(1.5)
        # print(f"sleep 2: {time.perf_counter() - t:.3f}s")

        print(f"Total: {time.perf_counter() - start:.3f}s")

        return reranked[:self.FINAL_K]