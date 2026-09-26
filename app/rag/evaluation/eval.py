import sys
import math
from pydantic import BaseModel, Field
from litellm import completion
from dotenv import load_dotenv

from app.prompts.prompts import CHUNK_RELEVANCE_JUDGE_SYSTEM_PROMPT, COVERAGE_JUDGE_SYSTEM_PROMPT, OVERALL_RELEVANCE_JUDGE_SYSTEM_PROMPT
from app.rag.chunker import Result
from app.rag.evaluation.test import TestQuestion, load_tests
from app.rag.retriever import Retriever


load_dotenv(override=True)

MODEL = "ollama/gpt-oss:20b"
db_name = "vector_db"


class RetrievalEval(BaseModel):
    """Evaluation metrics for retrieval performance."""

    mrr: float = Field(description="Mean Reciprocal Rank - average across all keywords")
    ndcg: float = Field(description="Normalized Discounted Cumulative Gain (binary relevance)")
    keywords_found: int = Field(description="Number of keywords found in top-k results")
    total_keywords: int = Field(description="Total number of keywords to find")
    keyword_coverage: float = Field(description="Percentage of keywords found")

class ChunkRelevanceEval(BaseModel):
    """LLM-as-a-judge evaluation of chunk relevance."""

    chunk_id: int = Field(
        description="The id of the chunk in the list"
    )
    relevance_score: int = Field(
        description="How relevant the chunk is to the question. Must be an integer from 1 to 5.",
        ge=1,
        le=5,
    )


class ChunksRelevanceEval(BaseModel):
    """LLM-as-a-judge evaluation of chunks relevance."""

    chunks: list[ChunkRelevanceEval] = Field(
        description="The array of the returned chunks relevance by the LLM"
    )

class MeanChunkRelevanceEval(BaseModel):
    """Mean Chunk Relevance of result of LLM-as-a-judge evaluation of chunks relevance."""

    score: float = Field(
            description="This is the score of the mean chunk relevance by averaging the relevance score against the total"
        )

class OverallRelevanceEval(BaseModel):
    """LLM-as-a-judge evaluation of the retrieved context as a whole."""

    relevance_score: int = Field(
        description=(
            "How relevant the retrieved chunks are as a whole to the question. "
            "Must be an integer from 1 to 5."
        ),
        ge=1,
        le=5,
    )


class CoverageEval(BaseModel):
    """LLM-as-a-judge evaluation of retrieved context coverage."""

    coverage_score: int = Field(
        description=(
            "How completely the retrieved chunks cover the information "
            "needed to support the reference answer. "
            "Must be an integer from 1 to 5."
        ),
        ge=1,
        le=5,
    )

class CompleteLLMAsAJudgeEval(BaseModel):
    """LLM-as-a-judge complete evaluation of the retrieved context as a whole."""

    overall_relevance_score: int = Field(
        description=(
            "How relevant the retrieved chunks are as a whole to the question. "
            "Must be an integer from 1 to 5."
        ),
        ge=1,
        le=5,
    )

    mean_chunk_relevance_score: float = Field(
        description="This is the score of the mean chunk relevance by averaging the relevance score against the total"
    )

    coverage_score: int = Field(
        description=(
            "How completely the retrieved chunks cover the information "
            "needed to support the reference answer. "
            "Must be an integer from 1 to 5."
        ),
        ge=1,
        le=5,
    )

    


def calculate_mrr(keyword: str, retrieved_docs: list) -> float:
    """Calculate reciprocal rank for a single keyword (case-insensitive)."""
    keyword_lower = keyword.lower()
    for rank, doc in enumerate(retrieved_docs, start=1):
        if keyword_lower in doc.page_content.lower():
            return 1.0 / rank
    return 0.0


def calculate_dcg(relevances: list[int], k: int) -> float:
    """Calculate Discounted Cumulative Gain."""
    dcg = 0.0
    for i in range(min(k, len(relevances))):
        dcg += relevances[i] / math.log2(i + 2)  # i+2 because rank starts at 1
    return dcg


def calculate_ndcg(keyword: str, retrieved_docs: list, k: int = 10) -> float:
    """Calculate nDCG for a single keyword (binary relevance, case-insensitive)."""
    keyword_lower = keyword.lower()

    # Binary relevance: 1 if keyword found, 0 otherwise
    relevances = [
        1 if keyword_lower in doc.page_content.lower() else 0 for doc in retrieved_docs[:k]
    ]

    # DCG
    dcg = calculate_dcg(relevances, k)

    # Ideal DCG (best case: keyword in first position)
    ideal_relevances = sorted(relevances, reverse=True)
    idcg = calculate_dcg(ideal_relevances, k)

    return dcg / idcg if idcg > 0 else 0.0


def evaluate_retrieval(test: TestQuestion, k: int = 10) -> RetrievalEval:
    """
    Evaluate retrieval performance for a test question.

    Args:
        test: TestQuestion object containing question and keywords
        k: Number of top documents to retrieve (default 10)

    Returns:
        RetrievalEval object with MRR, nDCG, and keyword coverage metrics
    """
    # Retrieve documents using shared answer module
    retriever = Retriever()
    retrieved_chunks = retriever.retrieve_context(test.question)

    # Calculate MRR (average across all keywords)
    mrr_scores = [calculate_mrr(keyword, retrieved_chunks) for keyword in test.keywords]
    avg_mrr = sum(mrr_scores) / len(mrr_scores) if mrr_scores else 0.0

    # Calculate nDCG (average across all keywords)
    ndcg_scores = [calculate_ndcg(keyword, retrieved_chunks, k) for keyword in test.keywords]
    avg_ndcg = sum(ndcg_scores) / len(ndcg_scores) if ndcg_scores else 0.0

    # Calculate keyword coverage
    keywords_found = sum(1 for score in mrr_scores if score > 0)
    total_keywords = len(test.keywords)
    keyword_coverage = (keywords_found / total_keywords * 100) if total_keywords > 0 else 0.0

    return RetrievalEval(
        mrr=avg_mrr,
        ndcg=avg_ndcg,
        keywords_found=keywords_found,
        total_keywords=total_keywords,
        keyword_coverage=keyword_coverage,
    )


def evaluate_chunk_relevance_with_llm(test: TestQuestion) -> tuple[MeanChunkRelevanceEval, list]:
    """
    Evaluate chunk quality using LLM-as-a-judge (async).

    Args:
        test: TestQuestion object containing question and reference answer

    Returns:
        Tuple of (MeanChunkRelevanceEval object, generated_answer string, retrieved_docs list)
    """
    # Get RAG chunks using shared retriever module
    retriever = Retriever()
    retrieved_chunks = retriever.retrieve_context(test.question)

    valid_ids = list(range(1, len(retrieved_chunks) + 1))

    user_prompt = f"""
Question:

{test.question}

VALID CHUNK IDs:

{valid_ids}

RETRIEVED CHUNKS:

"""

    for chunk_id, chunk in zip(valid_ids, retrieved_chunks):
        user_prompt += (
            f"# CHUNK ID: {chunk_id}\n\n"
            f"{chunk.page_content}\n\n"
        )

    user_prompt += """
Evaluate every retrieved chunk independently.

Return ONLY the JSON object matching the required schema.
"""

    judge_messages = [
        {
            "role": "system",
            "content": CHUNK_RELEVANCE_JUDGE_SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": user_prompt,
        },
    ]

    # Call LLM judge with structured outputs (async)
    judge_response = completion(model=MODEL, messages=judge_messages)
    response = judge_response.choices[0].message.content
    print("RESPONSE", response)

    # Validate the LLM response against the Pydantic model.
    result = ChunksRelevanceEval.model_validate_json(response)

    # Extract IDs returned by the LLM.
    returned_ids = [chunk.chunk_id for chunk in result.chunks]

    # Validate that the LLM evaluated exactly the chunks we supplied.
    if sorted(returned_ids) != sorted(valid_ids):
        raise ValueError(
            "Invalid chunk IDs returned by LLM. "
            f"Expected {valid_ids}, got {returned_ids}"
        )

    # Calculate the average relevance for this question.
    average_relevance = sum(
        chunk.relevance_score
        for chunk in result.chunks
    ) / len(result.chunks)

    mean_chunk_relevance = MeanChunkRelevanceEval(
        score=average_relevance
    )



    return mean_chunk_relevance, retrieved_chunks

def evaluate_overall_relevance(
    test: TestQuestion
) -> OverallRelevanceEval:

    retriever = Retriever()
    retrieved_chunks = retriever.retrieve_context(test.question)
    user_prompt = f"""
Question:

{test.question}

RETRIEVED CHUNKS:

"""

    for index, chunk in enumerate(retrieved_chunks):
        user_prompt += (
            f"# CHUNK ID: {index + 1}\n\n"
            f"{chunk.page_content}\n\n"
        )

    user_prompt += """
Evaluate the retrieved chunks as a whole.

Return ONLY the JSON object matching the required schema.
"""

    judge_messages = [
        {
            "role": "system",
            "content": OVERALL_RELEVANCE_JUDGE_SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": user_prompt,
        },
    ]

    judge_response = completion(model=MODEL, messages=judge_messages)
    response = judge_response.choices[0].message.content

    result = OverallRelevanceEval.model_validate_json(response)

    if not 1 <= result.relevance_score <= 5:
        raise ValueError(
            f"Invalid overall relevance score: "
            f"{result.relevance_score}. Expected 1-5."
        )

    return result

def evaluate_context_coverage(
    test: TestQuestion,
) -> CoverageEval:

    retriever = Retriever()
    retrieved_chunks = retriever.retrieve_context(test.question)

    user_prompt = f"""
Question:

{test.question}

REFERENCE ANSWER:

{test.reference_answer}

RETRIEVED CHUNKS:

"""

    for index, chunk in enumerate(retrieved_chunks):
        user_prompt += (
            f"# CHUNK ID: {index + 1}\n\n"
            f"{chunk.page_content}\n\n"
        )

    user_prompt += """
Evaluate how completely the retrieved chunks cover the information
needed to support the reference answer.

Return ONLY the JSON object matching the required schema.
"""

    judge_messages = [
        {
            "role": "system",
            "content": COVERAGE_JUDGE_SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": user_prompt,
        },
    ]

    judge_response = completion(model=MODEL, messages=judge_messages)
    response = judge_response.choices[0].message.content
    print("COVERAGE RESPONSE", response)

    return CoverageEval.model_validate_json(response)



def evaluate_all_retrieval():
    """Evaluate all retrieval tests."""
    tests = load_tests()
    total_tests = len(tests)
    for index, test in enumerate(tests):
        result = evaluate_retrieval(test)
        progress = (index + 1) / total_tests
        yield test, result, progress


def evaluate_all_answers():
    """Evaluate all answers to tests using batched async execution."""
    tests = load_tests()
    total_tests = len(tests)
    for index, test in enumerate(tests):
        mean_chunk_relevance_score = evaluate_chunk_relevance_with_llm(test)[0]
        overall_relevance_score = evaluate_overall_relevance(test)
        coverage_score = evaluate_context_coverage(test)
        complete_llm_as_a_judge_result = CompleteLLMAsAJudgeEval(
            coverage_score=coverage_score.coverage_score,
            mean_chunk_relevance_score=mean_chunk_relevance_score.score,
            overall_relevance_score=overall_relevance_score.relevance_score
        )
        progress = (index + 1) / total_tests
        yield test, complete_llm_as_a_judge_result, progress


def run_cli_evaluation(test_number: int):
    """Run evaluation for a specific test (async helper for CLI)."""
    # Load tests
    tests = load_tests("tests.jsonl")

    if test_number < 0 or test_number >= len(tests):
        print(f"Error: test_row_number must be between 0 and {len(tests) - 1}")
        sys.exit(1)

    # Get the test
    test = tests[test_number]

    # Print test info
    print(f"\n{'=' * 80}")
    print(f"Test #{test_number}")
    print(f"{'=' * 80}")
    print(f"Question: {test.question}")
    print(f"Keywords: {test.keywords}")
    print(f"Category: {test.category}")
    print(f"Reference Answer: {test.reference_answer}")

    # Retrieval Evaluation
    print(f"\n{'=' * 80}")
    print("Retrieval Evaluation")
    print(f"{'=' * 80}")

    retrieval_result = evaluate_retrieval(test)

    print(f"MRR: {retrieval_result.mrr:.4f}")
    print(f"nDCG: {retrieval_result.ndcg:.4f}")
    print(f"Keywords Found: {retrieval_result.keywords_found}/{retrieval_result.total_keywords}")
    print(f"Keyword Coverage: {retrieval_result.keyword_coverage:.1f}%")

    # Answer Evaluation
    print(f"\n{'=' * 80}")
    print("Answer Evaluation")
    print(f"{'=' * 80}")

    # answer_result, retrieved_docs = evaluate_answer(test)

    # print(f"\nGenerated Answer:\n{generated_answer}")
    # print(f"\nFeedback:\n{answer_result.feedback}")
    # print("\nScores:")
    # print(f"  Accuracy: {answer_result.accuracy:.2f}/5")
    # print(f"  Completeness: {answer_result.completeness:.2f}/5")
    # print(f"  Relevance: {answer_result.relevance:.2f}/5")
    # print(f"\n{'=' * 80}\n")


def main():
    """CLI to evaluate a specific test by row number."""
    if len(sys.argv) != 2:
        print("Usage: uv run eval.py <test_row_number>")
        sys.exit(1)

    try:
        test_number = int(sys.argv[1])
    except ValueError:
        print("Error: test_row_number must be an integer")
        sys.exit(1)

    run_cli_evaluation(test_number)


if __name__ == "__main__":
    main()
