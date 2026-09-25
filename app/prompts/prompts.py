from app.rag.chunker import Result


CHUNKS_RERANKING_SYSTEM_PROMPT = """
You are a document re-ranking engine.

You will receive:
1. A user question.
2. A numbered list of document chunks.

Your task is to rank ALL of the provided chunks from most relevant to least relevant.

Rules:

- The ONLY valid chunk IDs are the IDs explicitly provided.
- NEVER invent, infer, or create new chunk IDs.
- NEVER omit a chunk.
- NEVER duplicate a chunk ID.
- Every provided chunk ID must appear exactly once.
- Your output must be a permutation of the provided IDs.
- Rank only using the information contained in the supplied chunks.
- Do not use outside knowledge.
- Do not explain your reasoning.

Return only the ordered list of chunk IDs.
"""

def chunks_reranking_user_prompt(question, chunks: list[Result], valid_ids: list[int]):
    
    user_prompt = f"""
Question:

{question}

The ONLY valid chunk IDs are:

{valid_ids}

Use every ID exactly once.

Here are the chunks:

"""

    for index, chunk in enumerate(chunks):
        user_prompt += (
            f"# CHUNK ID: {index + 1}\n"
            f"{chunk.page_content}\n\n"
        )

    user_prompt += """
Return ONLY a JSON object matching the schema.

Example:

{
    "order": [3, 1, 2, 4]
}

Do not include any explanation.
"""


def rewrite_query_prompt(query: str) -> str:
    f"""
    You are a query rewriting component in an AI Security Incident Investigation Agent.

Your job is to rewrite a user's investigation query into a clear, retrieval-optimized search query for a cybersecurity knowledge base.

The knowledge base contains:

* Security concepts and guidance
* Incident response procedures
* Incident-specific investigation guidance
* MITRE ATT&CK information
* Security playbooks
* Vulnerability and CVE information

Rules:

1. Preserve the original meaning and investigation intent.
2. Do not add facts, assumptions, or conclusions that are not present in the original query.
3. Expand ambiguous security terminology when the intended meaning is clear.
4. Include important entities, technologies, attack techniques, indicators, and investigation activities from the original query.
5. Prefer specific cybersecurity terminology over conversational wording.
6. Remove unnecessary conversational words.
7. Do not answer the query. Only rewrite it.
8. Produce one optimized search query.
9. Keep the rewritten query concise, normally one sentence.
10. Do not include explanations, labels, or commentary.

Examples:

Input:
"What should I check after someone successfully logs into SSH following loads of failed attempts?"

Output:
"post-authentication activity investigation following suspected SSH credential compromise"

Input:
"What evidence should I look for if an attacker might have escalated privileges?"

Output:
"evidence for investigating privilege escalation activity and post-escalation actions"

Input:
"How do I investigate a suspicious connection from an internal server to an unknown external IP?"

Output:
"investigation of suspicious outbound network connection from internal server to unknown external IP"

Input:
"What should I check when a user clicked a phishing link?"

Output:
"investigation steps and evidence for phishing link compromise"

Input:
"How can I tell if this malware actually executed?"

Output:
"evidence of malware execution and execution artifacts"

Input:
"185.123.45.67 logged into deploy-admin after 150 failed SSH attempts. What should I investigate next?"

Output:
"investigation of successful SSH login following brute-force attempts, including post-authentication activity and account compromise evidence"

Now rewrite the following query:

{query}

    """

