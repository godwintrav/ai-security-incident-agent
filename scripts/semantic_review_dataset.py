import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Literal

from litellm import completion
from pydantic import BaseModel, Field, ValidationError


# ============================================================
# Models
# ============================================================


class SemanticIssue(BaseModel):
    category: Literal[
        "incident_type",
        "severity",
        "ioc",
        "finding",
        "missing_evidence",
        "analysis_summary",
        "evidence_grounding",
        "overclaiming",
        "internal_consistency",
        "other",
    ]

    severity: Literal["low", "medium", "high"]

    description: str = Field(
        description="Clear explanation of the semantic problem."
    )

    recommendation: str = Field(
        description="How the example should potentially be corrected."
    )


class SemanticReview(BaseModel):
    verdict: Literal[
        "pass",
        "needs_review",
        "fail",
    ]

    evidence_grounding_score: int = Field(ge=1, le=5)

    classification_score: int = Field(ge=1, le=5)

    severity_score: int = Field(ge=1, le=5)

    ioc_quality_score: int = Field(ge=1, le=5)

    findings_quality_score: int = Field(ge=1, le=5)

    missing_evidence_score: int = Field(ge=1, le=5)

    summary_quality_score: int = Field(ge=1, le=5)

    overall_score: int = Field(ge=1, le=5)

    issues: list[SemanticIssue]

    reasoning: str = Field(
        description=(
            "Concise explanation of why the example received this verdict."
        )
    )


class ReviewRecord(BaseModel):
    training_index: int
    review: SemanticReview


# ============================================================
# Judge prompt
# ============================================================


SEMANTIC_REVIEW_SYSTEM_PROMPT = """
You are an expert cybersecurity incident-response analyst reviewing
fine-tuning data for an AI security incident investigation system.

Your job is NOT to solve the incident from scratch.

Your job is to determine whether the EXPECTED ANALYSIS supplied in the
training example is a high-quality, evidence-grounded answer to the
supplied incident information.

Be conservative.

Security conclusions must not be stronger than the evidence supports.

A suspicious event is not automatically a confirmed compromise.

Examples:

- Failed authentication attempts do not prove account compromise.
- A suspicious email does not prove credentials were stolen.
- A malicious attachment does not prove execution.
- A connection to a suspicious IP does not prove host compromise.
- A CVE affecting a product does not prove exploitation.
- A detected file does not necessarily prove successful malware execution.
- A suspicious process does not automatically establish persistence.
- An IOC is an indicator, not necessarily proof of compromise.

Evaluate the example using the following criteria.


1. EVIDENCE GROUNDING

Check whether the expected analysis is actually supported by the supplied
evidence.

Findings and conclusions must not introduce facts that are absent from the
evidence.

Score:
5 = completely evidence grounded
4 = mostly grounded, minor issue
3 = some questionable inference
2 = significant unsupported reasoning
1 = substantially unsupported


2. INCIDENT CLASSIFICATION

Determine whether expected incident_type is reasonable given the evidence.

The input incident_type is contextual information and MUST NOT automatically
be treated as ground truth.

An output of "unknown" can be correct when evidence is insufficient.

Do not penalize "unknown" merely because the input contains a known incident
category.

IMPORTANT CLASSIFICATION GUIDANCE:

Incident classification represents the best evidence-grounded incident
category, not necessarily absolute proof that every aspect of the attack
has been confirmed.

For example, "credential_compromise" may be appropriate when the combined
evidence strongly indicates unauthorized credential use, even if the
attacker's subsequent actions are still unknown.

Do not require absolute proof before assigning a known incident type.

However, use "unknown" when the supplied evidence does not reasonably
distinguish the suspected incident from benign activity.

Only recommend incident types allowed by the dataset schema:
- credential_compromise
- phishing
- malware
- suspicious_network_activity
- unknown

Score:
5 = strongly appropriate
4 = reasonable
3 = debatable
2 = poorly supported
1 = clearly incorrect


3. SEVERITY

Determine whether severity is proportional to the evidence.

Consider factors such as:

- confirmed compromise
- privilege level
- affected systems
- execution
- persistence
- lateral movement
- data access
- exfiltration
- operational impact
- scope
- uncertainty

Do not assume severe impact without evidence.

IMPORTANT SEVERITY GUIDANCE:

Severity is not based only on confirmed impact.

When evaluating severity, consider both demonstrated and reasonably
supported potential impact, including:

- privilege level of the affected account
- sensitivity or criticality of the affected asset
- successful authentication following suspicious failures
- creation of credentials, tokens, or API keys
- attacker persistence opportunities
- blast radius
- likelihood of unauthorized access
- demonstrated malicious activity
- confirmed impact
- uncertainty

Do NOT automatically downgrade an incident simply because data
exfiltration, lateral movement, or destructive impact has not yet been
confirmed.

For example, suspicious successful access to a highly privileged account
may reasonably justify high severity even while post-compromise activity
is still being investigated.

However, severity must still be proportional to the evidence. Do not
assign high or critical severity solely because an event is suspicious.

Score:
5 = clearly appropriate
4 = reasonable
3 = questionable
2 = poorly justified
1 = clearly inappropriate


4. IOC QUALITY

Check whether identified IOCs are meaningful security indicators.

Consider whether:

- the value actually represents a useful indicator
- its type is appropriate
- the evidence supports treating it as relevant
- benign values are incorrectly being presented as malicious indicators

An IOC does not have to prove compromise, but it should be relevant to the
investigation.

Score:
5 = excellent
4 = good
3 = questionable IOC selection
2 = significant problems
1 = clearly incorrect


5. FINDINGS QUALITY

Check whether findings:

- accurately describe observations
- distinguish observations from assessments
- avoid unsupported causal claims
- avoid claiming compromise without sufficient evidence
- correctly reference the significance of the evidence

Score:
5 = excellent
4 = good
3 = questionable
2 = significant problems
1 = incorrect


6. MISSING EVIDENCE

Check whether missing_evidence:

- identifies genuinely useful investigative gaps
- explains why the evidence matters
- suggests a reasonable evidence source
- does not request information already supplied
- would meaningfully increase or decrease confidence

An empty missing_evidence list can be correct if the supplied evidence is
sufficient for the intended conclusion.

Score:
5 = excellent
4 = good
3 = incomplete/questionable
2 = poor
1 = clearly wrong


7. ANALYSIS SUMMARY

Check whether the summary:

- matches the findings
- matches the severity
- matches the classification
- accurately represents uncertainty
- does not introduce unsupported claims

Score:
5 = excellent
4 = good
3 = questionable
2 = poor
1 = incorrect


8. INTERNAL CONSISTENCY

Look for contradictions such as:

- low severity but summary claims catastrophic compromise
- unknown classification but findings state confirmed malware infection
- missing evidence asks for evidence already supplied
- IOC marked relevant while findings describe it as confirmed benign
- high confidence despite major unresolved uncertainty

Report these as issues.


VERDICT RULES

PASS:
The example is suitable for fine-tuning as written.
Minor stylistic imperfections are acceptable.

NEEDS_REVIEW:
The example may be usable but contains a questionable security judgment,
ambiguous severity, weak missing-evidence choice, questionable IOC, or other
issue that a human should inspect.

FAIL:
The example teaches materially incorrect security reasoning, contains
unsupported conclusions, serious contradictions, or labels that should not
be used for fine-tuning.


IMPORTANT:

Do not invent evidence.

Do not assume facts outside the supplied example.

Do not rewrite the example.

Do not fail an example merely because another analysis could also be valid.

Judge whether the supplied expected analysis is defensible and useful.

Return ONLY JSON matching the required schema.

Return ONLY valid JSON.

Do not include markdown.
Do not include ```json.
Do not include explanations before or after the JSON.

The JSON must follow this exact structure:
{
    "verdict": "pass | needs_review | fail",
    "evidence_grounding_score": 1-5,
    "classification_score": 1-5,
    "severity_score": 1-5,
    "ioc_quality_score": 1-5,
    "findings_quality_score": 1-5,
    "missing_evidence_score": 1-5,
    "summary_quality_score": 1-5,
    "overall_score": 1-5,
    "issues": [
        {
            "category": "...",
            "severity": "low | medium | high",
            "description": "...",
            "recommendation": "..."
        }
    ],
    "reasoning": "..."
}
"""


# ============================================================
# Dataset loading
# ============================================================


def load_jsonl(path: Path) -> list[dict]:
    examples = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                examples.append(json.loads(line))

            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at line {line_number}: {exc}"
                ) from exc

    return examples


# ============================================================
# Training example extraction
# ============================================================


def extract_training_example(example: dict) -> tuple[dict, dict]:

    messages = example["messages"]

    user_content = messages[1]["content"]
    assistant_content = messages[2]["content"]

    incident_input = json.loads(user_content)
    expected_analysis = json.loads(assistant_content)

    return incident_input, expected_analysis


# ============================================================
# Judge
# ============================================================


def review_example(
    model: str,
    index: int,
    incident_input: dict,
    expected_analysis: dict,
    max_attempts: int = 3,
) -> SemanticReview:

    payload = {
        "incident_input": incident_input,
        "expected_analysis": expected_analysis,
    }

    base_user_prompt = f"""
Review the following fine-tuning example.

<training_example>
{json.dumps(payload, ensure_ascii=False, indent=2)}
</training_example>

Evaluate ONLY the semantic quality of the expected analysis against the
supplied incident input and evidence.

Return ONLY valid JSON.

Do not include markdown.
Do not include ```json.
Do not include explanations before or after the JSON.

IMPORTANT ENUM RULES:

For "verdict", use EXACTLY one of:
- "pass"
- "needs_review"
- "fail"

For every issue "category", use EXACTLY one of:
- "incident_type"
- "severity"
- "ioc"
- "finding"
- "missing_evidence"
- "analysis_summary"
- "evidence_grounding"
- "overclaiming"
- "internal_consistency"
- "other"

Do NOT invent new category names.

For every issue "severity", use EXACTLY one of:
- "low"
- "medium"
- "high"

All scores MUST be integers from 1 to 5.

Return this exact JSON structure:

{{
  "verdict": "pass",
  "evidence_grounding_score": 5,
  "classification_score": 5,
  "severity_score": 5,
  "ioc_quality_score": 5,
  "findings_quality_score": 5,
  "missing_evidence_score": 5,
  "summary_quality_score": 5,
  "overall_score": 5,
  "issues": [],
  "reasoning": "Concise explanation of the verdict."
}}
"""

    messages = [
        {
            "role": "system",
            "content": SEMANTIC_REVIEW_SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": base_user_prompt,
        },
    ]

    last_error = None

    for attempt in range(1, max_attempts + 1):

        response = completion(
            model=model,
            messages=messages,
            temperature=0,
        )

        content = response.choices[0].message.content

        if not content:
            last_error = ValueError("Judge returned empty content.")
            continue

        # Some local models may still wrap JSON in markdown.
        cleaned_content = content.strip()

        if cleaned_content.startswith("```json"):
            cleaned_content = cleaned_content[7:]

        elif cleaned_content.startswith("```"):
            cleaned_content = cleaned_content[3:]

        if cleaned_content.endswith("```"):
            cleaned_content = cleaned_content[:-3]

        cleaned_content = cleaned_content.strip()

        try:
            return SemanticReview.model_validate_json(
                cleaned_content
            )

        except ValidationError as exc:

            last_error = exc

            print(
                f"🔄 training[{index}] "
                f"validation failed "
                f"(attempt {attempt}/{max_attempts})"
            )

            if attempt < max_attempts:

                messages.append(
                    {
                        "role": "assistant",
                        "content": content,
                    }
                )

                messages.append(
                    {
                        "role": "user",
                        "content": f"""
Your previous JSON response failed schema validation.

Validation error:

{exc}

Correct ONLY the formatting/schema problems.

Pay special attention to enum values.

"verdict" must be exactly:
"pass", "needs_review", or "fail"

Issue "category" must be exactly one of:
"incident_type",
"severity",
"ioc",
"finding",
"missing_evidence",
"analysis_summary",
"evidence_grounding",
"overclaiming",
"internal_consistency",
"other"

Issue "severity" must be exactly:
"low",
"medium",
or "high"

All scores must be integers from 1 to 5.

Preserve your original semantic judgment.

Return ONLY the corrected JSON.
""",
                    }
                )

    raise ValueError(
        f"Judge failed schema validation after "
        f"{max_attempts} attempts.\n\n"
        f"Last error:\n{last_error}"
    )


# ============================================================
# Save individual result immediately
# ============================================================


def append_review(
    output_path: Path,
    index: int,
    review: SemanticReview,
) -> None:

    record = ReviewRecord(
        training_index=index,
        review=review,
    )

    with output_path.open("a", encoding="utf-8") as file:
        file.write(
            record.model_dump_json()
            + "\n"
        )


# ============================================================
# Summary
# ============================================================


def print_summary(reviews: list[ReviewRecord]) -> None:

    verdicts = Counter(
        record.review.verdict
        for record in reviews
    )

    issue_categories = Counter(
        issue.category
        for record in reviews
        for issue in record.review.issues
    )

    scores = {
        "evidence_grounding": [],
        "classification": [],
        "severity": [],
        "ioc_quality": [],
        "findings_quality": [],
        "missing_evidence": [],
        "summary_quality": [],
        "overall": [],
    }

    for record in reviews:

        review = record.review

        scores["evidence_grounding"].append(
            review.evidence_grounding_score
        )

        scores["classification"].append(
            review.classification_score
        )

        scores["severity"].append(
            review.severity_score
        )

        scores["ioc_quality"].append(
            review.ioc_quality_score
        )

        scores["findings_quality"].append(
            review.findings_quality_score
        )

        scores["missing_evidence"].append(
            review.missing_evidence_score
        )

        scores["summary_quality"].append(
            review.summary_quality_score
        )

        scores["overall"].append(
            review.overall_score
        )

    print("\n" + "=" * 60)
    print("SEMANTIC REVIEW SUMMARY")
    print("=" * 60)

    print(f"\nExamples reviewed: {len(reviews)}")

    print("\nVerdicts")

    for verdict in [
        "pass",
        "needs_review",
        "fail",
    ]:

        print(
            f"  {verdict:20}"
            f"{verdicts[verdict]}"
        )

    print("\nAverage Scores")

    for name, values in scores.items():

        if values:

            average = sum(values) / len(values)

            print(
                f"  {name:25}"
                f"{average:.2f}/5"
            )

    print("\nIssue Categories")

    if not issue_categories:

        print("  None")

    else:

        for category, count in issue_categories.most_common():

            print(
                f"  {category:25}"
                f"{count}"
            )

    flagged = [
        record
        for record in reviews
        if record.review.verdict != "pass"
    ]

    print("\nFlagged Examples")

    if not flagged:

        print("  None")

    else:

        for record in flagged:

            print(
                f"  training[{record.training_index}]"
                f" -> {record.review.verdict}"
                f" ({record.review.overall_score}/5)"
            )


# ============================================================
# Main
# ============================================================


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Perform LLM-assisted semantic review of the "
            "security incident fine-tuning dataset."
        )
    )

    parser.add_argument(
        "--train",
        required=True,
        type=Path,
        help="Path to training JSONL.",
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path where semantic review results will be written.",
    )

    parser.add_argument(
        "--model",
        required=True,
        help=(
            "LiteLLM model identifier used as the independent judge."
        ),
    )

    parser.add_argument(
        "--start",
        type=int,
        default=0,
        help="Training index to start reviewing from.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of examples to review.",
    )

    args = parser.parse_args()

    examples = load_jsonl(args.train)

    print("=" * 60)
    print("SEMANTIC DATASET REVIEW")
    print("=" * 60)

    print(f"\nTraining examples loaded: {len(examples)}")
    print(f"Judge model: {args.model}")

    end = len(examples)

    if args.limit is not None:
        end = min(
            args.start + args.limit,
            len(examples),
        )

    selected_indices = range(
        args.start,
        end,
    )

    print(
        f"Reviewing training[{args.start}:{end}]"
    )

    # Start fresh for this run.
    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.output.write_text(
        "",
        encoding="utf-8",
    )

    reviews: list[ReviewRecord] = []

    for index in selected_indices:

        example = examples[index]

        try:

            incident_input, expected_analysis = (
                extract_training_example(example)
            )

            review = review_example(
                model=args.model,
                index=index,
                incident_input=incident_input,
                expected_analysis=expected_analysis,
            )

            record = ReviewRecord(
                training_index=index,
                review=review,
            )

            reviews.append(record)

            append_review(
                output_path=args.output,
                index=index,
                review=review,
            )

            icon = {
                "pass": "✅",
                "needs_review": "⚠️",
                "fail": "❌",
            }[review.verdict]

            print(
                f"{icon} training[{index}] "
                f"{review.verdict.upper()} "
                f"{review.overall_score}/5"
            )

        except (
            ValidationError,
            ValueError,
            KeyError,
            TypeError,
        ) as exc:

            print(
                f"💥 training[{index}] "
                f"review failed: {exc}"
            )

    print_summary(reviews)

    print(
        f"\nFull review written to: "
        f"{args.output}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())