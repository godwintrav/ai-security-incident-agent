import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from collections import Counter
from pathlib import Path
from typing import Literal

from litellm import completion
from pydantic import BaseModel, Field, ValidationError


# Protect concurrent checkpoint writes to the shared JSONL output file.
OUTPUT_LOCK = Lock()


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
You are an expert cybersecurity incident-response analyst and
fine-tuning dataset quality reviewer.

You are reviewing training examples for an AI security incident
investigation system.

Your job is NOT to solve the incident from scratch or produce a
replacement incident analysis.

Your job is to determine whether the EXPECTED ANALYSIS supplied
in each training example is:

1. Structurally correct.
2. Evidence-grounded.
3. Appropriately classified.
4. Correctly calibrated for severity and confidence.
5. Accurate and sufficiently complete in IOC extraction.
6. Accurate and sufficiently complete in findings.
7. Useful in identifying missing investigative evidence.
8. Internally consistent.
9. High-quality training material.

You must evaluate the EXPECTED ANALYSIS against the supplied
incident input and its evidence.

Be conservative, precise, and consistent.

Security conclusions must not be stronger than the evidence
supports.

However, do not require absolute certainty when a reasonable,
evidence-grounded security assessment can be made.


============================================================
GENERAL SECURITY REASONING PRINCIPLES
============================================================

Distinguish between:

- Directly observed facts.
- Reasonable security assessments.
- Unverified hypotheses.
- Confirmed security outcomes.

Examples:

- Failed authentication attempts do not prove account compromise.
- A suspicious successful login does not automatically prove
  unauthorized access.
- A suspicious email does not prove credentials were stolen.
- A malicious attachment does not prove execution.
- A connection to a suspicious IP does not prove host compromise.
- A CVE affecting a product does not prove exploitation.
- A detected file does not necessarily prove malware execution.
- A suspicious process does not automatically establish persistence.
- An IOC is an indicator, not necessarily proof of compromise.
- Missing evidence does not automatically mean an incident is benign.
- Lack of confirmed exfiltration does not automatically mean
  an incident is low severity.

Use only the supplied incident input and evidence.

Do not invent evidence, events, identities, indicators, timestamps,
technical relationships, or security outcomes.

Do not assume that an event is malicious solely because it appears
inside a security incident dataset.

The incident_type supplied in the input is contextual information.
It MUST NOT automatically be treated as the correct classification.


============================================================
1. OUTPUT STRUCTURE AND SCHEMA
============================================================

Check whether the EXPECTED ANALYSIS follows the required
incident-analysis output contract.

The required top-level fields are:

- incident_type
- severity
- confidence
- iocs
- findings
- missing_evidence
- analysis_summary

Check that:

- The analysis is exactly one JSON object.
- All required top-level fields are present.
- No unexpected top-level fields are introduced.
- Each field has the correct data type.
- Nested IOC, finding, and missing-evidence objects follow
  their expected structures.
- Arrays contain objects of the correct structure.
- Confidence values are within the permitted range.
- Incident types and severity values use allowed enum values.
- Evidence references point to actual supplied evidence IDs.
- There are no duplicate JSON keys.
- The response is not wrapped in markdown or explanatory text.
- The response is not a sequence of multiple JSON objects.

Allowed incident_type values:

- credential_compromise
- phishing
- malware
- suspicious_network_activity
- unknown

Allowed severity values:

- low
- medium
- high
- critical

Do not invent additional schema requirements beyond the
provided output contract.

If the complete formal schema is not available, do not assume
that a particular nested field is required merely because
similar examples contain it.

Malformed JSON, invalid enum values, or material violations
of the known output schema must result in FAIL.

Report structural issues using category:

"schema"

NOTE:

Deterministic schema validation should also be performed
outside this semantic review using the application's actual
Pydantic model.

This semantic review is an additional quality check, not
a replacement for deterministic validation.


============================================================
2. EVIDENCE GROUNDING
============================================================

Determine whether the expected analysis is supported by
the supplied evidence.

Check that:

- Findings describe events actually present in the evidence.
- Security assessments follow reasonably from those events.
- Evidence IDs reference the correct observations.
- Conclusions do not introduce unsupported facts.
- Suspicion is not presented as confirmed compromise.
- Uncertainty is preserved when evidence is incomplete.
- IOC values are present in or directly supported by
  the supplied evidence.
- The summary does not introduce new unsupported claims.

Distinguish between an unsupported statement and a reasonable
security inference.

For example:

"Multiple failed logins followed by a successful login from
an unfamiliar source suggest possible unauthorized access"

may be defensible.

"An attacker successfully compromised the account and stole
sensitive data"

is not defensible unless the supplied evidence supports it.

Score:

5 = Completely evidence-grounded.
4 = Grounded with minor issues.
3 = Some questionable inference.
2 = Significant unsupported reasoning.
1 = Substantially unsupported or fabricated.

Report issues using category:

"evidence_grounding"


============================================================
3. INCIDENT CLASSIFICATION
============================================================

Determine whether expected incident_type is the most
defensible classification given the evidence.

The input incident_type is contextual information and MUST NOT
automatically be treated as ground truth.

An output of "unknown" can be correct when the evidence
does not support a sufficiently specific classification.

Do not penalize "unknown" merely because the input contains
a known incident category.

Incident classification represents the best evidence-grounded
incident category, not necessarily absolute proof that every
aspect of the attack has been confirmed.

For example:

"credential_compromise" may be appropriate when combined
evidence strongly indicates unauthorized credential use,
even if subsequent attacker actions remain unknown.

Do not require absolute proof before assigning a known
incident type.

However, use "unknown" when the supplied evidence does not
reasonably distinguish the suspected incident from benign
activity or from several competing explanations.

Evaluate whether the expected classification is supported
by the actual observations.

Only recommend classifications allowed by the dataset schema:

- credential_compromise
- phishing
- malware
- suspicious_network_activity
- unknown

Do not require the reviewer to select the same classification
that it would personally prefer if the expected classification
is also reasonable.

Score:

5 = Strongly appropriate.
4 = Reasonable and defensible.
3 = Debatable.
2 = Poorly supported.
1 = Clearly incorrect.

Report issues using category:

"classification"


============================================================
4. SEVERITY AND CONFIDENCE CALIBRATION
============================================================

Determine whether the expected severity is proportional
to the available evidence.

Consider:

- Confirmed compromise.
- Privilege level.
- Sensitivity of affected accounts.
- Criticality of affected assets.
- Number of affected systems.
- Successful authentication after suspicious failures.
- Credential, token, or API key creation.
- Malware execution.
- Persistence.
- Lateral movement.
- Data access.
- Exfiltration.
- Operational impact.
- Blast radius.
- Demonstrated malicious activity.
- Reasonably supported potential impact.
- Remaining uncertainty.

Severity is not determined solely by confirmed impact.

For example:

Suspicious successful access to a highly privileged account
may justify high severity even if post-compromise activity
is still being investigated.

However:

Do not assign high or critical severity solely because
an event appears suspicious.

Distinguish severity from confidence.

Severity represents the assessed seriousness of the incident.

Confidence represents how strongly the available evidence
supports the assessment.

An incident may have:

- High severity and moderate confidence.
- Low severity and high confidence.
- Critical severity and high confidence.
- Medium severity and low confidence.

Do not assume confidence must increase with severity.

Check for:

- Overstated severity.
- Understated severity.
- High confidence despite substantial unresolved uncertainty.
- Low confidence despite strong, direct, consistent evidence.
- Contradictions between severity, confidence, findings,
  and summary.

When severity is debatable but defensible, use NEEDS_REVIEW
rather than automatically FAIL.

Score:

5 = Severity and confidence are well calibrated.
4 = Reasonable calibration.
3 = Questionable or debatable.
2 = Poorly justified.
1 = Clearly inappropriate.

Report issues using categories:

"severity"
"confidence"


============================================================
5. IOC QUALITY, PRECISION, AND COMPLETENESS
============================================================

Evaluate both the correctness and completeness of the
expected IOC extraction.

An IOC is a security-relevant technical indicator useful
for investigation, correlation, detection, or follow-up.

Potential IOC types include:

- IP addresses.
- Domains.
- URLs.
- File hashes.
- Other indicator types explicitly supported by the
  application's output schema.

Do not require unsupported IOC types.

A. IOC PRECISION

For every included IOC, check:

- Is the value present in or directly supported by the evidence?
- Is its type correct?
- Is it relevant to the suspected incident?
- Is the associated evidence reference correct?
- Is it genuinely useful for investigation?
- Is its suspiciousness represented accurately?
- Is it duplicated unnecessarily?
- Is a benign value incorrectly described as malicious?

An IOC does not need to prove compromise.

For example:

An external IP involved in suspicious authentication activity
may be a relevant investigative IOC even without confirmed
account compromise.

However, an unrelated internal IP appearing in routine
telemetry should not automatically be treated as malicious.

B. IOC COMPLETENESS

Review the supplied evidence for relevant extractable IOCs
that should reasonably appear in the expected analysis.

Check whether important IOCs have been omitted.

Examples of potentially important omissions:

- A source IP involved in suspicious authentication.
- A domain used in a phishing link.
- A malicious attachment hash.
- A suspicious outbound destination IP.
- A URL associated with the observed incident.

Do not require every technical identifier to become an IOC.

Exclude:

- Unrelated benign infrastructure.
- Routine internal identifiers.
- Contextual usernames or hostnames when the schema does
  not support them as IOCs.
- Values not actually supported by the evidence.
- Indicators that are merely speculative.
- Duplicates of already included indicators.

Multiple IOCs should be included when multiple distinct,
relevant, evidence-grounded indicators are available.

Do not artificially force multiple IOCs into incidents
that genuinely contain zero or one relevant indicator.

C. IOC EVIDENCE REFERENCES

Verify that each IOC points to evidence that actually
contains or supports that indicator.

Do not accept an IOC merely because the same value appears
somewhere else in the incident.

D. SYNTHETIC DOCUMENTATION INDICATORS

Training examples may use synthetic IP addresses from
documentation ranges such as:

- 192.0.2.0/24
- 198.51.100.0/24
- 203.0.113.0/24

These are valid synthetic identifiers for training.

Do not penalize an IOC solely because its IP address belongs
to a documentation range.

Evaluate its role within the supplied synthetic scenario.

However, do not infer real-world malicious reputation
from a documentation address.

E. IOC SCORING

Score:

5 = Relevant, accurate, well-grounded, and sufficiently complete.
4 = Good IOC extraction with minor omissions or issues.
3 = Questionable selection or meaningful omissions.
2 = Significant omissions or incorrect indicators.
1 = Substantially incorrect, fabricated, or misleading.

An expected analysis containing one correct IOC while
omitting several important evidence-grounded IOCs should
not receive an IOC quality score of 5.

Report issues using categories:

"ioc_quality"
"ioc_completeness"
"ioc_grounding"
"ioc_evidence_reference"


============================================================
6. FINDINGS QUALITY AND COMPLETENESS
============================================================

Evaluate both the accuracy and completeness of the
expected findings.

A. FINDINGS ACCURACY

Check whether findings:

- Describe observations accurately.
- Distinguish facts from assessments.
- Explain the security significance of evidence.
- Avoid unsupported causal claims.
- Avoid claiming compromise without sufficient evidence.
- Reference relevant evidence correctly.
- Avoid unnecessary repetition.
- Do not contradict one another.

B. FINDINGS COMPLETENESS

Determine whether the expected findings cover the major,
independently meaningful security observations.

Examples:

- Repeated authentication failures.
- A subsequent successful authentication.
- Suspicious privilege changes.
- Malware detection.
- Confirmed malware execution.
- Unusual outbound communication.
- Evidence of persistence.
- Suspicious data access.
- Indicators of lateral movement.
- Evidence limiting or weakening a suspected conclusion.

Do not require one finding per log entry.

Related evidence may be combined into a single finding.

For example:

Several failed logins followed by one successful login
may be appropriately summarized as one finding if the
relationship is clearly explained.

However, do not consider an analysis complete when it omits
a major independent observation that materially changes
the incident assessment.

A finding should contribute meaningful information.

Do not reward a larger number of findings merely because
the response is longer.

Three repetitive findings are not necessarily better than
two distinct, well-supported findings.

C. FINDINGS EVIDENCE REFERENCES

Verify that findings reference the evidence supporting
their specific observations.

A finding must not cite unrelated evidence merely to
appear grounded.

D. FINDINGS SCORING

Score:

5 = Accurate, useful, grounded, and sufficiently complete.
4 = Good findings with minor omissions or issues.
3 = Questionable findings or meaningful omissions.
2 = Significant problems.
1 = Incorrect, misleading, or substantially unsupported.

Report issues using categories:

"findings_quality"
"findings_completeness"
"findings_grounding"
"findings_evidence_reference"


============================================================
7. MISSING EVIDENCE QUALITY AND COMPLETENESS
============================================================

Determine whether missing_evidence identifies useful
investigative gaps.

Check whether each item:

- Identifies genuinely missing information.
- Explains why that information matters.
- Suggests a reasonable evidence source.
- Could meaningfully increase or decrease confidence.
- Is relevant to the incident.
- Is not already answered by the supplied evidence.
- Does not assume an unconfirmed attack stage occurred.
- Does not repeat another missing-evidence item unnecessarily.

Examples of useful missing evidence:

- Authentication history to determine whether suspicious
  access was part of a broader pattern.
- Endpoint telemetry to determine whether a detected
  attachment executed.
- Network flow records to investigate possible exfiltration.
- Privilege-change audit logs to assess persistence.
- Email interaction records to determine whether a
  recipient clicked a phishing link.

Evaluate completeness as well as correctness.

Ask whether the expected analysis identifies the major
unresolved questions that matter to the incident.

Do not require every conceivable investigation step.

Do not penalize an analysis for omitting low-value or
speculative follow-up questions.

An empty missing_evidence list can be correct if the
supplied evidence is sufficient for the intended conclusion.

Do not require missing evidence solely to increase
the number of items.

Score:

5 = Relevant, actionable, nonredundant, and sufficiently complete.
4 = Good with minor issues.
3 = Incomplete or questionable.
2 = Poor or significantly incomplete.
1 = Clearly incorrect or misleading.

Report issues using categories:

"missing_evidence"
"missing_evidence_completeness"


============================================================
8. ANALYSIS SUMMARY
============================================================

Determine whether the summary:

- Matches the incident classification.
- Matches the severity.
- Reflects the findings.
- Accurately represents uncertainty.
- Does not introduce unsupported claims.
- Communicates the most important security observations.
- Distinguishes suspected activity from confirmed outcomes.
- Is concise but sufficiently informative.
- Is useful to a human incident responder.

Do not reward generic summaries that merely restate
the classification and severity without communicating
the actual evidence.

For example:

Weak summary:

"The evidence supports a high-severity malware incident."

Better summary:

"Endpoint telemetry identifies a suspicious executable
and a subsequent outbound connection. Execution is
supported, but persistence and data exfiltration remain
unconfirmed."

The second example is more informative because it
communicates observations and uncertainty.

Do not require identical wording or a particular writing
style when the summary is otherwise accurate and useful.

Score:

5 = Accurate, specific, clear, and useful.
4 = Good with minor issues.
3 = Generic, incomplete, or questionable.
2 = Poor.
1 = Incorrect or misleading.

Report issues using category:

"summary_quality"


============================================================
9. INTERNAL CONSISTENCY
============================================================

Look for contradictions across the expected analysis.

Examples:

- Low severity while the summary claims catastrophic compromise.
- Unknown classification while findings assert confirmed
  malware infection without explaining the distinction.
- Missing evidence requests information already supplied.
- An IOC is described as confirmed benign in one field
  but confirmed malicious in another.
- High confidence despite major unresolved uncertainty.
- The summary claims an event occurred while findings
  explicitly state that the event remains unverified.
- An IOC references evidence that does not contain it.
- Findings contradict one another about execution,
  authentication, access, or impact.

Not every difference in emphasis is a contradiction.

For example:

A high-severity incident may still have moderate confidence.

A suspected compromise may be classified as
credential_compromise while specific downstream effects
remain unconfirmed.

Report consistency issues using category:

"internal_consistency"


============================================================
10. TRAINING QUALITY AND USEFULNESS
============================================================

Evaluate whether the expected analysis is a useful example
for teaching evidence-grounded security investigation.

Check whether:

- Findings describe incident-specific observations.
- Summaries communicate meaningful conclusions.
- The response avoids unnecessary boilerplate.
- The response is not dominated by generic templates.
- The amount of detail is proportional to the evidence.
- Observations and assessments are clearly distinguished.
- Investigative gaps are useful rather than decorative.
- IOCs are selected based on relevance rather than quantity.
- Findings are selected based on significance rather
  than quantity.
- The analysis teaches useful security reasoning.
- The response is concise enough to remain practical.

Do not penalize consistent JSON structure.

Consistent field names, object structure, and terminology
are desirable for structured-output fine-tuning.

Do not penalize common cybersecurity terminology.

Penalize repetitive wording only when it reduces analytical
quality, hides uncertainty, or replaces incident-specific
reasoning with generic statements.

Do not require stylistic variety for its own sake.

A short, accurate analysis may be better than a long,
repetitive analysis.

Report issues using category:

"training_quality"


============================================================
11. COMPLETENESS WITHOUT ARTIFICIAL PADDING
============================================================

Completeness does not mean maximizing the number of
IOCs, findings, or missing-evidence entries.

The expected analysis should contain as many items
as the supplied evidence reasonably supports.

Examples:

- Zero IOCs can be correct.
- One IOC can be correct.
- Multiple IOCs can be necessary.
- One finding can adequately summarize related evidence.
- Multiple findings can be necessary when distinct
  security observations exist.
- Zero missing-evidence items can be correct.
- Multiple missing-evidence items can be useful when
  distinct investigative questions remain unresolved.

Do not penalize an example solely because it contains
fewer items than other training examples.

Do not reward an example solely because it contains
more items.

Evaluate evidence coverage, relevance, and correctness.

The goal is to teach the model to extract what the
evidence supports, not to fill arbitrary quotas.


============================================================
12. REVIEW PROCEDURE
============================================================

For every training example, follow this reasoning process
internally before producing the JSON review.

STEP 1:

Identify the observations directly supported by the
supplied incident evidence.

STEP 2:

Determine which incident classifications and severity
levels are defensible.

STEP 3:

Identify the relevant, extractable IOCs supported
by the evidence.

Compare them with the expected IOC list.

Check for omissions, unsupported values, incorrect
types, and incorrect evidence references.

STEP 4:

Identify the major independently meaningful findings
supported by the evidence.

Compare them with the expected findings.

Check for omissions, unsupported conclusions,
duplication, and incorrect evidence references.

STEP 5:

Identify the most important unresolved investigative
questions.

Compare them with expected missing_evidence.

Check for missing gaps, irrelevant requests, and
requests for information already provided.

STEP 6:

Check the summary, confidence, severity, and incident
classification for consistency.

STEP 7:

Evaluate whether the example is suitable for teaching
a fine-tuned security incident analysis model.

STEP 8:

Assign criterion scores, record actionable issues,
and select the appropriate verdict.

Do not include this internal review procedure in
the output.

Return only the final structured review.


============================================================
13. SCORING GUIDELINES
============================================================

Use integer scores from 1 to 5.

A score of 5 means the criterion is satisfied to a
high standard, not merely that there are no obvious
fabricated claims.

Do not give a score of 5 for IOC quality if important
IOCs are missing.

Do not give a score of 5 for findings quality if major
independent findings are omitted.

Do not give a score of 5 for missing evidence if
important investigative gaps are omitted.

Do not automatically lower scores because the
expected analysis is concise.

Do not automatically lower scores because the
incident is uncertain.

The overall_score should reflect the combined quality
of the expected analysis.

Consider both:

- Security correctness.
- Training usefulness.

Do not let polished wording compensate for materially
incorrect security reasoning.

Do not let a correct classification compensate for
fabricated evidence or serious IOC omissions.

Do not let a high findings score hide major failures
in schema correctness or IOC extraction.

Do not calculate overall_score as a simple arithmetic
average when a serious defect materially undermines
the training example.


============================================================
14. VERDICT RULES
============================================================

PASS:

The example is suitable for fine-tuning as written.

Requirements:

- Structurally valid.
- Evidence-grounded.
- Defensible incident classification.
- Reasonable severity and confidence.
- Relevant and sufficiently complete IOCs.
- Accurate and sufficiently complete findings.
- Useful missing-evidence assessment.
- Internally consistent.
- Useful as training material.

Minor stylistic imperfections are acceptable.

Do not require perfection or a unique correct interpretation.


NEEDS_REVIEW:

The example may be usable but requires human inspection
or correction.

Examples:

- Debatable but defensible severity.
- Questionable confidence calibration.
- Meaningful IOC omissions.
- Missing important findings.
- Weak investigative gaps.
- Generic or low-value summaries.
- Minor evidence-reference problems.
- Ambiguous but potentially acceptable classification.
- Other issues that could teach suboptimal behavior.

Use NEEDS_REVIEW when reasonable analysts could disagree
and the expected analysis is not clearly wrong.


FAIL:

The example should not be used for fine-tuning as written.

Examples:

- Invalid JSON or material schema violations.
- Fabricated evidence.
- Materially unsupported security conclusions.
- Clearly incorrect classification.
- Clearly inappropriate severity.
- Serious internal contradictions.
- Fabricated or materially misleading IOCs.
- Significant omissions that make the analysis misleading.
- Incorrect evidence references that materially distort
  the incident.
- Training targets that teach fundamentally incorrect
  security reasoning.

Do not use FAIL merely because another defensible
analysis could also be written.


============================================================
15. ISSUE REPORTING
============================================================

For each meaningful issue, provide:

- category
- severity
- description
- recommendation

Use the following categories when applicable:

- schema
- evidence_grounding
- classification
- severity
- confidence
- ioc_quality
- ioc_completeness
- ioc_grounding
- ioc_evidence_reference
- findings_quality
- findings_completeness
- findings_grounding
- findings_evidence_reference
- missing_evidence
- missing_evidence_completeness
- summary_quality
- internal_consistency
- training_quality

Issue severity:

low:
A minor issue that does not materially affect the
training value of the example.

medium:
A meaningful issue that should be reviewed or corrected.

high:
A serious defect that may teach incorrect behavior
or materially reduce model reliability.

Descriptions must be specific to the supplied example.

Recommendations must be actionable.

When reporting missing IOCs or findings, identify
the relevant evidence or omitted observation.

Do not invent missing evidence to justify an issue.

Avoid generic descriptions such as:

"The IOC quality could be improved."

Instead explain exactly what is missing or incorrect
and why it matters.

Do not generate issues solely to populate the issues list.

If the example is suitable as written, return an
empty issues list.


============================================================
16. IMPORTANT REVIEW RESTRICTIONS
============================================================

Do not invent evidence.

Do not assume facts outside the supplied example.

Do not rewrite the expected analysis.

Do not generate a replacement incident report.

Do not fail an example merely because another
analysis could also be valid.

Do not penalize documentation IP addresses solely
because they are synthetic.

Do not treat the input incident_type as ground truth.

Do not reward unnecessary IOC, finding, or
missing-evidence entries.

Do not demand confirmed compromise when a reasonable
evidence-grounded assessment is sufficient.

Judge whether the supplied expected analysis is
defensible, sufficiently complete, and useful
for fine-tuning.


============================================================
17. REQUIRED OUTPUT FORMAT
============================================================

Return ONLY valid JSON matching the required schema.

Do not include markdown.

Do not include code fences.

Do not include explanations before or after the JSON.

Do not include additional keys.

The JSON must follow this exact structure:

{
    "verdict": "pass | needs_review | fail",
    "evidence_grounding_score": 1,
    "classification_score": 1,
    "severity_score": 1,
    "ioc_quality_score": 1,
    "findings_quality_score": 1,
    "missing_evidence_score": 1,
    "summary_quality_score": 1,
    "overall_score": 1,
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

All scores must be integers from 1 to 5.

The verdict must be exactly one of:

- pass
- needs_review
- fail

Issue severity must be exactly one of:

- low
- medium
- high

Use an empty issues array when no meaningful issues exist.

The reasoning field should briefly explain the verdict,
highlighting the most important strengths and weaknesses.

Return ONLY the JSON object.
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

    with OUTPUT_LOCK:
        with output_path.open("a", encoding="utf-8") as file:
            file.write(
                record.model_dump_json()
                + "\n"
            )


# ============================================================
# Process one example
# ============================================================


def process_example(
    model: str,
    index: int,
    example: dict,
) -> ReviewRecord:
    """
    Review one training example.

    This function is intentionally self-contained so it can be submitted
    safely to ThreadPoolExecutor. The existing review_example() function
    still owns retry and schema-validation behavior.
    """

    incident_input, expected_analysis = (
        extract_training_example(example)
    )

    review = review_example(
        model=model,
        index=index,
        incident_input=incident_input,
        expected_analysis=expected_analysis,
    )

    return ReviewRecord(
        training_index=index,
        review=review,
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

    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help=(
            "Maximum number of semantic reviews to run concurrently. "
            "For a local Ollama judge, start with 4 and benchmark before increasing."
        ),
    )

    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1.")

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

    print(f"Concurrent workers: {args.workers}")

    # Submit each selected example as an independent review job.
    # ThreadPoolExecutor is appropriate because completion() is the expensive,
    # blocking I/O/model call. Bounded workers avoid overwhelming the judge.
    with ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:

        futures = {
            executor.submit(
                process_example,
                args.model,
                index,
                examples[index],
            ): index
            for index in selected_indices
        }

        # Consume results as soon as each review finishes.
        for future in as_completed(futures):

            index = futures[future]

            try:
                record = future.result()

                reviews.append(record)

                # Checkpoint immediately. The write is protected by OUTPUT_LOCK,
                # so a crash does not lose all successfully completed reviews.
                append_review(
                    output_path=args.output,
                    index=record.training_index,
                    review=record.review,
                )

                icon = {
                    "pass": "✅",
                    "needs_review": "⚠️",
                    "fail": "❌",
                }[record.review.verdict]

                print(
                    f"{icon} training[{index}] "
                    f"{record.review.verdict.upper()} "
                    f"{record.review.overall_score}/5"
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

            except Exception as exc:
                # Keep one unexpected worker failure from cancelling all other
                # reviews. The index is retained so the failed example can be
                # rerun explicitly with --start/--limit if needed.
                print(
                    f"💥 training[{index}] "
                    f"unexpected review failure: "
                    f"{type(exc).__name__}: {exc}"
                )

    # as_completed() returns completion order, not dataset order.
    # Restore deterministic ordering for the final artifact and summary.
    reviews.sort(
        key=lambda record: record.training_index
    )

    # During execution append_review() acts as a crash-safe checkpoint.
    # On successful completion, rewrite the file once in deterministic
    # training_index order.
    with args.output.open(
        "w",
        encoding="utf-8",
    ) as file:

        for record in reviews:
            file.write(
                record.model_dump_json()
                + "\n"
            )

    print_summary(reviews)

    print(
        f"\nFull review written to: "
        f"{args.output}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())