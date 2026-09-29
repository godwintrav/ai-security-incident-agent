import argparse
import json
from pathlib import Path

from litellm import completion
from pydantic import BaseModel, ValidationError


# ============================================================
# Models
# ============================================================


class SemanticMatch(BaseModel):
    matched: bool
    matched_prediction_indexes: list[int]
    reason: str


class UnsupportedClaim(BaseModel):
    prediction_index: int
    unsupported: bool
    overclaiming: bool
    reason: str


class SemanticEvaluation(BaseModel):
    finding_matches: list[SemanticMatch]
    missing_evidence_matches: list[SemanticMatch]
    unsupported_claims: list[UnsupportedClaim]


class DeterministicMetrics(BaseModel):
    schema_valid: bool

    incident_type_correct: bool | None = None
    severity_correct: bool | None = None

    # Required IOC matching
    required_ioc_count: int = 0
    matched_required_ioc_count: int = 0
    required_ioc_recall: float | None = None

    # Predicted IOC quality
    predicted_ioc_count: int = 0
    matched_predicted_ioc_count: int = 0
    ioc_precision: float | None = None

    # IOC evidence grounding
    grounded_ioc_count: int = 0
    ungrounded_ioc_count: int = 0
    ioc_grounding_rate: float | None = None

    # Placeholder / invalid IOC values
    placeholder_ioc_count: int = 0


class SemanticMetrics(BaseModel):
    required_finding_count: int = 0
    matched_required_finding_count: int = 0
    required_finding_recall: float | None = None

    required_missing_evidence_count: int = 0
    matched_required_missing_evidence_count: int = 0
    required_missing_evidence_recall: float | None = None

    predicted_finding_count: int = 0
    unsupported_finding_count: int = 0
    overclaiming_finding_count: int = 0

    unsupported_finding_rate: float | None = None
    overclaiming_finding_rate: float | None = None


class IOCDetail(BaseModel):
    prediction_index: int
    type: str
    normalized_type: str
    value: str

    matched_required_ioc: bool
    evidence_grounded: bool
    placeholder_value: bool

    invalid_evidence_ids: list[str]


class ScoredPrediction(BaseModel):
    case_id: str
    model: str

    deterministic: DeterministicMetrics

    ioc_details: list[IOCDetail]

    semantic: SemanticMetrics | None = None
    semantic_details: SemanticEvaluation | None = None


# ============================================================
# Constants
# ============================================================


IOC_TYPE_ALIASES = {
    # IP addresses
    "ip": "ip_address",
    "ip address": "ip_address",
    "ip_address": "ip_address",
    "source ip": "ip_address",
    "source_ip": "ip_address",
    "destination ip": "ip_address",
    "destination_ip": "ip_address",
    "src ip": "ip_address",
    "src_ip": "ip_address",
    "dst ip": "ip_address",
    "dst_ip": "ip_address",
    "ipv4": "ip_address",
    "ipv6": "ip_address",

    # Hostnames
    "host": "hostname",
    "hostname": "hostname",
    "host name": "hostname",
    "host_name": "hostname",

    # Users / accounts
    "user": "username",
    "username": "username",
    "user name": "username",
    "user_name": "username",
    "user account": "username",
    "user_account": "username",
    "account": "username",

    # Domains
    "domain": "domain",
    "domain name": "domain",
    "domain_name": "domain",

    # URLs
    "url": "url",
    "uri": "url",

    # Files
    "file": "filename",
    "filename": "filename",
    "file name": "filename",
    "file_name": "filename",

    # Processes
    "process": "process",
    "process name": "process",
    "process_name": "process",

    # File hashes
    "hash": "file_hash",
    "file hash": "file_hash",
    "file_hash": "file_hash",
    "sha256": "file_hash",
    "sha1": "file_hash",
    "md5": "file_hash",

    # Email
    "email": "email_address",
    "email address": "email_address",
    "email_address": "email_address",

    # Device
    "device": "device_id",
    "device id": "device_id",
    "device_id": "device_id",

    # User agent
    "user agent": "user_agent",
    "user_agent": "user_agent",
}


PLACEHOLDER_IOC_VALUES = {
    "",
    "n/a",
    "na",
    "none",
    "null",
    "unknown",
    "not available",
    "not provided",
    "unspecified",
}


# ============================================================
# File helpers
# ============================================================


def load_jsonl(path: str) -> list[dict]:
    records = []

    with open(path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {path} "
                    f"at line {line_number}: {exc}"
                ) from exc

    return records


def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                record,
                ensure_ascii=False,
            )
            + "\n"
        )


def load_completed_cases(path: Path) -> set[str]:
    if not path.exists():
        return set()

    completed = set()

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line in file:
            if not line.strip():
                continue

            record = json.loads(line)

            completed.add(
                record["case_id"]
            )

    return completed


# ============================================================
# IOC normalization
# ============================================================


def normalize_text(value: str) -> str:
    return (
        str(value)
        .strip()
        .lower()
    )


def normalize_ioc_type(value: str) -> str:
    normalized = (
        str(value)
        .strip()
        .lower()
        .replace("-", " ")
    )

    if normalized in IOC_TYPE_ALIASES:
        return IOC_TYPE_ALIASES[normalized]

    return normalized.replace(" ", "_")


def normalize_ioc_value(value: str) -> str:
    return normalize_text(value)


def is_placeholder_ioc_value(
    value: str,
) -> bool:
    return (
        normalize_ioc_value(value)
        in PLACEHOLDER_IOC_VALUES
    )


# ============================================================
# Evidence helpers
# ============================================================


def collect_evidence_ids(
    value,
) -> set[str]:
    """
    Recursively walks the regression input and collects
    values stored under keys named 'evidence_id' or 'id'
    when they look like evidence records.

    The first preference is explicit evidence_id fields.

    This allows the scorer to verify that predicted IOC
    evidence_ids actually exist in the supplied incident
    input.
    """

    evidence_ids = set()

    if isinstance(value, dict):

        if "evidence_id" in value:
            evidence_id = value["evidence_id"]

            if isinstance(evidence_id, str):
                evidence_ids.add(evidence_id)

        # Most of our dataset evidence records use "id".
        # Only treat it as an evidence ID if this object
        # appears to represent evidence.
        if (
            "id" in value
            and isinstance(value["id"], str)
            and (
                "evidence" in value
                or "source" in value
                or "content" in value
                or "description" in value
                or value["id"].startswith("ev_")
            )
        ):
            evidence_ids.add(value["id"])

        for nested_value in value.values():
            evidence_ids.update(
                collect_evidence_ids(
                    nested_value
                )
            )

    elif isinstance(value, list):
        for item in value:
            evidence_ids.update(
                collect_evidence_ids(item)
            )

    return evidence_ids


def check_ioc_evidence_grounding(
    predicted_ioc: dict,
    valid_evidence_ids: set[str],
) -> tuple[bool, list[str]]:
    """
    An IOC is considered evidence-grounded when:

    1. It references at least one evidence ID.
    2. Every referenced evidence ID exists in the supplied
       incident input.

    Semantic correctness of the evidence-to-IOC relationship
    is a separate question. This check verifies reference
    integrity.
    """

    evidence_ids = predicted_ioc.get(
        "evidence_ids",
        [],
    )

    if not evidence_ids:
        return False, []

    invalid_ids = [
        evidence_id
        for evidence_id in evidence_ids
        if evidence_id not in valid_evidence_ids
    ]

    return len(invalid_ids) == 0, invalid_ids


# ============================================================
# IOC matching
# ============================================================


def ioc_matches(
    required: dict,
    predicted: dict,
) -> bool:
    """
    Deterministically matches IOC type + value.

    Confidence is intentionally ignored.

    Evidence IDs are evaluated separately as an evidence
    grounding metric.
    """

    required_type = required.get("type")
    required_value = required.get("value")

    predicted_type = predicted.get("type")
    predicted_value = predicted.get("value")

    if (
        required_type is None
        or required_value is None
        or predicted_type is None
        or predicted_value is None
    ):
        return False

    if is_placeholder_ioc_value(
        predicted_value
    ):
        return False

    return (
        normalize_ioc_type(required_type)
        == normalize_ioc_type(predicted_type)
        and
        normalize_ioc_value(required_value)
        == normalize_ioc_value(predicted_value)
    )


def match_required_iocs(
    required_iocs: list[dict],
    predicted_iocs: list[dict],
) -> tuple[
    int,
    float,
    set[int],
]:
    """
    Matches each required IOC to at most one predicted IOC.

    Returns:
        matched required IOC count
        required IOC recall
        indexes of matched predictions
    """

    if not required_iocs:
        return 0, 1.0, set()

    matched_required_count = 0

    used_prediction_indexes = set()

    for required in required_iocs:

        for index, predicted in enumerate(
            predicted_iocs
        ):
            if index in used_prediction_indexes:
                continue

            if ioc_matches(
                required,
                predicted,
            ):
                matched_required_count += 1

                used_prediction_indexes.add(
                    index
                )

                break

    recall = (
        matched_required_count
        / len(required_iocs)
    )

    return (
        matched_required_count,
        recall,
        used_prediction_indexes,
    )


def calculate_ioc_precision(
    predicted_iocs: list[dict],
    matched_prediction_indexes: set[int],
) -> float:
    """
    IOC precision measures how many predicted IOCs match
    expected IOC requirements.

    Placeholder IOCs naturally count against precision.
    """

    if not predicted_iocs:
        return 1.0

    return (
        len(matched_prediction_indexes)
        / len(predicted_iocs)
    )


# ============================================================
# Deterministic scoring
# ============================================================


def score_deterministic(
    regression_case: dict,
    prediction_record: dict,
) -> tuple[
    DeterministicMetrics,
    list[IOCDetail],
]:
    schema_valid = prediction_record.get(
        "schema_valid",
        False,
    )

    if not schema_valid:
        return (
            DeterministicMetrics(
                schema_valid=False,
            ),
            [],
        )

    prediction = prediction_record.get(
        "prediction"
    )

    if not prediction:
        return (
            DeterministicMetrics(
                schema_valid=False,
            ),
            [],
        )

    expected = regression_case["expected"]

    incident_type_correct = (
        prediction["incident_type"]
        == expected["incident_type"]
    )

    severity_correct = (
        prediction["severity"]
        == expected["severity"]
    )

    required_iocs = expected.get(
        "required_iocs",
        [],
    )

    predicted_iocs = prediction.get(
        "iocs",
        [],
    )

    (
        matched_required_count,
        required_ioc_recall,
        matched_prediction_indexes,
    ) = match_required_iocs(
        required_iocs,
        predicted_iocs,
    )

    ioc_precision = calculate_ioc_precision(
        predicted_iocs,
        matched_prediction_indexes,
    )

    valid_evidence_ids = collect_evidence_ids(
        regression_case["input"]
    )

    grounded_ioc_count = 0
    ungrounded_ioc_count = 0
    placeholder_ioc_count = 0

    ioc_details = []

    for index, predicted_ioc in enumerate(
        predicted_iocs
    ):
        value = str(
            predicted_ioc.get(
                "value",
                "",
            )
        )

        ioc_type = str(
            predicted_ioc.get(
                "type",
                "",
            )
        )

        placeholder = (
            is_placeholder_ioc_value(
                value
            )
        )

        if placeholder:
            placeholder_ioc_count += 1

        (
            evidence_grounded,
            invalid_evidence_ids,
        ) = check_ioc_evidence_grounding(
            predicted_ioc,
            valid_evidence_ids,
        )

        # A placeholder cannot be considered a valid
        # grounded IOC even if it somehow references
        # a real evidence ID.
        if placeholder:
            evidence_grounded = False

        if evidence_grounded:
            grounded_ioc_count += 1
        else:
            ungrounded_ioc_count += 1

        ioc_details.append(
            IOCDetail(
                prediction_index=index,
                type=ioc_type,
                normalized_type=(
                    normalize_ioc_type(
                        ioc_type
                    )
                ),
                value=value,
                matched_required_ioc=(
                    index
                    in matched_prediction_indexes
                ),
                evidence_grounded=(
                    evidence_grounded
                ),
                placeholder_value=placeholder,
                invalid_evidence_ids=(
                    invalid_evidence_ids
                ),
            )
        )

    if predicted_iocs:
        ioc_grounding_rate = (
            grounded_ioc_count
            / len(predicted_iocs)
        )
    else:
        # Returning no IOCs does not represent an
        # evidence-grounding failure.
        ioc_grounding_rate = 1.0

    deterministic = DeterministicMetrics(
        schema_valid=True,

        incident_type_correct=(
            incident_type_correct
        ),

        severity_correct=(
            severity_correct
        ),

        required_ioc_count=(
            len(required_iocs)
        ),

        matched_required_ioc_count=(
            matched_required_count
        ),

        required_ioc_recall=(
            required_ioc_recall
        ),

        predicted_ioc_count=(
            len(predicted_iocs)
        ),

        matched_predicted_ioc_count=(
            len(matched_prediction_indexes)
        ),

        ioc_precision=ioc_precision,

        grounded_ioc_count=(
            grounded_ioc_count
        ),

        ungrounded_ioc_count=(
            ungrounded_ioc_count
        ),

        ioc_grounding_rate=(
            ioc_grounding_rate
        ),

        placeholder_ioc_count=(
            placeholder_ioc_count
        ),
    )

    return deterministic, ioc_details


# ============================================================
# Semantic judge prompt
# ============================================================


JUDGE_SYSTEM_PROMPT = """
You are evaluating the output of a cybersecurity incident
analysis model.

Your job is NOT to perform a new incident investigation.

Your job is to compare the model prediction against the
evaluation requirements and supplied incident evidence.

Be strict but fair.


1. REQUIRED FINDINGS

For every required finding, determine whether one or more
predicted findings semantically satisfy that SPECIFIC
requirement.

A predicted finding does NOT match merely because:

- it references the same evidence
- it discusses the same user, IP, host, process, or event
- it is relevant to the same incident
- it discusses a related security concept

The predicted finding must express the core security
observation, conclusion, or assessment required by the
specific requirement.

Ask:

"If I removed the required finding from the expected answer,
would this predicted finding independently communicate the
same important security conclusion?"

If not, it is not a match.

Multiple predicted findings may jointly satisfy one
requirement only when their combined meaning clearly
expresses the complete required conclusion.

Examples:

Required:
"Determine whether persistence was established."

Prediction:
"Review scheduled tasks and registry run keys to determine
whether persistence was established."

MATCH.

Required:
"Malicious PowerShell execution was observed."

Prediction:
"PowerShell activity should be investigated."

NO MATCH.

Required:
"Successful authentication was followed by privileged API
key creation."

Prediction:
"A successful authentication occurred from a new device."

NO MATCH.

Even though both may reference the same authentication
evidence, the prediction does not capture the required
privileged API key creation.

Never mark a finding as matched solely because it references
the same evidence ID or is generally relevant to the
investigation.


2. REQUIRED MISSING EVIDENCE

For every required missing-evidence requirement, determine
whether one or more predicted missing-evidence items
semantically request the same information.

Different wording is acceptable.

Do not count loosely related evidence as equivalent.

Example:

Required:
"Obtain post-authentication activity."

Prediction:
"Review command history and endpoint telemetry after the
successful login."

MATCH.

Required:
"Obtain MFA authentication details."

Prediction:
"Review network traffic."

NO MATCH.


3. UNSUPPORTED / OVERCLAIMED FINDINGS

For every predicted finding, determine whether it is
unsupported and/or overclaiming.

unsupported:
The finding asserts a fact, relationship, or security
conclusion that is not reasonably supported by the supplied
evidence.

overclaiming:
The finding expresses a stronger level of certainty than the
evidence supports.

Suspicion, possibility, and evidence-backed assessment are
different from confirmed compromise.

Example:

Evidence:
150 failed logins followed by one successful login.

Supported:
"The sequence is suspicious and consistent with brute-force
activity."

Potential overclaim:
"The attacker successfully cracked the password."

Example:

Evidence:
A suspicious executable was downloaded.

Supported:
"A suspicious executable was downloaded."

Unsupported:
"The malware executed and established persistence."

Do not penalize reasonable security analysis merely because
absolute proof is unavailable.

Do not mark a finding unsupported solely because it contains
an assessment or hypothesis when that assessment is clearly
qualified and reasonably grounded in the evidence.

When judging whether a claim is supported, consider the complete
supplied incident input, including:

- incident description
- evidence records
- security knowledge
- playbook
- CVE results

Do not treat a statement as unsupported if it is explicitly
provided in the incident description, even when it is not
repeated in an evidence record.

However, distinguish supplied incident context from stronger
conclusions inferred from that context.

For example:

Incident description:
"A service account accessed an administrative resource outside
its documented workflow."

Supported:
"The service account accessed the administrative resource
outside its documented workflow."

Potential overclaim:
"The service account was compromised."

The first statement is explicitly supplied by the incident
context. The second requires additional evidence.

Return JSON only.

Do not use Markdown.

Do not include commentary before or after the JSON.
""".strip()


# ============================================================
# Semantic judge input
# ============================================================


def build_judge_prompt(
    regression_case: dict,
    prediction: dict,
) -> str:

    expected = regression_case["expected"]

    judge_input = {
        "incident_input": (
            regression_case["input"]
        ),

        "evaluation_requirements": (
            regression_case.get(
                "evaluation_requirements",
                {},
            )
        ),

        "required_findings": (
            expected.get(
                "required_findings",
                [],
            )
        ),

        "required_missing_evidence": (
            expected.get(
                "required_missing_evidence",
                [],
            )
        ),

        "predicted_findings": (
            prediction.get(
                "findings",
                [],
            )
        ),

        "predicted_missing_evidence": (
            prediction.get(
                "missing_evidence",
                [],
            )
        ),
    }

    return f"""
Evaluate the following incident-analysis prediction.

Return exactly this JSON structure:

{{
  "finding_matches": [
    {{
      "matched": true,
      "matched_prediction_indexes": [0],
      "reason": "brief explanation"
    }}
  ],
  "missing_evidence_matches": [
    {{
      "matched": true,
      "matched_prediction_indexes": [0],
      "reason": "brief explanation"
    }}
  ],
  "unsupported_claims": [
    {{
      "prediction_index": 0,
      "unsupported": false,
      "overclaiming": false,
      "reason": "brief explanation"
    }}
  ]
}}

Rules:

- There must be exactly one finding_matches entry for
  every required finding, in the same order.

- There must be exactly one missing_evidence_matches entry
  for every required missing-evidence requirement, in the
  same order.

- There must be exactly one unsupported_claims entry for
  every predicted finding, in the same order.

- matched_prediction_indexes must contain only indexes from
  the corresponding prediction array.

- If no prediction satisfies a requirement, return:
  "matched": false
  and
  "matched_prediction_indexes": []

- Do not create additional requirements.

- Use evaluation_requirements when they provide
  case-specific guidance.

INPUT:

{json.dumps(
    judge_input,
    ensure_ascii=False,
    indent=2,
)}
""".strip()


# ============================================================
# Judge validation
# ============================================================


def validate_judge_result(
    regression_case: dict,
    prediction: dict,
    result: SemanticEvaluation,
) -> None:

    expected = regression_case["expected"]

    required_findings = expected.get(
        "required_findings",
        [],
    )

    required_missing = expected.get(
        "required_missing_evidence",
        [],
    )

    predicted_findings = prediction.get(
        "findings",
        [],
    )

    predicted_missing = prediction.get(
        "missing_evidence",
        [],
    )

    # --------------------------------------------------------
    # Count validation
    # --------------------------------------------------------

    if (
        len(result.finding_matches)
        != len(required_findings)
    ):
        raise ValueError(
            "Judge returned incorrect number of "
            "finding_matches."
        )

    if (
        len(result.missing_evidence_matches)
        != len(required_missing)
    ):
        raise ValueError(
            "Judge returned incorrect number of "
            "missing_evidence_matches."
        )

    if (
        len(result.unsupported_claims)
        != len(predicted_findings)
    ):
        raise ValueError(
            "Judge returned incorrect number of "
            "unsupported_claims."
        )

    # --------------------------------------------------------
    # Finding indexes
    # --------------------------------------------------------

    for match in result.finding_matches:

        if (
            not match.matched
            and match.matched_prediction_indexes
        ):
            raise ValueError(
                "Unmatched finding requirement "
                "contains prediction indexes."
            )

        if (
            match.matched
            and not match.matched_prediction_indexes
        ):
            raise ValueError(
                "Matched finding requirement has "
                "no prediction indexes."
            )

        for index in (
            match.matched_prediction_indexes
        ):
            if (
                index < 0
                or index >= len(
                    predicted_findings
                )
            ):
                raise ValueError(
                    "Judge returned invalid "
                    "finding index."
                )

    # --------------------------------------------------------
    # Missing evidence indexes
    # --------------------------------------------------------

    for match in (
        result.missing_evidence_matches
    ):

        if (
            not match.matched
            and match.matched_prediction_indexes
        ):
            raise ValueError(
                "Unmatched missing-evidence "
                "requirement contains prediction "
                "indexes."
            )

        if (
            match.matched
            and not match.matched_prediction_indexes
        ):
            raise ValueError(
                "Matched missing-evidence "
                "requirement has no prediction "
                "indexes."
            )

        for index in (
            match.matched_prediction_indexes
        ):
            if (
                index < 0
                or index >= len(
                    predicted_missing
                )
            ):
                raise ValueError(
                    "Judge returned invalid "
                    "missing-evidence index."
                )

    # --------------------------------------------------------
    # Unsupported claim indexes
    # --------------------------------------------------------

    expected_indexes = set(
        range(
            len(predicted_findings)
        )
    )

    returned_indexes = {
        item.prediction_index
        for item in result.unsupported_claims
    }

    if returned_indexes != expected_indexes:
        raise ValueError(
            "unsupported_claims prediction indexes "
            "do not exactly match predicted findings."
        )


# ============================================================
# Semantic judge
# ============================================================


def call_semantic_judge(
    regression_case: dict,
    prediction: dict,
    model: str,
    max_retries: int = 3,
) -> SemanticEvaluation:

    user_prompt = build_judge_prompt(
        regression_case,
        prediction,
    )

    messages = [
        {
            "role": "system",
            "content": JUDGE_SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": user_prompt,
        },
    ]

    last_error = None

    for attempt in range(
        1,
        max_retries + 1,
    ):

        response = completion(
            model=model,
            messages=messages,
            temperature=0,
        )

        content = (
            response
            .choices[0]
            .message
            .content
            .strip()
        )

        try:
            result = (
                SemanticEvaluation
                .model_validate_json(
                    content
                )
            )

            validate_judge_result(
                regression_case,
                prediction,
                result,
            )

            return result

        except (
            ValidationError,
            ValueError,
        ) as exc:

            last_error = str(exc)

            if attempt == max_retries:
                break

            messages.append(
                {
                    "role": "assistant",
                    "content": content,
                }
            )

            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Your previous response "
                        "failed validation.\n\n"
                        f"Validation error:\n"
                        f"{last_error}\n\n"
                        "Correct the response and "
                        "return JSON only."
                    ),
                }
            )

    raise RuntimeError(
        "Semantic judge failed after "
        f"{max_retries} attempts. "
        f"Last error: {last_error}"
    )


# ============================================================
# Semantic metrics
# ============================================================


def calculate_semantic_metrics(
    regression_case: dict,
    prediction: dict,
    result: SemanticEvaluation,
) -> SemanticMetrics:

    expected = regression_case["expected"]

    required_findings = expected.get(
        "required_findings",
        [],
    )

    required_missing = expected.get(
        "required_missing_evidence",
        [],
    )

    predicted_findings = prediction.get(
        "findings",
        [],
    )

    # --------------------------------------------------------
    # Finding recall
    # --------------------------------------------------------

    matched_findings = sum(
        1
        for item in result.finding_matches
        if item.matched
    )

    if required_findings:
        finding_recall = (
            matched_findings
            / len(required_findings)
        )
    else:
        finding_recall = 1.0

    # --------------------------------------------------------
    # Missing evidence recall
    # --------------------------------------------------------

    matched_missing = sum(
        1
        for item
        in result.missing_evidence_matches
        if item.matched
    )

    if required_missing:
        missing_recall = (
            matched_missing
            / len(required_missing)
        )
    else:
        missing_recall = 1.0

    # --------------------------------------------------------
    # Unsupported / overclaiming
    # --------------------------------------------------------

    unsupported_count = sum(
        1
        for item in result.unsupported_claims
        if item.unsupported
    )

    overclaiming_count = sum(
        1
        for item in result.unsupported_claims
        if item.overclaiming
    )

    predicted_finding_count = len(
        predicted_findings
    )

    if predicted_finding_count:
        unsupported_rate = (
            unsupported_count
            / predicted_finding_count
        )

        overclaiming_rate = (
            overclaiming_count
            / predicted_finding_count
        )
    else:
        unsupported_rate = 0.0
        overclaiming_rate = 0.0

    return SemanticMetrics(
        required_finding_count=(
            len(required_findings)
        ),

        matched_required_finding_count=(
            matched_findings
        ),

        required_finding_recall=(
            finding_recall
        ),

        required_missing_evidence_count=(
            len(required_missing)
        ),

        matched_required_missing_evidence_count=(
            matched_missing
        ),

        required_missing_evidence_recall=(
            missing_recall
        ),

        predicted_finding_count=(
            predicted_finding_count
        ),

        unsupported_finding_count=(
            unsupported_count
        ),

        overclaiming_finding_count=(
            overclaiming_count
        ),

        unsupported_finding_rate=(
            unsupported_rate
        ),

        overclaiming_finding_rate=(
            overclaiming_rate
        ),
    )


# ============================================================
# Main
# ============================================================


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--regression",
        required=True,
        help="Path to regression.jsonl",
    )

    parser.add_argument(
        "--predictions",
        required=True,
        help="Path to predictions.jsonl",
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Path to scored_predictions.jsonl",
    )

    parser.add_argument(
        "--judge-model",
        default="ollama/gpt-oss:20b",
        help=(
            "LiteLLM model identifier for "
            "semantic judging."
        ),
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional number of cases to score.",
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    regression_cases = load_jsonl(
        args.regression
    )

    prediction_records = load_jsonl(
        args.predictions
    )

    regression_by_id = {
        case["case_id"]: case
        for case in regression_cases
    }

    output_path = Path(
        args.output
    )

    completed_cases = (
        load_completed_cases(
            output_path
        )
    )

    processed = 0

    # --------------------------------------------------------
    # Score predictions
    # --------------------------------------------------------

    for prediction_record in (
        prediction_records
    ):

        case_id = prediction_record[
            "case_id"
        ]

        if case_id in completed_cases:
            continue

        if case_id not in regression_by_id:
            print(
                f"Skipping unknown case_id: "
                f"{case_id}"
            )
            continue

        regression_case = (
            regression_by_id[
                case_id
            ]
        )

        # ----------------------------------------------------
        # Deterministic scoring
        # ----------------------------------------------------

        (
            deterministic,
            ioc_details,
        ) = score_deterministic(
            regression_case,
            prediction_record,
        )

        semantic_result = None
        semantic_metrics = None

        # ----------------------------------------------------
        # Semantic scoring
        # ----------------------------------------------------

        if deterministic.schema_valid:

            prediction = (
                prediction_record[
                    "prediction"
                ]
            )

            semantic_result = (
                call_semantic_judge(
                    regression_case=(
                        regression_case
                    ),
                    prediction=prediction,
                    model=args.judge_model,
                )
            )

            semantic_metrics = (
                calculate_semantic_metrics(
                    regression_case=(
                        regression_case
                    ),
                    prediction=prediction,
                    result=semantic_result,
                )
            )

        # ----------------------------------------------------
        # Save result
        # ----------------------------------------------------

        scored = ScoredPrediction(
            case_id=case_id,

            model=prediction_record[
                "model"
            ],

            deterministic=(
                deterministic
            ),

            ioc_details=ioc_details,

            semantic=semantic_metrics,

            semantic_details=(
                semantic_result
            ),
        )

        append_jsonl(
            output_path,
            scored.model_dump(),
        )

        processed += 1

        print(
            f"[{processed}] "
            f"Scored {case_id}"
        )

        # Useful quick visibility while testing
        print(
            "    "
            f"schema="
            f"{deterministic.schema_valid} "
            f"type="
            f"{deterministic.incident_type_correct} "
            f"severity="
            f"{deterministic.severity_correct} "
            f"ioc_recall="
            f"{deterministic.required_ioc_recall} "
            f"ioc_precision="
            f"{deterministic.ioc_precision} "
            f"ioc_grounding="
            f"{deterministic.ioc_grounding_rate}"
        )

        if semantic_metrics:
            print(
                "    "
                f"finding_recall="
                f"{semantic_metrics.required_finding_recall} "
                f"missing_recall="
                f"{semantic_metrics.required_missing_evidence_recall} "
                f"unsupported="
                f"{semantic_metrics.unsupported_finding_count} "
                f"overclaiming="
                f"{semantic_metrics.overclaiming_finding_count}"
            )

        if (
            args.limit is not None
            and processed >= args.limit
        ):
            break


if __name__ == "__main__":
    main()