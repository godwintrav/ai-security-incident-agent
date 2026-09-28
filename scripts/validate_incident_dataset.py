import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError
from typing import Literal


# ============================================================
# Incident Analysis Schema
# ============================================================

IncidentType = Literal[
    "credential_compromise",
    "phishing",
    "malware",
    "suspicious_network_activity",
    "unknown",
]

Severity = Literal[
    "low",
    "medium",
    "high",
    "critical",
]


class IOC(BaseModel):
    type: str = Field(
        description="Type of indicator of compromise."
    )

    value: str = Field(
        description="The actual indicator value."
    )

    evidence_ids: list[str] = Field(
        description="Evidence IDs supporting this IOC."
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence that this IOC is relevant."
    )


class Finding(BaseModel):
    title: str = Field(
        description="Short title describing the finding."
    )

    description: str = Field(
        description="Brief description of the finding."
    )

    assessment: str = Field(
        description="Evidence-grounded assessment."
    )

    evidence_ids: list[str] = Field(
        description="Evidence IDs supporting the finding."
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in the finding."
    )


class MissingEvidence(BaseModel):
    description: str = Field(
        description="Evidence that is currently missing."
    )

    reason: str = Field(
        description="Why the missing evidence is important."
    )

    priority: Literal["low", "medium", "high"] = Field(
        description="Priority of obtaining the missing evidence."
    )

    suggested_source: str = Field(
        description="Suggested source for obtaining the evidence."
    )


class IncidentAnalysis(BaseModel):
    incident_type: IncidentType

    severity: Severity

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    iocs: list[IOC]

    findings: list[Finding]

    missing_evidence: list[MissingEvidence]

    analysis_summary: str


# ============================================================
# Dataset Validation Helpers
# ============================================================

EXPECTED_ROLES = [
    "system",
    "user",
    "assistant",
]

EXPECTED_INPUT_KEYS = {
    "incident",
    "evidence",
    "security_knowledge",
    "playbook",
    "cve_results",
}

EXPECTED_INCIDENT_KEYS = {
    "description",
    "incident_type",
}


class ValidationReport:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.info: list[str] = []

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)

    def info_message(self, message: str) -> None:
        self.info.append(message)


# ============================================================
# JSONL Loading
# ============================================================

def load_jsonl(
    path: Path,
    report: ValidationReport,
    dataset_name: str,
) -> list[dict[str, Any]]:
    if not path.exists():
        report.error(
            f"{dataset_name}: file does not exist: {path}"
        )
        return []

    examples = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                report.warning(
                    f"{dataset_name}: empty line at line {line_number}"
                )
                continue

            try:
                example = json.loads(line)
            except json.JSONDecodeError as exc:
                report.error(
                    f"{dataset_name}: invalid JSON at line "
                    f"{line_number}: {exc}"
                )
                continue

            if not isinstance(example, dict):
                report.error(
                    f"{dataset_name}: line {line_number} "
                    f"must contain a JSON object."
                )
                continue

            examples.append(example)

    return examples


# ============================================================
# Generic Utilities
# ============================================================

def stable_hash(value: Any) -> str:
    serialized = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def get_nested(
    obj: dict[str, Any],
    *keys: str,
) -> Any:
    current = obj

    for key in keys:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

    return current


def stringify(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
    )


# ============================================================
# Training Example Validation
# ============================================================

def validate_training_structure(
    example: dict[str, Any],
    index: int,
    report: ValidationReport,
) -> tuple[dict[str, Any] | None, IncidentAnalysis | None]:
    location = f"training[{index}]"

    messages = example.get("messages")

    if not isinstance(messages, list):
        report.error(
            f"{location}: 'messages' must be a list."
        )
        return None, None

    if len(messages) != 3:
        report.error(
            f"{location}: expected exactly 3 messages, "
            f"got {len(messages)}."
        )
        return None, None

    for message_index, message in enumerate(messages):
        if not isinstance(message, dict):
            report.error(
                f"{location}: message[{message_index}] "
                f"must be an object."
            )
            continue

        if "role" not in message:
            report.error(
                f"{location}: message[{message_index}] "
                f"is missing 'role'."
            )

        if "content" not in message:
            report.error(
                f"{location}: message[{message_index}] "
                f"is missing 'content'."
            )

        if not isinstance(
            message.get("content"),
            str,
        ):
            report.error(
                f"{location}: message[{message_index}] "
                f"'content' must be a string."
            )

    roles = [
        message.get("role")
        for message in messages
    ]

    if roles != EXPECTED_ROLES:
        report.error(
            f"{location}: expected roles "
            f"{EXPECTED_ROLES}, got {roles}."
        )

    user_content = messages[1].get("content")
    assistant_content = messages[2].get("content")

    if not isinstance(user_content, str):
        return None, None

    if not isinstance(assistant_content, str):
        return None, None

    # --------------------------------------------------------
    # Parse user JSON
    # --------------------------------------------------------

    try:
        input_data = json.loads(user_content)
    except json.JSONDecodeError as exc:
        report.error(
            f"{location}: user content is not valid JSON: {exc}"
        )
        return None, None

    if not isinstance(input_data, dict):
        report.error(
            f"{location}: user content must decode "
            f"to an object."
        )
        return None, None

    missing_input_keys = (
        EXPECTED_INPUT_KEYS
        - set(input_data.keys())
    )

    if missing_input_keys:
        report.error(
            f"{location}: missing input keys: "
            f"{sorted(missing_input_keys)}"
        )

    incident = input_data.get("incident")

    if not isinstance(incident, dict):
        report.error(
            f"{location}: 'incident' must be an object."
        )
    else:
        missing_incident_keys = (
            EXPECTED_INCIDENT_KEYS
            - set(incident.keys())
        )

        if missing_incident_keys:
            report.error(
                f"{location}: incident missing keys: "
                f"{sorted(missing_incident_keys)}"
            )

        if not isinstance(
            incident.get("description"),
            str,
        ):
            report.error(
                f"{location}: incident.description "
                f"must be a string."
            )

    evidence = input_data.get("evidence")

    if not isinstance(evidence, list):
        report.error(
            f"{location}: 'evidence' must be a list."
        )
    else:
        validate_evidence_structure(
            evidence,
            location,
            report,
        )

    # --------------------------------------------------------
    # Parse assistant JSON
    # --------------------------------------------------------

    try:
        analysis = IncidentAnalysis.model_validate_json(
            assistant_content
        )
    except ValidationError as exc:
        report.error(
            f"{location}: IncidentAnalysis validation failed:\n"
            f"{exc}"
        )
        return input_data, None

    return input_data, analysis


# ============================================================
# Evidence Validation
# ============================================================

def validate_evidence_structure(
    evidence: list[Any],
    location: str,
    report: ValidationReport,
) -> None:
    seen_ids: set[str] = set()

    for evidence_index, item in enumerate(evidence):
        evidence_location = (
            f"{location}.evidence[{evidence_index}]"
        )

        if not isinstance(item, dict):
            report.error(
                f"{evidence_location}: evidence "
                f"must be an object."
            )
            continue

        required_keys = {
            "id",
            "type",
            "source",
            "timestamp",
            "content",
        }

        missing = required_keys - set(item.keys())

        if missing:
            report.error(
                f"{evidence_location}: missing keys: "
                f"{sorted(missing)}"
            )

        evidence_id = item.get("id")

        if not isinstance(evidence_id, str):
            report.error(
                f"{evidence_location}: id must be a string."
            )
            continue

        if evidence_id in seen_ids:
            report.error(
                f"{evidence_location}: duplicate evidence ID: "
                f"{evidence_id}"
            )

        seen_ids.add(evidence_id)


# ============================================================
# Evidence Grounding
# ============================================================

def validate_evidence_grounding(
    input_data: dict[str, Any],
    analysis: IncidentAnalysis,
    index: int,
    report: ValidationReport,
) -> None:
    location = f"training[{index}]"

    evidence = input_data.get("evidence", [])

    if not isinstance(evidence, list):
        return

    evidence_by_id = {
        item.get("id"): item
        for item in evidence
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
    }

    # --------------------------------------------------------
    # IOC validation
    # --------------------------------------------------------

    for ioc_index, ioc in enumerate(analysis.iocs):
        ioc_location = (
            f"{location}.iocs[{ioc_index}]"
        )

        if not ioc.evidence_ids:
            report.warning(
                f"{ioc_location}: IOC has no evidence IDs."
            )

        for evidence_id in ioc.evidence_ids:
            if evidence_id not in evidence_by_id:
                report.error(
                    f"{ioc_location}: references "
                    f"nonexistent evidence ID '{evidence_id}'."
                )
                continue

            evidence_item = evidence_by_id[evidence_id]

            evidence_text = stringify(evidence_item)

            if ioc.value not in evidence_text:
                report.error(
                    f"{ioc_location}: IOC value "
                    f"'{ioc.value}' does not appear in "
                    f"referenced evidence '{evidence_id}'."
                )

    # --------------------------------------------------------
    # Finding validation
    # --------------------------------------------------------

    for finding_index, finding in enumerate(
        analysis.findings
    ):
        finding_location = (
            f"{location}.findings[{finding_index}]"
        )

        if not finding.evidence_ids:
            report.warning(
                f"{finding_location}: finding has "
                f"no evidence IDs."
            )

        for evidence_id in finding.evidence_ids:
            if evidence_id not in evidence_by_id:
                report.error(
                    f"{finding_location}: references "
                    f"nonexistent evidence ID '{evidence_id}'."
                )


# ============================================================
# Classification Consistency
# ============================================================

def validate_classification(
    input_data: dict[str, Any],
    analysis: IncidentAnalysis,
    index: int,
    report: ValidationReport,
) -> None:
    location = f"training[{index}]"

    incident = input_data.get("incident", {})

    if not isinstance(incident, dict):
        return

    input_type = incident.get("incident_type")

    if input_type not in {
        "credential_compromise",
        "phishing",
        "malware",
        "suspicious_network_activity",
    }:
        report.warning(
            f"{location}: input incident_type "
            f"'{input_type}' is not one of the known "
            f"incident types."
        )
        return

    if analysis.incident_type == "unknown":
        report.info_message(
            f"{location}: model output classified "
            f"known input type '{input_type}' as unknown."
        )


# ============================================================
# Training Statistics
# ============================================================

def collect_training_statistics(
    validated_examples: list[
        tuple[dict[str, Any], IncidentAnalysis]
    ],
) -> dict[str, Counter]:
    incident_types = Counter()
    severities = Counter()
    missing_evidence = Counter()
    ioc_types = Counter()
    ioc_counts = Counter()
    finding_counts = Counter()

    for input_data, analysis in validated_examples:
        input_type = get_nested(
            input_data,
            "incident",
            "incident_type",
        )

        incident_types[input_type] += 1
        severities[analysis.severity] += 1

        missing_evidence[
            "with_missing_evidence"
            if analysis.missing_evidence
            else "without_missing_evidence"
        ] += 1

        for ioc in analysis.iocs:
            ioc_types[ioc.type] += 1

        ioc_counts[
            len(analysis.iocs)
        ] += 1

        finding_counts[
            len(analysis.findings)
        ] += 1

    return {
        "incident_types": incident_types,
        "severities": severities,
        "missing_evidence": missing_evidence,
        "ioc_types": ioc_types,
        "ioc_counts": ioc_counts,
        "finding_counts": finding_counts,
    }


# ============================================================
# Duplicate Detection
# ============================================================

def get_training_input_fingerprint(
    input_data: dict[str, Any],
) -> str:
    return stable_hash(input_data)


def validate_training_duplicates(
    validated_inputs: list[dict[str, Any]],
    report: ValidationReport,
) -> None:
    seen: dict[str, int] = {}

    for index, input_data in enumerate(
        validated_inputs
    ):
        fingerprint = get_training_input_fingerprint(
            input_data
        )

        if fingerprint in seen:
            report.error(
                "Duplicate training input: "
                f"training[{index}] duplicates "
                f"training[{seen[fingerprint]}]."
            )
        else:
            seen[fingerprint] = index


# ============================================================
# Regression Validation
# ============================================================

def validate_regression(
    regression_examples: list[dict[str, Any]],
    report: ValidationReport,
) -> list[dict[str, Any]]:
    validated = []

    for index, example in enumerate(
        regression_examples
    ):
        location = f"regression[{index}]"

        required_keys = {
            "case_id",
            "input",
            "expected",
            "evaluation_requirements",
        }

        missing = required_keys - set(example.keys())

        if missing:
            report.error(
                f"{location}: missing keys: "
                f"{sorted(missing)}"
            )
            continue

        case_id = example.get("case_id")

        if not isinstance(case_id, str):
            report.error(
                f"{location}: case_id must be a string."
            )

        input_data = example.get("input")

        if not isinstance(input_data, dict):
            report.error(
                f"{location}: input must be an object."
            )
            continue

        incident = input_data.get("incident")

        if not isinstance(incident, dict):
            report.error(
                f"{location}: input.incident "
                f"must be an object."
            )
        else:
            if not isinstance(
                incident.get("description"),
                str,
            ):
                report.error(
                    f"{location}: incident.description "
                    f"must be a string."
                )

        evidence = input_data.get("evidence")

        if not isinstance(evidence, list):
            report.error(
                f"{location}: evidence must be a list."
            )
        else:
            validate_evidence_structure(
                evidence,
                location,
                report,
            )

        expected = example.get("expected")

        if not isinstance(expected, dict):
            report.error(
                f"{location}: expected must be an object."
            )

        validated.append(example)

    return validated


# ============================================================
# Train / Regression Leakage
# ============================================================

def validate_train_regression_leakage(
    training_inputs: list[dict[str, Any]],
    regression_examples: list[dict[str, Any]],
    report: ValidationReport,
) -> None:
    train_fingerprints = {
        stable_hash(input_data)
        for input_data in training_inputs
    }

    for index, example in enumerate(
        regression_examples
    ):
        input_data = example.get("input")

        if not isinstance(input_data, dict):
            continue

        fingerprint = stable_hash(input_data)

        if fingerprint in train_fingerprints:
            report.error(
                f"Data leakage: regression[{index}] "
                f"has the exact same input as a "
                f"training example."
            )


# ============================================================
# Regression / Training Description Overlap
# ============================================================

def validate_description_overlap(
    training_inputs: list[dict[str, Any]],
    regression_examples: list[dict[str, Any]],
    report: ValidationReport,
) -> None:
    training_descriptions = {
        get_nested(
            input_data,
            "incident",
            "description",
        )
        for input_data in training_inputs
    }

    for index, example in enumerate(
        regression_examples
    ):
        description = get_nested(
            example,
            "input",
            "incident",
            "description",
        )

        if (
            description
            and description in training_descriptions
        ):
            report.warning(
                f"regression[{index}]: incident "
                f"description exactly matches a "
                f"training example."
            )


# ============================================================
# Distribution Report
# ============================================================

def print_counter(
    title: str,
    counter: Counter,
) -> None:
    print(f"\n{title}")

    if not counter:
        print("  None")
        return

    for key, count in counter.most_common():
        print(f"  {str(key):35} {count}")


def print_statistics(
    statistics: dict[str, Counter],
) -> None:
    print("\n" + "=" * 60)
    print("DATASET DISTRIBUTION")
    print("=" * 60)

    print_counter(
        "Incident Types",
        statistics["incident_types"],
    )

    print_counter(
        "Severities",
        statistics["severities"],
    )

    print_counter(
        "Missing Evidence",
        statistics["missing_evidence"],
    )

    print_counter(
        "IOC Types",
        statistics["ioc_types"],
    )

    print_counter(
        "IOC Count Per Example",
        statistics["ioc_counts"],
    )

    print_counter(
        "Finding Count Per Example",
        statistics["finding_counts"],
    )


# ============================================================
# Matrix: Severity × Missing Evidence
# ============================================================

def print_severity_missing_matrix(
    validated_examples: list[
        tuple[dict[str, Any], IncidentAnalysis]
    ],
) -> None:
    matrix = Counter()

    for _, analysis in validated_examples:
        missing = (
            "missing"
            if analysis.missing_evidence
            else "none"
        )

        matrix[
            (analysis.severity, missing)
        ] += 1

    print("\n" + "=" * 60)
    print("SEVERITY × MISSING EVIDENCE")
    print("=" * 60)

    print(
        f"{'Severity':<15}"
        f"{'No Missing':<15}"
        f"{'Missing':<15}"
    )

    print("-" * 45)

    for severity in [
        "low",
        "medium",
        "high",
        "critical",
    ]:
        print(
            f"{severity:<15}"
            f"{matrix[(severity, 'none')]:<15}"
            f"{matrix[(severity, 'missing')]:<15}"
        )


# ============================================================
# Main
# ============================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the AI Security Incident "
            "Analysis training and regression datasets."
        )
    )

    parser.add_argument(
        "--train",
        required=True,
        type=Path,
        help="Path to training JSONL file.",
    )

    parser.add_argument(
        "--regression",
        required=False,
        type=Path,
        help="Path to regression JSONL file.",
    )

    args = parser.parse_args()

    report = ValidationReport()

    print("=" * 60)
    print("INCIDENT ANALYSIS DATASET VALIDATION")
    print("=" * 60)

    # --------------------------------------------------------
    # Load training dataset
    # --------------------------------------------------------

    training_examples = load_jsonl(
        args.train,
        report,
        "training",
    )

    print(
        f"\nTraining examples loaded: "
        f"{len(training_examples)}"
    )

    # --------------------------------------------------------
    # Validate training examples
    # --------------------------------------------------------

    validated_examples: list[
        tuple[dict[str, Any], IncidentAnalysis]
    ] = []

    training_inputs: list[dict[str, Any]] = []

    for index, example in enumerate(
        training_examples
    ):
        input_data, analysis = (
            validate_training_structure(
                example,
                index,
                report,
            )
        )

        if input_data is None:
            continue

        training_inputs.append(input_data)

        if analysis is None:
            continue

        validate_evidence_grounding(
            input_data,
            analysis,
            index,
            report,
        )

        validate_classification(
            input_data,
            analysis,
            index,
            report,
        )

        validated_examples.append(
            (input_data, analysis)
        )

    # --------------------------------------------------------
    # Duplicate checks
    # --------------------------------------------------------

    validate_training_duplicates(
        training_inputs,
        report,
    )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    statistics = collect_training_statistics(
        validated_examples
    )

    print_statistics(statistics)

    print_severity_missing_matrix(
        validated_examples
    )

    # --------------------------------------------------------
    # Regression dataset
    # --------------------------------------------------------

    regression_examples: list[dict[str, Any]] = []

    if args.regression:
        regression_examples = load_jsonl(
            args.regression,
            report,
            "regression",
        )

        print(
            f"\nRegression examples loaded: "
            f"{len(regression_examples)}"
        )

        regression_examples = validate_regression(
            regression_examples,
            report,
        )

        validate_train_regression_leakage(
            training_inputs,
            regression_examples,
            report,
        )

        validate_description_overlap(
            training_inputs,
            regression_examples,
            report,
        )

    # --------------------------------------------------------
    # Final report
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)

    print(
        f"\nTraining examples: "
        f"{len(training_examples)}"
    )

    print(
        f"Valid IncidentAnalysis outputs: "
        f"{len(validated_examples)}"
    )

    if args.regression:
        print(
            f"Regression examples: "
            f"{len(regression_examples)}"
        )

    print(
        f"\nErrors:   {len(report.errors)}"
    )

    print(
        f"Warnings: {len(report.warnings)}"
    )

    print(
        f"Info:     {len(report.info)}"
    )

    # --------------------------------------------------------
    # Errors
    # --------------------------------------------------------

    if report.errors:
        print("\n" + "-" * 60)
        print("ERRORS")
        print("-" * 60)

        for error in report.errors:
            print(f"❌ {error}")

    # --------------------------------------------------------
    # Warnings
    # --------------------------------------------------------

    if report.warnings:
        print("\n" + "-" * 60)
        print("WARNINGS")
        print("-" * 60)

        for warning in report.warnings:
            print(f"⚠️  {warning}")

    # --------------------------------------------------------
    # Informational findings
    # --------------------------------------------------------

    if report.info:
        print("\n" + "-" * 60)
        print("INFORMATION")
        print("-" * 60)

        for message in report.info:
            print(f"ℹ️  {message}")

    # --------------------------------------------------------
    # Final status
    # --------------------------------------------------------

    print("\n" + "=" * 60)

    if report.passed:
        print("RESULT: ✅ PASS")
        print(
            "Dataset passed all automated validation checks."
        )
        print(
            "Next step: semantic review and then "
            "base-model selection."
        )
        print("=" * 60)

        return 0

    print("RESULT: ❌ FAIL")
    print(
        "Dataset requires correction before "
        "fine-tuning preparation."
    )
    print("=" * 60)

    return 1


if __name__ == "__main__":
    sys.exit(main())