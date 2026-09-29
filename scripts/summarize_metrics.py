import argparse
import json
from collections import Counter
from pathlib import Path
from statistics import mean


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


def save_json(
    path: Path,
    data: dict,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            ensure_ascii=False,
            indent=2,
        )

        file.write("\n")


# ============================================================
# Utility helpers
# ============================================================


def safe_divide(
    numerator: int | float,
    denominator: int | float,
    default: float = 0.0,
) -> float:
    if denominator == 0:
        return default

    return numerator / denominator


def average_non_null(
    values: list[float | None],
) -> float | None:
    valid_values = [
        value
        for value in values
        if value is not None
    ]

    if not valid_values:
        return None

    return mean(valid_values)


def count_true(
    values: list[bool | None],
) -> int:
    return sum(
        1
        for value in values
        if value is True
    )


def count_evaluated(
    values: list[bool | None],
) -> int:
    return sum(
        1
        for value in values
        if value is not None
    )


def round_metric(
    value: float | None,
    digits: int = 4,
) -> float | None:
    if value is None:
        return None

    return round(value, digits)


# ============================================================
# Validation
# ============================================================


def validate_records(
    records: list[dict],
) -> None:
    if not records:
        raise ValueError(
            "No scored predictions found."
        )

    seen_case_ids = set()

    for index, record in enumerate(
        records,
        start=1,
    ):
        case_id = record.get("case_id")

        if not case_id:
            raise ValueError(
                f"Record {index} has no case_id."
            )

        if case_id in seen_case_ids:
            raise ValueError(
                f"Duplicate case_id found: "
                f"{case_id}"
            )

        seen_case_ids.add(case_id)

        if "deterministic" not in record:
            raise ValueError(
                f"{case_id} is missing "
                f"deterministic metrics."
            )

        deterministic = record[
            "deterministic"
        ]

        if "schema_valid" not in deterministic:
            raise ValueError(
                f"{case_id} deterministic metrics "
                f"are missing schema_valid."
            )


# ============================================================
# Schema metrics
# ============================================================


def calculate_schema_metrics(
    records: list[dict],
) -> dict:
    total = len(records)

    valid = sum(
        1
        for record in records
        if record["deterministic"][
            "schema_valid"
        ]
    )

    invalid = total - valid

    return {
        "total_cases": total,
        "schema_valid_count": valid,
        "schema_invalid_count": invalid,
        "schema_validity_rate": (
            round_metric(
                safe_divide(
                    valid,
                    total,
                )
            )
        ),
    }


# ============================================================
# Classification metrics
# ============================================================


def calculate_classification_metrics(
    records: list[dict],
) -> dict:
    incident_type_values = [
        record["deterministic"].get(
            "incident_type_correct"
        )
        for record in records
    ]

    severity_values = [
        record["deterministic"].get(
            "severity_correct"
        )
        for record in records
    ]

    incident_type_evaluated = (
        count_evaluated(
            incident_type_values
        )
    )

    incident_type_correct = count_true(
        incident_type_values
    )

    severity_evaluated = count_evaluated(
        severity_values
    )

    severity_correct = count_true(
        severity_values
    )

    return {
        "incident_type": {
            "evaluated_count": (
                incident_type_evaluated
            ),
            "correct_count": (
                incident_type_correct
            ),
            "incorrect_count": (
                incident_type_evaluated
                - incident_type_correct
            ),
            "accuracy": round_metric(
                safe_divide(
                    incident_type_correct,
                    incident_type_evaluated,
                )
            ),
        },

        "severity": {
            "evaluated_count": (
                severity_evaluated
            ),
            "correct_count": (
                severity_correct
            ),
            "incorrect_count": (
                severity_evaluated
                - severity_correct
            ),
            "accuracy": round_metric(
                safe_divide(
                    severity_correct,
                    severity_evaluated,
                )
            ),
        },
    }


# ============================================================
# IOC metrics
# ============================================================


def calculate_ioc_metrics(
    records: list[dict],
) -> dict:

    # --------------------------------------------------------
    # Global counts
    # --------------------------------------------------------

    required_ioc_count = sum(
        record["deterministic"].get(
            "required_ioc_count",
            0,
        )
        for record in records
    )

    matched_required_ioc_count = sum(
        record["deterministic"].get(
            "matched_required_ioc_count",
            0,
        )
        for record in records
    )

    predicted_ioc_count = sum(
        record["deterministic"].get(
            "predicted_ioc_count",
            0,
        )
        for record in records
    )

    matched_predicted_ioc_count = sum(
        record["deterministic"].get(
            "matched_predicted_ioc_count",
            0,
        )
        for record in records
    )

    grounded_ioc_count = sum(
        record["deterministic"].get(
            "grounded_ioc_count",
            0,
        )
        for record in records
    )

    ungrounded_ioc_count = sum(
        record["deterministic"].get(
            "ungrounded_ioc_count",
            0,
        )
        for record in records
    )

    placeholder_ioc_count = sum(
        record["deterministic"].get(
            "placeholder_ioc_count",
            0,
        )
        for record in records
    )

    # --------------------------------------------------------
    # Micro metrics
    # --------------------------------------------------------

    micro_recall = safe_divide(
        matched_required_ioc_count,
        required_ioc_count,
    )

    micro_precision = safe_divide(
        matched_predicted_ioc_count,
        predicted_ioc_count,
    )

    micro_grounding_rate = safe_divide(
        grounded_ioc_count,
        predicted_ioc_count,
    )

    placeholder_rate = safe_divide(
        placeholder_ioc_count,
        predicted_ioc_count,
    )

    # --------------------------------------------------------
    # Macro metrics
    # --------------------------------------------------------

    macro_recall = average_non_null([
        record["deterministic"].get(
            "required_ioc_recall"
        )
        for record in records
    ])

    macro_precision = average_non_null([
        record["deterministic"].get(
            "ioc_precision"
        )
        for record in records
    ])

    macro_grounding = average_non_null([
        record["deterministic"].get(
            "ioc_grounding_rate"
        )
        for record in records
    ])

    # --------------------------------------------------------
    # Case-level diagnostics
    # --------------------------------------------------------

    cases_with_placeholders = sum(
        1
        for record in records
        if record["deterministic"].get(
            "placeholder_ioc_count",
            0,
        ) > 0
    )

    cases_with_ungrounded_iocs = sum(
        1
        for record in records
        if record["deterministic"].get(
            "ungrounded_ioc_count",
            0,
        ) > 0
    )

    return {
        "counts": {
            "required_iocs": (
                required_ioc_count
            ),
            "matched_required_iocs": (
                matched_required_ioc_count
            ),
            "predicted_iocs": (
                predicted_ioc_count
            ),
            "matched_predicted_iocs": (
                matched_predicted_ioc_count
            ),
            "grounded_iocs": (
                grounded_ioc_count
            ),
            "ungrounded_iocs": (
                ungrounded_ioc_count
            ),
            "placeholder_iocs": (
                placeholder_ioc_count
            ),
        },

        "micro": {
            "recall": round_metric(
                micro_recall
            ),
            "precision": round_metric(
                micro_precision
            ),
            "grounding_rate": round_metric(
                micro_grounding_rate
            ),
            "placeholder_rate": round_metric(
                placeholder_rate
            ),
        },

        "macro": {
            "recall": round_metric(
                macro_recall
            ),
            "precision": round_metric(
                macro_precision
            ),
            "grounding_rate": round_metric(
                macro_grounding
            ),
        },

        "diagnostics": {
            "cases_with_placeholder_iocs": (
                cases_with_placeholders
            ),
            "cases_with_ungrounded_iocs": (
                cases_with_ungrounded_iocs
            ),
        },
    }


# ============================================================
# Finding metrics
# ============================================================


def calculate_finding_metrics(
    records: list[dict],
) -> dict:

    semantic_records = [
        record
        for record in records
        if record.get("semantic") is not None
    ]

    required_count = sum(
        record["semantic"].get(
            "required_finding_count",
            0,
        )
        for record in semantic_records
    )

    matched_count = sum(
        record["semantic"].get(
            "matched_required_finding_count",
            0,
        )
        for record in semantic_records
    )

    predicted_count = sum(
        record["semantic"].get(
            "predicted_finding_count",
            0,
        )
        for record in semantic_records
    )

    unsupported_count = sum(
        record["semantic"].get(
            "unsupported_finding_count",
            0,
        )
        for record in semantic_records
    )

    overclaiming_count = sum(
        record["semantic"].get(
            "overclaiming_finding_count",
            0,
        )
        for record in semantic_records
    )

    # --------------------------------------------------------
    # Micro
    # --------------------------------------------------------

    micro_recall = safe_divide(
        matched_count,
        required_count,
    )

    unsupported_rate = safe_divide(
        unsupported_count,
        predicted_count,
    )

    overclaiming_rate = safe_divide(
        overclaiming_count,
        predicted_count,
    )

    # --------------------------------------------------------
    # Macro
    # --------------------------------------------------------

    macro_recall = average_non_null([
        record["semantic"].get(
            "required_finding_recall"
        )
        for record in semantic_records
    ])

    macro_unsupported_rate = (
        average_non_null([
            record["semantic"].get(
                "unsupported_finding_rate"
            )
            for record in semantic_records
        ])
    )

    macro_overclaiming_rate = (
        average_non_null([
            record["semantic"].get(
                "overclaiming_finding_rate"
            )
            for record in semantic_records
        ])
    )

    # --------------------------------------------------------
    # Diagnostics
    # --------------------------------------------------------

    cases_with_unsupported = sum(
        1
        for record in semantic_records
        if record["semantic"].get(
            "unsupported_finding_count",
            0,
        ) > 0
    )

    cases_with_overclaiming = sum(
        1
        for record in semantic_records
        if record["semantic"].get(
            "overclaiming_finding_count",
            0,
        ) > 0
    )

    return {
        "semantic_cases_evaluated": (
            len(semantic_records)
        ),

        "counts": {
            "required_findings": (
                required_count
            ),
            "matched_required_findings": (
                matched_count
            ),
            "predicted_findings": (
                predicted_count
            ),
            "unsupported_findings": (
                unsupported_count
            ),
            "overclaiming_findings": (
                overclaiming_count
            ),
        },

        "micro": {
            "required_finding_recall": (
                round_metric(
                    micro_recall
                )
            ),
            "unsupported_finding_rate": (
                round_metric(
                    unsupported_rate
                )
            ),
            "overclaiming_finding_rate": (
                round_metric(
                    overclaiming_rate
                )
            ),
        },

        "macro": {
            "required_finding_recall": (
                round_metric(
                    macro_recall
                )
            ),
            "unsupported_finding_rate": (
                round_metric(
                    macro_unsupported_rate
                )
            ),
            "overclaiming_finding_rate": (
                round_metric(
                    macro_overclaiming_rate
                )
            ),
        },

        "diagnostics": {
            "cases_with_unsupported_findings": (
                cases_with_unsupported
            ),
            "cases_with_overclaiming_findings": (
                cases_with_overclaiming
            ),
        },
    }


# ============================================================
# Missing evidence metrics
# ============================================================


def calculate_missing_evidence_metrics(
    records: list[dict],
) -> dict:

    semantic_records = [
        record
        for record in records
        if record.get("semantic") is not None
    ]

    required_count = sum(
        record["semantic"].get(
            "required_missing_evidence_count",
            0,
        )
        for record in semantic_records
    )

    matched_count = sum(
        record["semantic"].get(
            "matched_required_missing_evidence_count",
            0,
        )
        for record in semantic_records
    )

    micro_recall = safe_divide(
        matched_count,
        required_count,
    )

    macro_recall = average_non_null([
        record["semantic"].get(
            "required_missing_evidence_recall"
        )
        for record in semantic_records
    ])

    return {
        "semantic_cases_evaluated": (
            len(semantic_records)
        ),

        "counts": {
            "required_missing_evidence": (
                required_count
            ),
            "matched_required_missing_evidence": (
                matched_count
            ),
        },

        "micro": {
            "recall": round_metric(
                micro_recall
            ),
        },

        "macro": {
            "recall": round_metric(
                macro_recall
            ),
        },
    }


# ============================================================
# Per-case diagnostics
# ============================================================


def build_case_diagnostics(
    records: list[dict],
) -> dict:

    schema_failures = []

    incident_type_errors = []

    severity_errors = []

    incomplete_ioc_recall = []

    ioc_precision_errors = []

    ungrounded_ioc_cases = []

    placeholder_ioc_cases = []

    incomplete_finding_recall = []

    incomplete_missing_evidence = []

    unsupported_finding_cases = []

    overclaiming_finding_cases = []

    for record in records:

        case_id = record["case_id"]

        deterministic = record[
            "deterministic"
        ]

        semantic = record.get(
            "semantic"
        )

        # ----------------------------------------------------
        # Schema
        # ----------------------------------------------------

        if not deterministic.get(
            "schema_valid",
            False,
        ):
            schema_failures.append(
                case_id
            )

            # Other deterministic metrics are not
            # meaningful for invalid predictions.
            continue

        # ----------------------------------------------------
        # Classification
        # ----------------------------------------------------

        if (
            deterministic.get(
                "incident_type_correct"
            )
            is False
        ):
            incident_type_errors.append(
                case_id
            )

        if (
            deterministic.get(
                "severity_correct"
            )
            is False
        ):
            severity_errors.append(
                case_id
            )

        # ----------------------------------------------------
        # IOC
        # ----------------------------------------------------

        ioc_recall = deterministic.get(
            "required_ioc_recall"
        )

        if (
            ioc_recall is not None
            and ioc_recall < 1.0
        ):
            incomplete_ioc_recall.append(
                case_id
            )

        ioc_precision = deterministic.get(
            "ioc_precision"
        )

        if (
            ioc_precision is not None
            and ioc_precision < 1.0
        ):
            ioc_precision_errors.append(
                case_id
            )

        if deterministic.get(
            "ungrounded_ioc_count",
            0,
        ) > 0:
            ungrounded_ioc_cases.append(
                case_id
            )

        if deterministic.get(
            "placeholder_ioc_count",
            0,
        ) > 0:
            placeholder_ioc_cases.append(
                case_id
            )

        # ----------------------------------------------------
        # Semantic
        # ----------------------------------------------------

        if semantic is None:
            continue

        finding_recall = semantic.get(
            "required_finding_recall"
        )

        if (
            finding_recall is not None
            and finding_recall < 1.0
        ):
            incomplete_finding_recall.append(
                case_id
            )

        missing_recall = semantic.get(
            "required_missing_evidence_recall"
        )

        if (
            missing_recall is not None
            and missing_recall < 1.0
        ):
            incomplete_missing_evidence.append(
                case_id
            )

        if semantic.get(
            "unsupported_finding_count",
            0,
        ) > 0:
            unsupported_finding_cases.append(
                case_id
            )

        if semantic.get(
            "overclaiming_finding_count",
            0,
        ) > 0:
            overclaiming_finding_cases.append(
                case_id
            )

    return {
        "schema_failures": (
            schema_failures
        ),

        "incident_type_errors": (
            incident_type_errors
        ),

        "severity_errors": (
            severity_errors
        ),

        "incomplete_ioc_recall": (
            incomplete_ioc_recall
        ),

        "ioc_precision_errors": (
            ioc_precision_errors
        ),

        "ungrounded_ioc_cases": (
            ungrounded_ioc_cases
        ),

        "placeholder_ioc_cases": (
            placeholder_ioc_cases
        ),

        "incomplete_finding_recall": (
            incomplete_finding_recall
        ),

        "incomplete_missing_evidence": (
            incomplete_missing_evidence
        ),

        "unsupported_finding_cases": (
            unsupported_finding_cases
        ),

        "overclaiming_finding_cases": (
            overclaiming_finding_cases
        ),
    }


# ============================================================
# Model metadata
# ============================================================


def get_model_metadata(
    records: list[dict],
) -> dict:

    models = Counter(
        record.get(
            "model",
            "unknown",
        )
        for record in records
    )

    if len(models) == 1:
        model = next(
            iter(models.keys())
        )
    else:
        model = "mixed"

    return {
        "model": model,
        "models_found": dict(
            models
        ),
    }


# ============================================================
# Summary
# ============================================================


def summarize(
    records: list[dict],
) -> dict:

    validate_records(
        records
    )

    model_metadata = (
        get_model_metadata(
            records
        )
    )

    schema = (
        calculate_schema_metrics(
            records
        )
    )

    classification = (
        calculate_classification_metrics(
            records
        )
    )

    iocs = (
        calculate_ioc_metrics(
            records
        )
    )

    findings = (
        calculate_finding_metrics(
            records
        )
    )

    missing_evidence = (
        calculate_missing_evidence_metrics(
            records
        )
    )

    diagnostics = (
        build_case_diagnostics(
            records
        )
    )

    return {
        "model": (
            model_metadata["model"]
        ),

        "models_found": (
            model_metadata[
                "models_found"
            ]
        ),

        "total_cases": (
            len(records)
        ),

        "schema": schema,

        "classification": (
            classification
        ),

        "iocs": iocs,

        "findings": findings,

        "missing_evidence": (
            missing_evidence
        ),

        "diagnostics": diagnostics,
    }


# ============================================================
# Console report
# ============================================================


def print_summary(
    summary: dict,
) -> None:

    schema = summary["schema"]

    classification = (
        summary["classification"]
    )

    iocs = summary["iocs"]

    findings = summary["findings"]

    missing = summary[
        "missing_evidence"
    ]

    print()
    print("=" * 60)
    print("MODEL EVALUATION SUMMARY")
    print("=" * 60)

    print(
        f"Model:       "
        f"{summary['model']}"
    )

    print(
        f"Total cases: "
        f"{summary['total_cases']}"
    )

    print()

    # --------------------------------------------------------
    # Schema
    # --------------------------------------------------------

    print("SCHEMA")
    print("-" * 60)

    print(
        f"Valid:       "
        f"{schema['schema_valid_count']}"
        f"/{schema['total_cases']} "
        f"({schema['schema_validity_rate']:.2%})"
    )

    print()

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    print("CLASSIFICATION")
    print("-" * 60)

    incident_type_accuracy = (
        classification[
            "incident_type"
        ]["accuracy"]
    )

    severity_accuracy = (
        classification[
            "severity"
        ]["accuracy"]
    )

    print(
        f"Incident type accuracy: "
        f"{incident_type_accuracy:.2%}"
    )

    print(
        f"Severity accuracy:      "
        f"{severity_accuracy:.2%}"
    )

    print()

    # --------------------------------------------------------
    # IOC
    # --------------------------------------------------------

    print("IOCs")
    print("-" * 60)

    print(
        f"Micro recall:          "
        f"{iocs['micro']['recall']:.2%}"
    )

    print(
        f"Micro precision:       "
        f"{iocs['micro']['precision']:.2%}"
    )

    print(
        f"Grounding rate:        "
        f"{iocs['micro']['grounding_rate']:.2%}"
    )

    print(
        f"Placeholder IOC rate:  "
        f"{iocs['micro']['placeholder_rate']:.2%}"
    )

    print(
        f"Placeholder IOC count: "
        f"{iocs['counts']['placeholder_iocs']}"
    )

    print()

    # --------------------------------------------------------
    # Findings
    # --------------------------------------------------------

    print("FINDINGS")
    print("-" * 60)

    print(
        f"Finding recall:        "
        f"{findings['micro']['required_finding_recall']:.2%}"
    )

    print(
        f"Unsupported rate:      "
        f"{findings['micro']['unsupported_finding_rate']:.2%}"
    )

    print(
        f"Overclaiming rate:     "
        f"{findings['micro']['overclaiming_finding_rate']:.2%}"
    )

    print()

    # --------------------------------------------------------
    # Missing evidence
    # --------------------------------------------------------

    print("MISSING EVIDENCE")
    print("-" * 60)

    print(
        f"Recall:                "
        f"{missing['micro']['recall']:.2%}"
    )

    print()

    print("=" * 60)


# ============================================================
# Main
# ============================================================


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate scored incident-analysis "
            "predictions into model-level metrics."
        )
    )

    parser.add_argument(
        "--scored",
        required=True,
        help=(
            "Path to scored_predictions.jsonl"
        ),
    )

    parser.add_argument(
        "--output",
        required=True,
        help=(
            "Path to output metrics.json"
        ),
    )

    args = parser.parse_args()

    scored_path = Path(
        args.scored
    )

    output_path = Path(
        args.output
    )

    records = load_jsonl(
        str(scored_path)
    )

    summary = summarize(
        records
    )

    save_json(
        output_path,
        summary,
    )

    print_summary(
        summary
    )

    print(
        f"\nSaved metrics to: "
        f"{output_path}"
    )


if __name__ == "__main__":
    main()