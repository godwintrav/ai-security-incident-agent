import argparse
import json

from dataclasses import dataclass
from pathlib import Path


# ============================================================
# Metric definitions
# ============================================================


@dataclass(frozen=True)
class MetricDefinition:
    name: str
    path: tuple[str, ...]
    higher_is_better: bool = True


METRICS = [
    MetricDefinition(
        name="Schema validity",
        path=("schema", "schema_validity_rate"),
    ),
    MetricDefinition(
        name="Incident type accuracy",
        path=("classification", "incident_type", "accuracy"),
    ),
    MetricDefinition(
        name="Severity accuracy",
        path=("classification", "severity", "accuracy"),
    ),
    MetricDefinition(
        name="IOC recall",
        path=("iocs", "micro", "recall"),
    ),
    MetricDefinition(
        name="IOC precision",
        path=("iocs", "micro", "precision"),
    ),
    MetricDefinition(
        name="IOC grounding",
        path=("iocs", "micro", "grounding_rate"),
    ),
    MetricDefinition(
        name="Placeholder IOC rate",
        path=("iocs", "micro", "placeholder_rate"),
        higher_is_better=False,
    ),
    MetricDefinition(
        name="Finding recall",
        path=("findings", "micro", "required_finding_recall"),
    ),
    MetricDefinition(
        name="Unsupported finding rate",
        path=("findings", "micro", "unsupported_finding_rate"),
        higher_is_better=False,
    ),
    MetricDefinition(
        name="Overclaiming finding rate",
        path=("findings", "micro", "overclaiming_finding_rate"),
        higher_is_better=False,
    ),
    MetricDefinition(
        name="Missing evidence recall",
        path=("missing_evidence", "micro", "recall"),
    ),
]


# ============================================================
# Arguments
# ============================================================


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Compare evaluation metrics across multiple model variants."
        )
    )

    parser.add_argument(
        "--model",
        action="append",
        nargs=2,
        metavar=("LABEL", "METRICS_PATH"),
        required=True,
        help=(
            "Model label followed by path to metrics.json. "
            "Repeat this argument for each model."
        ),
    )

    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help=(
            "Optional path where the comparison JSON should be saved."
        ),
    )

    return parser.parse_args()


# ============================================================
# Loading
# ============================================================


def load_json(path: str) -> dict:
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Metrics file does not exist: {file_path}"
        )

    with file_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


# ============================================================
# Metric extraction
# ============================================================


def get_nested_value(
    data: dict,
    path: tuple[str, ...],
):
    current = data

    for key in path:
        if not isinstance(current, dict):
            return None

        if key not in current:
            return None

        current = current[key]

    return current


def extract_metrics(data: dict) -> dict[str, float | None]:
    result = {}

    for metric in METRICS:
        value = get_nested_value(
            data,
            metric.path,
        )

        result[metric.name] = value

    return result


# ============================================================
# Formatting
# ============================================================


def percentage(value):
    if value is None:
        return "N/A"

    return f"{value * 100:.2f}%"


def percentage_points(value):
    if value is None:
        return "N/A"

    pp = value * 100

    return f"{pp:+.2f} pp"


def direction_symbol(
    delta: float | None,
    higher_is_better: bool,
):
    if delta is None:
        return ""

    if abs(delta) < 1e-12:
        return "="

    improved = (
        delta > 0
        if higher_is_better
        else delta < 0
    )

    return "↑" if improved else "↓"


# ============================================================
# Comparison
# ============================================================


def build_comparison(
    models: list[dict],
):
    baseline = models[0]

    comparison = {
        "baseline": baseline["label"],
        "models": [],
        "metrics": [],
    }

    for model in models:
        comparison["models"].append(
            {
                "label": model["label"],
                "metrics_path": model["metrics_path"],
                "model_name": model["raw"].get("model"),
                "total_cases": model["raw"].get("total_cases"),
            }
        )

    for metric_definition in METRICS:
        metric_name = metric_definition.name

        baseline_value = baseline["metrics"].get(
            metric_name
        )

        metric_result = {
            "metric": metric_name,
            "higher_is_better": (
                metric_definition.higher_is_better
            ),
            "values": {},
        }

        for model in models:
            value = model["metrics"].get(
                metric_name
            )

            if (
                value is not None
                and baseline_value is not None
            ):
                delta = value - baseline_value
            else:
                delta = None

            metric_result["values"][model["label"]] = {
                "value": value,
                "delta_vs_baseline": delta,
            }

        comparison["metrics"].append(
            metric_result
        )

    return comparison


# ============================================================
# Console output
# ============================================================


def print_comparison(
    models: list[dict],
):
    baseline = models[0]

    print()
    print("=" * 100)
    print("MODEL EVALUATION COMPARISON")
    print("=" * 100)
    print()

    print(f"Baseline: {baseline['label']}")
    print()

    # --------------------------------------------------------
    # Model metadata
    # --------------------------------------------------------

    print("MODELS")
    print("-" * 100)

    for model in models:
        raw = model["raw"]

        print(
            f"{model['label']:<24} "
            f"model={raw.get('model', 'unknown')} "
            f"cases={raw.get('total_cases', 'unknown')}"
        )

    print()

    # --------------------------------------------------------
    # Table header
    # --------------------------------------------------------

    metric_width = 30
    model_width = 18

    header = f"{'Metric':<{metric_width}}"

    for model in models:
        header += (
            f"{model['label']:>{model_width}}"
        )

        if model is not baseline:
            header += f"{'Δ baseline':>16}"

    print(header)
    print("-" * len(header))

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    for metric_definition in METRICS:
        metric_name = metric_definition.name

        baseline_value = baseline["metrics"].get(
            metric_name
        )

        row = f"{metric_name:<{metric_width}}"

        for model in models:
            value = model["metrics"].get(
                metric_name
            )

            row += (
                f"{percentage(value):>{model_width}}"
            )

            if model is not baseline:
                if (
                    value is not None
                    and baseline_value is not None
                ):
                    delta = value - baseline_value
                else:
                    delta = None

                symbol = direction_symbol(
                    delta,
                    metric_definition.higher_is_better,
                )

                delta_text = percentage_points(
                    delta
                )

                if symbol:
                    delta_text = (
                        f"{delta_text} {symbol}"
                    )

                row += f"{delta_text:>16}"

        print(row)

    print()
    print("=" * 100)

    print()
    print(
        "↑ = improvement relative to baseline"
    )
    print(
        "↓ = regression relative to baseline"
    )
    print(
        "= = unchanged relative to baseline"
    )
    print()

    print(
        "For error-rate metrics "
        "(placeholder IOC, unsupported findings, "
        "overclaiming), lower is better."
    )

    print()


# ============================================================
# Pairwise summary
# ============================================================


def print_pairwise_changes(
    models: list[dict],
):
    if len(models) < 2:
        return

    print("=" * 100)
    print("PAIRWISE CHANGES")
    print("=" * 100)

    for previous, current in zip(
        models,
        models[1:],
    ):
        print()
        print(
            f"{previous['label']} → "
            f"{current['label']}"
        )

        print("-" * 100)

        for metric_definition in METRICS:
            metric_name = metric_definition.name

            previous_value = previous[
                "metrics"
            ].get(metric_name)

            current_value = current[
                "metrics"
            ].get(metric_name)

            if (
                previous_value is None
                or current_value is None
            ):
                continue

            delta = (
                current_value
                - previous_value
            )

            symbol = direction_symbol(
                delta,
                metric_definition.higher_is_better,
            )

            print(
                f"{metric_name:<30} "
                f"{percentage(previous_value):>10} "
                f"→ "
                f"{percentage(current_value):>10} "
                f"{percentage_points(delta):>12} "
                f"{symbol}"
            )

    print()


# ============================================================
# Save comparison
# ============================================================


def save_comparison(
    output_path: str,
    comparison: dict,
):
    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            comparison,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print(
        f"Saved comparison to: {path}"
    )


# ============================================================
# Main
# ============================================================


def main():
    args = parse_args()

    if len(args.model) < 2:
        raise ValueError(
            "At least two --model arguments are required."
        )

    models = []

    labels = set()

    for label, metrics_path in args.model:
        if label in labels:
            raise ValueError(
                f"Duplicate model label: {label}"
            )

        labels.add(label)

        raw = load_json(
            metrics_path
        )

        metrics = extract_metrics(
            raw
        )

        models.append(
            {
                "label": label,
                "metrics_path": metrics_path,
                "raw": raw,
                "metrics": metrics,
            }
        )

    print_comparison(
        models
    )

    print_pairwise_changes(
        models
    )

    comparison = build_comparison(
        models
    )

    if args.output:
        save_comparison(
            args.output,
            comparison,
        )


if __name__ == "__main__":
    main()