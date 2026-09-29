import argparse
import json
import math
from pathlib import Path

import numpy as np
from transformers import AutoTokenizer


def load_jsonl(path: Path) -> list[dict]:
    rows = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {exc}"
                ) from exc

    return rows


def percentile(values: list[int], value: float) -> int:
    return int(math.ceil(np.percentile(values, value)))


def calculate_stats(values: list[int]) -> dict:
    return {
        "min": min(values),
        "mean": round(float(np.mean(values)), 2),
        "median": round(float(np.median(values)), 2),
        "p90": percentile(values, 90),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "max": max(values),
    }


def count_tokens(
    tokenizer,
    text: str,
) -> int:
    return len(
        tokenizer.encode(
            text,
            add_special_tokens=False,
        )
    )


def count_conversation_tokens(
    tokenizer,
    messages: list[dict],
) -> int:

    # This is the most important measurement.
    #
    # Instead of simply tokenizing the raw strings, we apply the
    # model's chat template first. This includes tokens inserted by
    # the model's actual conversation format.

    encoded = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=False,
    )

    return len(encoded["input_ids"])


def analyze(
    dataset: list[dict],
    tokenizer,
) -> dict:

    system_lengths = []
    user_lengths = []
    assistant_lengths = []
    total_lengths = []

    examples = []

    for index, row in enumerate(dataset):

        messages = row["messages"]

        system_message = next(
            message
            for message in messages
            if message["role"] == "system"
        )

        user_message = next(
            message
            for message in messages
            if message["role"] == "user"
        )

        assistant_message = next(
            message
            for message in messages
            if message["role"] == "assistant"
        )

        system_tokens = count_tokens(
            tokenizer,
            system_message["content"],
        )

        user_tokens = count_tokens(
            tokenizer,
            user_message["content"],
        )

        assistant_tokens = count_tokens(
            tokenizer,
            assistant_message["content"],
        )

        total_tokens = count_conversation_tokens(
            tokenizer,
            messages,
        )

        system_lengths.append(system_tokens)
        user_lengths.append(user_tokens)
        assistant_lengths.append(assistant_tokens)
        total_lengths.append(total_tokens)

        examples.append(
            {
                "training_index": index,
                "system_tokens": system_tokens,
                "user_tokens": user_tokens,
                "assistant_tokens": assistant_tokens,
                "total_tokens": total_tokens,
            }
        )

    thresholds = {}

    for threshold in [1024, 2048, 4096, 8192]:
        count = sum(
            length > threshold
            for length in total_lengths
        )

        thresholds[str(threshold)] = {
            "count": count,
            "percentage": round(
                (count / len(total_lengths)) * 100,
                2,
            ),
        }

    longest_examples = sorted(
        examples,
        key=lambda item: item["total_tokens"],
        reverse=True,
    )[:10]

    return {
        "examples": len(dataset),
        "system": calculate_stats(system_lengths),
        "user": calculate_stats(user_lengths),
        "assistant": calculate_stats(assistant_lengths),
        "total": calculate_stats(total_lengths),
        "thresholds": thresholds,
        "longest_examples": longest_examples,
    }


def print_stats(
    title: str,
    stats: dict,
) -> None:

    print(f"\n{title}")
    print("-" * 45)

    print(f"Min:       {stats['min']}")
    print(f"Mean:      {stats['mean']}")
    print(f"Median:    {stats['median']}")
    print(f"P90:       {stats['p90']}")
    print(f"P95:       {stats['p95']}")
    print(f"P99:       {stats['p99']}")
    print(f"Max:       {stats['max']}")


def main():

    parser = argparse.ArgumentParser(
        description="Analyze token lengths for fine-tuning dataset."
    )

    parser.add_argument(
        "--train",
        required=True,
        help="Path to training JSONL file.",
    )

    parser.add_argument(
        "--model",
        required=True,
        help="Hugging Face model/tokenizer ID.",
    )

    parser.add_argument(
        "--output",
        help="Optional path for JSON analysis output.",
    )

    args = parser.parse_args()

    train_path = Path(args.train)

    print("=" * 60)
    print("TOKEN LENGTH ANALYSIS")
    print("=" * 60)

    print(f"\nDataset: {train_path}")
    print(f"Tokenizer: {args.model}")

    dataset = load_jsonl(train_path)

    print(f"Examples loaded: {len(dataset)}")

    print("\nLoading tokenizer...")

    tokenizer = AutoTokenizer.from_pretrained(
        args.model,
        trust_remote_code=True,
    )

    print("Tokenizer loaded.")

    result = analyze(
        dataset,
        tokenizer,
    )

    print_stats(
        "SYSTEM PROMPT TOKENS",
        result["system"],
    )

    print_stats(
        "USER / INPUT TOKENS",
        result["user"],
    )

    print_stats(
        "ASSISTANT / OUTPUT TOKENS",
        result["assistant"],
    )

    print_stats(
        "TOTAL CONVERSATION TOKENS",
        result["total"],
    )

    print("\nSEQUENCE LENGTH THRESHOLDS")
    print("-" * 45)

    for threshold, values in result["thresholds"].items():
        print(
            f"> {threshold:<5} "
            f"{values['count']:>4} examples "
            f"({values['percentage']}%)"
        )

    print("\nTOP 10 LONGEST EXAMPLES")
    print("-" * 45)

    for example in result["longest_examples"]:
        print(
            f"training[{example['training_index']}] "
            f"{example['total_tokens']} tokens "
            f"(input={example['user_tokens']}, "
            f"output={example['assistant_tokens']})"
        )

    if args.output:

        output_path = Path(args.output)

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with output_path.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                result,
                file,
                indent=2,
            )

        print(
            f"\nAnalysis saved to: {output_path}"
        )


if __name__ == "__main__":
    main()