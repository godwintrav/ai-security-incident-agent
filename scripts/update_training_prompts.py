import json
from pathlib import Path


PROMPT_PATH = Path("app/prompts/incident_analysis_system.txt")
TRAIN_PATH = Path("data/evaluation/fine_tuning/train.jsonl")


def load_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8").strip()


def update_training_prompts():
    system_prompt = load_prompt()

    examples = []

    with TRAIN_PATH.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            example = json.loads(line)

            # Find and replace the system message
            for message in example["messages"]:
                if message["role"] == "system":
                    message["content"] = system_prompt
                    break
            else:
                raise ValueError("Training example has no system message.")

            examples.append(example)

    with TRAIN_PATH.open("w", encoding="utf-8") as file:
        for example in examples:
            file.write(
                json.dumps(example, ensure_ascii=False) + "\n"
            )

    print(f"Updated {len(examples)} training examples.")


if __name__ == "__main__":
    update_training_prompts()