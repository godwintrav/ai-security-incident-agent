import argparse
import json
import time

from pathlib import Path

import torch

from pydantic import ValidationError

from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
)

from scripts.validate_incident_dataset import IncidentAnalysis

from peft import PeftModel
import os
from huggingface_hub import login

# ============================================================
# Arguments
# ============================================================


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Generate predictions for the security incident "
            "regression dataset."
        )
    )

    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Hugging Face model name or local model path.",
    )

    parser.add_argument(
        "--dataset",
        type=str,
        required=True,
        help="Path to regression JSONL dataset.",
    )

    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Directory where predictions and config will be saved.",
    )

    parser.add_argument(
        "--max-new-tokens",
        type=int,
        default=1024,
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional number of cases to run. Useful for testing.",
    )

    parser.add_argument(
        "--system-prompt",
        type=str,
        required=True,
        help="Path to the canonical system prompt.",
    )

    parser.add_argument(
        "--precision",
        type=str,
        choices=["native", "nf4"],
        default="native",
        help=(
            "Model loading mode. "
            "'native' loads the model normally using torch_dtype='auto'. "
            "'nf4' loads the model using BitsAndBytes 4-bit NF4."
        ),
    )

    parser.add_argument(
        "--adapter",
        type=str,
        default=None,
        help=(
            "Optional Hugging Face repo ID or local path containing "
            "a PEFT/LoRA adapter."
        ),
    )

    return parser.parse_args()


# ============================================================
# Device
# ============================================================


def get_device() -> str:
    if torch.cuda.is_available():
        return "cuda"

    if torch.backends.mps.is_available():
        return "mps"

    return "cpu"


# ============================================================
# Dataset
# ============================================================


def load_jsonl(path: str) -> list[dict]:
    records = []

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if line:
                records.append(json.loads(line))

    return records


# ============================================================
# Model loading
# ============================================================


def load_model(
    model_name: str,
    precision: str,
    adapter: str = None
):
    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        trust_remote_code=True,
    )

    # --------------------------------------------------------
    # Native / unquantized model
    # --------------------------------------------------------

    if precision == "native":
        device = get_device()

        print(f"Loading model: {model_name}")
        print("Precision mode: native")
        print(f"Device: {device}")

        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype="auto",
            trust_remote_code=True,
        )

        model.to(device)
        model.eval()

        dtype = next(model.parameters()).dtype

        print(f"Model dtype: {dtype}")
        print("Quantized: False")

        quantization_metadata = None

        return (
            model,
            tokenizer,
            device,
            dtype,
            quantization_metadata,
        )

    # --------------------------------------------------------
    # BitsAndBytes NF4
    # --------------------------------------------------------

    if precision == "nf4":
        if not torch.cuda.is_available():
            raise RuntimeError(
                "NF4 mode requires a CUDA-capable NVIDIA GPU. "
                "Do not run this mode using Apple MPS. "
                "Use Google Colab or another CUDA environment."
            )

        device = "cuda"

        print(f"Loading model: {model_name}")
        print("Precision mode: nf4")
        print("Device: cuda")
        print("Quantization: BitsAndBytes 4-bit NF4")
        print("Double quantization: enabled")
        print("Compute dtype: bfloat16")

        if not torch.cuda.is_bf16_supported():
            raise RuntimeError(
                "The selected CUDA GPU does not report BF16 support. "
                "For this experiment, use a BF16-capable GPU so the "
                "NF4 configuration remains identical between baseline "
                "evaluation and QLoRA training."
            )

        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.bfloat16,
        )

        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            quantization_config=quantization_config,
            device_map="auto",
            torch_dtype=torch.bfloat16,
            trust_remote_code=True,
        )

        if adapter:
            print(f"Loading PEFT adapter: {adapter}")

            model = PeftModel.from_pretrained(
                model,
                adapter,
                is_trainable=False,
            )

        model.eval()

        dtype = next(model.parameters()).dtype

        quantization_metadata = {
            "library": "bitsandbytes",
            "load_in_4bit": True,
            "quant_type": "nf4",
            "double_quant": True,
            "compute_dtype": "bfloat16",
        }

        print(f"Reported model dtype: {dtype}")
        print("Quantized: True")

        return (
            model,
            tokenizer,
            device,
            dtype,
            quantization_metadata,
        )

    raise ValueError(
        f"Unsupported precision mode: {precision}"
    )


# ============================================================
# System prompt
# ============================================================


def load_system_prompt(path: str) -> str:
    return Path(path).read_text(
        encoding="utf-8"
    ).strip()


# ============================================================
# Generation
# ============================================================


def generate_prediction(
    model,
    tokenizer,
    device: str,
    system_prompt: str,
    incident_input: dict,
    max_new_tokens: int,
    model_name: str,
):
    messages = [
        {
            "role": "system",
            "content": system_prompt,
        },
        {
            "role": "user",
            "content": json.dumps(
                incident_input,
                ensure_ascii=False,
            ),
        },
    ]

    chat_template_kwargs = {
        "tokenize": True,
        "add_generation_prompt": True,
        "return_tensors": "pt",
        "return_dict": True,
    }

    # Disable Qwen thinking/reasoning so that the generated
    # response contains only the expected structured output.
    if "qwen" in model_name.lower():
        chat_template_kwargs["enable_thinking"] = False

    encoded = tokenizer.apply_chat_template(
        messages,
        **chat_template_kwargs,
    )

    encoded = {
        key: value.to(device)
        for key, value in encoded.items()
    }

    input_length = encoded["input_ids"].shape[-1]

    start_time = time.perf_counter()

    with torch.inference_mode():
        output = model.generate(
            **encoded,
            max_new_tokens=max_new_tokens,
            do_sample=False,
        )

    elapsed = time.perf_counter() - start_time

    generated_tokens = output[0][input_length:]

    raw_response = tokenizer.decode(
        generated_tokens,
        skip_special_tokens=True,
    ).strip()

    return {
        "raw_response": raw_response,
        "input_tokens": input_length,
        "generated_tokens": len(generated_tokens),
        "latency_seconds": round(elapsed, 3),
    }


# ============================================================
# Prediction parsing
# ============================================================


def parse_prediction(raw_response: str):
    try:
        prediction = IncidentAnalysis.model_validate_json(
            raw_response
        )

        return True, prediction.model_dump(), None

    except ValidationError as error:
        return False, None, str(error)

    except Exception as error:
        return False, None, str(error)


# ============================================================
# Resume support
# ============================================================


def load_completed_cases(
    predictions_path: Path,
) -> set[str]:
    """
    Allows an interrupted evaluation to resume.
    """

    completed = set()

    if not predictions_path.exists():
        return completed

    with open(
        predictions_path,
        "r",
        encoding="utf-8",
    ) as file:

        for line in file:
            line = line.strip()

            if not line:
                continue

            record = json.loads(line)

            completed.add(record["case_id"])

    return completed


# ============================================================
# Prediction output
# ============================================================


def append_prediction(
    predictions_path: Path,
    record: dict,
):
    with open(
        predictions_path,
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


def save_config(
    output_directory: Path,
    config: dict,
):
    path = output_directory / "config.json"

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            config,
            file,
            indent=2,
            ensure_ascii=False,
        )


# ============================================================
# Main
# ============================================================


def main():
    args = parse_args()

    output_directory = Path(args.output)

    #HF
    hf_token = os.environ['HF_TOKEN']
    login(hf_token, add_to_git_credential=True)

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    predictions_path = (
        output_directory / "predictions.jsonl"
    )

    regression_cases = load_jsonl(
        args.dataset
    )

    if args.limit is not None:
        regression_cases = regression_cases[
            : args.limit
        ]

    system_prompt = load_system_prompt(
        args.system_prompt
    )

    (
        model,
        tokenizer,
        device,
        dtype,
        quantization_metadata,
    ) = load_model(
        model_name=args.model,
        precision=args.precision,
        adapter=args.adapter
    )

    completed_cases = load_completed_cases(
        predictions_path
    )

    config = {
        "model": args.model,
        "dataset": args.dataset,
        "examples": len(regression_cases),
        "device": device,
        "dtype": str(dtype),
        "precision": args.precision,
        "max_new_tokens": args.max_new_tokens,
        "do_sample": False,
        "quantized": args.precision == "nf4",
        "quantization": quantization_metadata,
        "lora": args.adapter is not None,
        "adapter": args.adapter,
    }

    save_config(
        output_directory,
        config,
    )

    print()
    print(f"Regression cases: {len(regression_cases)}")
    print(f"Already completed: {len(completed_cases)}")
    print()

    for index, case in enumerate(
        regression_cases,
        start=1,
    ):
        case_id = case["case_id"]

        if case_id in completed_cases:
            print(
                f"[{index}/{len(regression_cases)}] "
                f"{case_id} - skipped"
            )

            continue

        print(
            f"[{index}/{len(regression_cases)}] "
            f"{case_id}"
        )

        try:
            generation = generate_prediction(
                model=model,
                tokenizer=tokenizer,
                device=device,
                system_prompt=system_prompt,
                incident_input=case["input"],
                max_new_tokens=args.max_new_tokens,
                model_name=args.model,
            )

            schema_valid, prediction, parse_error = (
                parse_prediction(
                    generation["raw_response"]
                )
            )

            record = {
                "case_id": case_id,
                "model": args.model,
                "precision": args.precision,
                "schema_valid": schema_valid,
                "raw_response": generation[
                    "raw_response"
                ],
                "prediction": prediction,
                "parse_error": parse_error,
                "input_tokens": generation[
                    "input_tokens"
                ],
                "generated_tokens": generation[
                    "generated_tokens"
                ],
                "latency_seconds": generation[
                    "latency_seconds"
                ],
            }

            append_prediction(
                predictions_path,
                record,
            )

            print(
                f"    schema_valid={schema_valid} "
                f"tokens={generation['generated_tokens']} "
                f"time={generation['latency_seconds']}s"
            )

        except Exception as error:
            print(
                f"    ERROR: {error}"
            )

            record = {
                "case_id": case_id,
                "model": args.model,
                "precision": args.precision,
                "schema_valid": False,
                "raw_response": None,
                "prediction": None,
                "parse_error": None,
                "generation_error": str(error),
            }

            append_prediction(
                predictions_path,
                record,
            )

    print()
    print("Prediction generation complete.")
    print(
        f"Results: {predictions_path}"
    )


if __name__ == "__main__":
    main()