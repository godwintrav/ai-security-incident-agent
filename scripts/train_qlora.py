from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import torch
from datasets import load_dataset
from peft import (
    LoraConfig,
    prepare_model_for_kbit_training,
)
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    set_seed,
)
from trl import SFTConfig, SFTTrainer
import os
import wandb
from huggingface_hub import login
from datetime import datetime


# ============================================================
# Defaults
# ============================================================

DEFAULT_MODEL = "Qwen/Qwen3.5-9B"

DEFAULT_TRAIN_PATH = (
    "data/evaluation/fine_tuning/train.jsonl"
)

DEFAULT_VALIDATION_PATH = (
    "data/evaluation/fine_tuning/validation.jsonl"
)

DEFAULT_OUTPUT_DIR = (
    "data/fine_tuning/qwen3.5-9b/qlora-run-001"
)

DEFAULT_SEED = 42

DEFAULT_MAX_LENGTH = 1024

DEFAULT_LORA_R = 16
DEFAULT_LORA_ALPHA = 32
DEFAULT_LORA_DROPOUT = 0.05

DEFAULT_LEARNING_RATE = 2e-4
DEFAULT_EPOCHS = 3

DEFAULT_BATCH_SIZE = 2
DEFAULT_GRADIENT_ACCUMULATION = 8

DEFAULT_WARMUP_RATIO = 0.05


LORA_TARGET_MODULES = [
    "q_proj",
    "k_proj",
    "v_proj",
    "o_proj",
]


# ============================================================
# CLI
# ============================================================


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fine-tune Qwen3.5 using 4-bit NF4 QLoRA."
        )
    )

    parser.add_argument(
        "--train",
        type=str,
        default=DEFAULT_TRAIN_PATH,
        help="Training JSONL file.",
    )

    parser.add_argument(
        "--validation",
        type=str,
        default=DEFAULT_VALIDATION_PATH,
        help="Validation JSONL file.",
    )

    parser.add_argument(
        "--model",
        type=str,
        default=DEFAULT_MODEL,
        help="Hugging Face model ID.",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default=DEFAULT_OUTPUT_DIR,
        help="Output directory.",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
    )

    parser.add_argument(
        "--max-length",
        type=int,
        default=DEFAULT_MAX_LENGTH,
    )

    parser.add_argument(
        "--epochs",
        type=float,
        default=DEFAULT_EPOCHS,
    )

    parser.add_argument(
        "--learning-rate",
        type=float,
        default=DEFAULT_LEARNING_RATE,
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
    )

    parser.add_argument(
        "--gradient-accumulation-steps",
        type=int,
        default=DEFAULT_GRADIENT_ACCUMULATION,
    )

    parser.add_argument(
        "--lora-r",
        type=int,
        default=DEFAULT_LORA_R,
    )

    parser.add_argument(
        "--lora-alpha",
        type=int,
        default=DEFAULT_LORA_ALPHA,
    )

    parser.add_argument(
        "--lora-dropout",
        type=float,
        default=DEFAULT_LORA_DROPOUT,
    )

    parser.add_argument(
        "--warmup-ratio",
        type=float,
        default=DEFAULT_WARMUP_RATIO,
    )

    parser.add_argument(
        "--resume-from-checkpoint",
        type=str,
        default=None,
    )

    return parser.parse_args()

# ============================================================
# Memory
# ============================================================

def print_gpu_memory(label: str):
    allocated = torch.cuda.memory_allocated() / 1024**3
    reserved = torch.cuda.memory_reserved() / 1024**3

    print(f"\n{label}")
    print(f"Allocated: {allocated:.2f} GiB")
    print(f"Reserved:  {reserved:.2f} GiB")

# ============================================================
# Dataset
# ============================================================


def load_datasets(
    train_path: str,
    validation_path: str,
):
    train_path = Path(train_path)
    validation_path = Path(validation_path)

    if not train_path.exists():
        raise FileNotFoundError(
            f"Training dataset not found: {train_path}"
        )

    if not validation_path.exists():
        raise FileNotFoundError(
            f"Validation dataset not found: {validation_path}"
        )

    train_dataset = load_dataset(
        "json",
        data_files=str(train_path),
        split="train",
    )

    validation_dataset = load_dataset(
        "json",
        data_files=str(validation_path),
        split="train",
    )

    return train_dataset, validation_dataset


# ============================================================
# Tokenizer
# ============================================================


def load_tokenizer(model_id: str):
    tokenizer = AutoTokenizer.from_pretrained(
        model_id,
        use_fast=True,
    )

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    tokenizer.padding_side = "right"

    return tokenizer


# ============================================================
# Quantization
# ============================================================


def build_quantization_config():
    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )


# ============================================================
# Model
# ============================================================


def load_model(
    model_id: str,
    quantization_config: BitsAndBytesConfig,
):
    if not torch.cuda.is_available():
        raise RuntimeError(
            "CUDA is required for bitsandbytes NF4 "
            "QLoRA training."
        )

    if not torch.cuda.is_bf16_supported():
        raise RuntimeError(
            "The selected CUDA GPU does not support "
            "bfloat16. Use a compatible GPU or adjust "
            "the training precision."
        )

    print_gpu_memory("1. BEFORE MODEL LOAD")

    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=quantization_config,
        device_map="auto",
        torch_dtype=torch.bfloat16,
    )

    print(f"Memory footprint: {model.get_memory_footprint() / 1e6:.1f} MB")
    print_gpu_memory("2. AFTER MODEL LOAD")

    # KV caching is useful for inference but not training.
    model.config.use_cache = False

    return model


# ============================================================
# Verify LoRA targets
# ============================================================


def verify_lora_targets(
    model,
    targets: list[str],
) -> None:
    counts = {
        target: 0
        for target in targets
    }

    for name, _module in model.named_modules():
        leaf_name = name.rsplit(".", 1)[-1]

        if leaf_name in counts:
            counts[leaf_name] += 1

    print()
    print("LORA TARGET MODULES")
    print("-" * 60)

    missing = []

    for target in targets:
        count = counts[target]

        print(
            f"{target:<20} {count:>10} modules"
        )

        if count == 0:
            missing.append(target)

    if missing:
        raise RuntimeError(
            "Requested LoRA modules were not found "
            f"in the model: {missing}"
        )


# ============================================================
# LoRA
# ============================================================


def build_lora_config(
    args: argparse.Namespace,
) -> LoraConfig:
    return LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        target_modules=LORA_TARGET_MODULES,
        bias="none",
        task_type="CAUSAL_LM",
    )


# ============================================================
# SFT configuration
# ============================================================


def build_training_config(
    args: argparse.Namespace,
    run_name: str,
    hub_model_name: str,
    log_to_wandb: bool = False
) -> SFTConfig:
    return SFTConfig(
        output_dir=args.output_dir,

        # --------------------------------------------
        # Sequence
        # --------------------------------------------

        max_length=args.max_length,

        # --------------------------------------------
        # Loss
        # --------------------------------------------

        assistant_only_loss=True,

        # --------------------------------------------
        # Training
        # --------------------------------------------

        num_train_epochs=args.epochs,

        per_device_train_batch_size=args.batch_size,

        per_device_eval_batch_size=args.batch_size,

        gradient_accumulation_steps=(
            args.gradient_accumulation_steps
        ),

        learning_rate=args.learning_rate,

        # --------------------------------------------
        # Optimizer
        # --------------------------------------------

        optim="paged_adamw_8bit",

        weight_decay=0.0,

        max_grad_norm=1.0,

        # --------------------------------------------
        # LR scheduler
        # --------------------------------------------

        lr_scheduler_type="cosine",

        warmup_ratio=args.warmup_ratio,

        # --------------------------------------------
        # Precision
        # --------------------------------------------

        bf16=True,
        fp16=False,

        # --------------------------------------------
        # Memory
        # --------------------------------------------

        gradient_checkpointing=True,

        gradient_checkpointing_kwargs={
            "use_reentrant": False,
        },

        # --------------------------------------------
        # Evaluation
        # --------------------------------------------

        eval_strategy="epoch",

        # --------------------------------------------
        # Checkpoints
        # --------------------------------------------

        save_strategy="epoch",

        save_total_limit=3,

        hub_strategy="every_save",

        # --------------------------------------------
        # Logging
        # --------------------------------------------

        logging_strategy="steps",

        logging_steps=5,

        logging_first_step=True,

        report_to="wandb" if log_to_wandb else None,

        # --------------------------------------------
        # Dataset
        # --------------------------------------------

        packing=False,

        # --------------------------------------------
        # Reproducibility
        # --------------------------------------------

        seed=args.seed,

        data_seed=args.seed,

        # --------------------------------------------
        # Push to Hub
        # --------------------------------------------
        run_name=run_name,

        push_to_hub=True,

        hub_model_id=hub_model_name,

        hub_private_repo=True,
    )


# ============================================================
# Training plan
# ============================================================


def print_training_plan(
    train_size: int,
    validation_size: int,
    args: argparse.Namespace,
) -> None:
    effective_batch_size = (
        args.batch_size
        * args.gradient_accumulation_steps
    )

    optimizer_steps_per_epoch = math.ceil(
        train_size / effective_batch_size
    )

    total_optimizer_steps = math.ceil(
        optimizer_steps_per_epoch
        * args.epochs
    )

    print()
    print("=" * 60)
    print("TRAINING PLAN")
    print("=" * 60)

    print(f"Model:                    {args.model}")
    print(f"Training examples:        {train_size}")
    print(f"Validation examples:      {validation_size}")

    print()
    print("QUANTIZATION")
    print("-" * 60)
    print("Quantization:              4-bit NF4")
    print("Double quantization:       yes")
    print("Compute dtype:             bfloat16")

    print()
    print("LORA")
    print("-" * 60)
    print(f"Rank:                      {args.lora_r}")
    print(f"Alpha:                     {args.lora_alpha}")
    print(f"Dropout:                   {args.lora_dropout}")
    print(
        "Targets:                   "
        + ", ".join(LORA_TARGET_MODULES)
    )

    print()
    print("TRAINING")
    print("-" * 60)
    print(f"Max length:                {args.max_length}")
    print(f"Epochs:                    {args.epochs}")
    print(f"Learning rate:             {args.learning_rate}")
    print(f"Physical batch size:       {args.batch_size}")
    print(
        f"Gradient accumulation:     "
        f"{args.gradient_accumulation_steps}"
    )
    print(f"Effective batch size:      {effective_batch_size}")
    print(
        f"Optimizer steps / epoch:   "
        f"~{optimizer_steps_per_epoch}"
    )
    print(
        f"Total optimizer steps:     "
        f"~{total_optimizer_steps}"
    )
    print("Assistant-only loss:       yes")
    print()


# ============================================================
# Save experiment configuration
# ============================================================


def save_experiment_config(
    args: argparse.Namespace,
    train_size: int,
    validation_size: int,
) -> None:
    output_dir = Path(args.output_dir)

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    config = {
        "model": args.model,
        "dataset": {
            "train": args.train,
            "validation": args.validation,
            "train_examples": train_size,
            "validation_examples": validation_size,
        },
        "quantization": {
            "load_in_4bit": True,
            "quant_type": "nf4",
            "double_quant": True,
            "compute_dtype": "bfloat16",
        },
        "lora": {
            "r": args.lora_r,
            "alpha": args.lora_alpha,
            "dropout": args.lora_dropout,
            "target_modules": LORA_TARGET_MODULES,
            "bias": "none",
            "task_type": "CAUSAL_LM",
        },
        "training": {
            "max_length": args.max_length,
            "epochs": args.epochs,
            "learning_rate": args.learning_rate,
            "batch_size": args.batch_size,
            "gradient_accumulation_steps": (
                args.gradient_accumulation_steps
            ),
            "effective_batch_size": (
                args.batch_size
                * args.gradient_accumulation_steps
            ),
            "optimizer": "paged_adamw_8bit",
            "scheduler": "cosine",
            "warmup_ratio": args.warmup_ratio,
            "assistant_only_loss": True,
            "gradient_checkpointing": True,
            "bf16": True,
            "seed": args.seed,
        },
    }

    config_path = (
        output_dir
        / "experiment_config.json"
    )

    with config_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            config,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print(
        f"Experiment config: {config_path}"
    )


# ============================================================
# Main
# ============================================================


def main() -> None:
    args = parse_args()

    set_seed(args.seed)

    print("=" * 60)
    print("QLORA SECURITY INCIDENT FINE-TUNING")
    print("=" * 60)

    #HF
    HF_USER = "godwintrav"
    hf_token = os.environ['HF_TOKEN']
    login(hf_token, add_to_git_credential=True)

    RUN_NAME =  f"{datetime.now():%Y-%m-%d_%H.%M.%S}"
    PROJECT_NAME = "ai-security-incident-analyzer"
    PROJECT_RUN_NAME = f"{PROJECT_NAME}-{RUN_NAME}"
    HUB_MODEL_NAME = f"{HF_USER}/{PROJECT_RUN_NAME}"

    
    LOG_TO_WANDB = True
    wandb.login()

    # Configure Weights & Biases to record against our project
    os.environ["WANDB_PROJECT"] = PROJECT_NAME
    os.environ["WANDB_LOG_MODEL"] = "false"
    os.environ["WANDB_WATCH"] = "false"

    # --------------------------------------------------------
    # Dataset
    # --------------------------------------------------------

    print()
    print("Loading datasets...")

    (
        train_dataset,
        validation_dataset,
    ) = load_datasets(
        train_path=args.train,
        validation_path=args.validation,
    )

    print(
        f"Training examples:   "
        f"{len(train_dataset)}"
    )

    print(
        f"Validation examples: "
        f"{len(validation_dataset)}"
    )

    print_training_plan(
        train_size=len(train_dataset),
        validation_size=len(validation_dataset),
        args=args,
    )

    save_experiment_config(
        args=args,
        train_size=len(train_dataset),
        validation_size=len(validation_dataset),
    )

    if LOG_TO_WANDB:
        wandb.init(project=PROJECT_NAME, name=RUN_NAME)

    # --------------------------------------------------------
    # Tokenizer
    # --------------------------------------------------------

    print()
    print("Loading tokenizer...")

    tokenizer = load_tokenizer(
        args.model
    )

    print("Tokenizer loaded.")

    # --------------------------------------------------------
    # Quantized base model
    # --------------------------------------------------------

    print()
    print("Loading 4-bit NF4 model...")

    quantization_config = (
        build_quantization_config()
    )

    model = load_model(
        model_id=args.model,
        quantization_config=(
            quantization_config
        ),
    )

    print("Model loaded.")

    # --------------------------------------------------------
    # Verify architecture
    # --------------------------------------------------------

    verify_lora_targets(
        model,
        LORA_TARGET_MODULES,
    )

    # --------------------------------------------------------
    # LoRA
    # --------------------------------------------------------

    lora_config = build_lora_config(
        args
    )

    # --------------------------------------------------------
    # SFT config
    # --------------------------------------------------------

    training_config = (
        build_training_config(args, run_name=RUN_NAME, hub_model_name=HUB_MODEL_NAME, log_to_wandb=LOG_TO_WANDB)
    )

    # --------------------------------------------------------
    # Trainer
    # --------------------------------------------------------

    print()
    print("Creating SFTTrainer...")

    trainer = SFTTrainer(
        model=model,
        args=training_config,
        train_dataset=train_dataset,
        eval_dataset=validation_dataset,
        processing_class=tokenizer,
        peft_config=lora_config,
    )

    print("SFTTrainer created.")

    # --------------------------------------------------------
    # Trainable parameter check
    # --------------------------------------------------------

    print()
    print("TRAINABLE PARAMETERS")
    print("-" * 60)

    trainer.model.print_trainable_parameters()

    # --------------------------------------------------------
    # Training
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("STARTING TRAINING")
    print("=" * 60)
    print()

    train_result = trainer.train(
        resume_from_checkpoint=(
            args.resume_from_checkpoint
        )
    )

    # --------------------------------------------------------
    # Final validation
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("FINAL VALIDATION")
    print("=" * 60)

    eval_metrics = trainer.evaluate()

    for key, value in sorted(
        eval_metrics.items()
    ):
        print(
            f"{key:<30} {value}"
        )

    # --------------------------------------------------------
    # Save adapter
    # --------------------------------------------------------

    final_adapter_dir = (
        Path(args.output_dir)
        / "final_adapter"
    )

    final_adapter_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    trainer.save_model(
        str(final_adapter_dir)
    )

    tokenizer.save_pretrained(
        str(final_adapter_dir)
    )

    # --------------------------------------------------------
    # Save metrics/state
    # --------------------------------------------------------

    trainer.save_metrics(
        "train",
        train_result.metrics,
    )

    trainer.save_metrics(
        "eval",
        eval_metrics,
    )

    trainer.save_state()
    trainer.model.push_to_hub(PROJECT_RUN_NAME, private=True)

    if LOG_TO_WANDB:
        wandb.finish()

    print()
    print("=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)

    print(
        f"Final adapter: {final_adapter_dir}"
    )

    print()
    print(
        "Next: load this adapter over the NF4 base "
        "and run the 104-case regression evaluation."
    )


if __name__ == "__main__":
    main()