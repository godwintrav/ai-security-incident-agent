import modal
import torch
from pathlib import Path
from modal import Volume, Image
# Setup - define our infrastructure with code!

app = modal.App("security-incident-analyzer")


# This collects the secret from Modal.
# Depending on your Modal configuration, you may need to replace "huggingface-secret" with "hf-secret"
secrets = [modal.Secret.from_name("huggingface-secret")]

GPU = "T4"
BASE_MODEL = "Qwen/Qwen3.5-9B"
PROJECT_NAME = "ai-security-incident-analyzer"
HF_USER = "godwintrav"  # your HF name here! Or use mine if you just want to reproduce my results.
RUN_NAME = "2026-10-12_15.22.45"
PROJECT_RUN_NAME = f"{PROJECT_NAME}-{RUN_NAME}"
REVISION = "a143fe472fc2dda35bfdbc20159e969d6cfba4ba"
FINETUNED_MODEL = f"{HF_USER}/{PROJECT_RUN_NAME}"
CACHE_DIR = "/cache"

# Change this to 1 if you want Modal to be always running, otherwise it will go cold after 2 mins
MIN_CONTAINERS = 0

image = Image.debian_slim().pip_install(
    "huggingface", "torch", "transformers", "bitsandbytes", "accelerate", "peft"
).env({"HF_HUB_CACHE": CACHE_DIR}).add_local_file(
    "app/prompts/incident_analysis_system_v2.txt",
    remote_path="/app/prompts/incident_analysis_v2.txt",
)

hf_cache_volume = Volume.from_name("hf-hub-cache", create_if_missing=True)


@app.cls(
    image=image,
    secrets=secrets,
    gpu=GPU,
    timeout=1800,
    min_containers=MIN_CONTAINERS,
    volumes={CACHE_DIR: hf_cache_volume},
    
)
class SecurityIncidentAnalyzer:
    @modal.enter()
    def setup(self):
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
        from peft import PeftModel

        self.system_prompt = Path(
            "/app/prompts/incident_analysis_v2.txt"
        ).read_text(encoding="utf-8")

        # Quant Config
        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
        )

        tokenizer = AutoTokenizer.from_pretrained(
            BASE_MODEL,
            trust_remote_code=True,
        )

        # Load model and tokenizer
        self.tokenizer = tokenizer
        self.tokenizer.pad_token = self.tokenizer.eos_token
        self.tokenizer.padding_side = "right"
        self.base_model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            quantization_config=quant_config,
            device_map="auto",
            torch_dtype=torch.float16,
            trust_remote_code=True,
        )
        self.fine_tuned_model = PeftModel.from_pretrained(
            self.base_model, FINETUNED_MODEL, revision=REVISION
        )

        self.fine_tuned_model.eval()

    @modal.method()
    def analyze(self, incident: dict):
        import json

        messages = [
            {
                "role": "system",
                "content": self.system_prompt,
            },
            {
                "role": "user",
                "content": json.dumps(incident),
            },
        ]

        device = self.fine_tuned_model.get_input_embeddings().weight.device

        inputs = self.tokenizer.apply_chat_template(
            messages,
            tokenize=True,
            add_generation_prompt=True,
            enable_thinking=False,
            return_tensors="pt",
            return_dict=True,
        ).to(device)

        with torch.inference_mode():
            output = self.fine_tuned_model.generate(
                **inputs,
                max_new_tokens=8192,
                do_sample=False,
                pad_token_id=self.tokenizer.pad_token_id,
            )

        # Remove the input prompt tokens
        generated = output[0][inputs["input_ids"].shape[-1]:]

        response = self.tokenizer.decode(
            generated,
            skip_special_tokens=True,
        )

        if len(generated) >= 8192:
            print(
                "Specialist reached max_new_tokens=%s",
                max_new_tokens,
            )

        print("Generated tokens:", len(generated))
        print("Response length:", len(response))
        print("Response ending:", repr(response[-500:]))

        try:
            return json.loads(response)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Model generated invalid JSON: {exc}. "
                f"Generated tokens: {len(generated)}. "
                f"Response ending: {response[-300:]!r}"
            ) from exc
