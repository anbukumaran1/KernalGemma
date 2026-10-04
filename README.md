# KernelGemma Synthetic Dataset Engine

High-performance, verifier-safe synthetic eBPF C training dataset generator for fine-tuning **Gemma 4 E4B** with Unsloth 4-bit QLoRA.

The engine generates strictly verified eBPF C code (XDP and kprobe only) paired with natural-language security intents, guaranteed to pass the Linux 5.15+ BPF in-kernel verifier.

---

## 1. Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- (Optional) `clang` with BPF backend target for optional `--clang-check` compilation validation.

### Installation
```bash
pip install -r requirements.txt
```

### Environment Configuration
Copy `.env.example` to `.env` and set your Google Gemini API key:
```bash
cp .env.example .env
```
Edit `.env`:
```env
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```

---

## 2. Usage

### Offline Dry-Run (Zero API Cost)
Generates the complete 300-row verifier-safe dataset locally using parameterised deterministic templates:
```bash
python dataset_engine.py --dry-run --rows 300
```

### Live Generation via Gemini API
Calls the Gemini REST API with automated validation, repair loops, rate-limit backoff, and atomic writes:
```bash
python dataset_engine.py --rows 300 --concurrency 8
```

### Resuming an Interrupted Run
If generation is stopped (e.g. `Ctrl+C`), resume seamlessly from the sidecar manifest:
```bash
python dataset_engine.py --resume
```

---

## 3. CLI Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--rows` | `int` | `300` | Total number of accepted dataset rows |
| `--output` | `str` | `kernelgemma_dataset.jsonl` | Output JSONL dataset file path |
| `--model` | `str` | `gemini-2.5-flash` | Gemini model ID for live generation |
| `--concurrency` | `int` | `8` | Maximum concurrent async worker tasks |
| `--seed` | `int` | `42` | PRNG seed for deterministic job specs & shuffle |
| `--resume` | `flag` | `False` | Resume using completed rows from `.meta.jsonl` |
| `--clang-check` | `flag` | `False` | Compile samples with `clang -target bpf -O2 -g -c` |
| `--dry-run` | `flag` | `False` | Offline generation using templates (zero API calls) |

---

## 4. Output Format

The output file (`kernelgemma_dataset.jsonl`) contains exactly one JSON object per line with UTF-8 encoding, `\n` line endings, and no blank lines:

```json
{"messages": [{"role": "system", "content": "You are KernelGemma, an expert Linux kernel security engineer. Translate the user's natural-language security intent into one complete, verifier-safe eBPF C program (XDP or kprobe). Respond with raw C code only: no markdown, no explanations."}, {"role": "user", "content": "<security_intent>"}, {"role": "assistant", "content": "<c_code>\n"}]}
```

- **System Prompt**: Identical across every row.
- **User Content**: Natural-language security intent (8 to 60 words, no technical tokens or syntax leaks).
- **Assistant Content**: Raw, verifier-safe C code only (no markdown fences, ends with a single `\n`).
- **Sidecar Manifest**: Per-row provenance, hashes, tier, style, and parameters are stored in `<output>.meta.jsonl`.

---

## 5. Dataset Composition (300 Rows)

- **XDP (60% / 180 rows)**:
  - `X1`: Drop single source IPv4 (30)
  - `X2`: Drop source CIDR/subnet via mask (25)
  - `X3`: Drop TCP traffic to destination port (25)
  - `X4`: Drop UDP traffic to destination port (20)
  - `X5`: SYN-flood mitigation via LRU hash map (25)
  - `X6`: UDP reflection amplification mitigation (20)
  - `X7`: ICMP flood / ping drop (15)
  - `X8`: Ingress allowlist-only default drop (10)
  - `X9`: Drop IPv4 fragments (10)
- **kprobe (40% / 120 rows)**:
  - `K1`: Log `sys_execve` process executions (30)
  - `K2`: Alert on `sys_openat` of sensitive files (30)
  - `K3`: Filter execve/openat by UID or comm (20)
  - `K4`: Count syscalls per PID in BPF hash map (20)
  - `K5`: Detect execution from `/tmp`, `/var/tmp`, `/dev/shm` (20)

---

## 6. Fine-Tuning in Google Colab (Unsloth QLoRA)

```python
from unsloth import FastLanguageModel
from datasets import load_dataset
import torch

max_seq_length = 2048
dtype = None # Auto detection
load_in_4bit = True

# 1. Load Gemma 4-bit base model
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="google/gemma-2-9b-it", # or Gemma 4 variant
    max_seq_length=max_seq_length,
    dtype=dtype,
    load_in_4bit=load_in_4bit,
)

# 2. Add LoRA adapters
model = FastLanguageModel.get_peft_model(
    model,
    r=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_alpha=16,
    lora_dropout=0,
    bias="none",
    use_gradient_checkpointing="unsloth",
    random_state=42,
)

# 3. Load KernelGemma JSONL dataset
dataset = load_dataset("json", data_files="kernelgemma_dataset.jsonl")

def format_prompts(batch):
    convos = batch["messages"]
    texts = [tokenizer.apply_chat_template(convo, tokenize=False, add_generation_prompt=False) for convo in convos]
    return {"text": texts}

dataset = dataset.map(format_prompts, batched=True)
```

---

## 7. Testing & Linting

```bash
# Run unit tests on static validator
pytest -q

# Check PEP-8 compliance & max line length (79 chars)
ruff check .
ruff format --check .
```
