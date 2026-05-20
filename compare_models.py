import argparse
import json
import re
from pathlib import Path

from mlx_lm import generate, load


DEFAULT_PROMPTS = [
    "Bir sunucuya yapılan SSH brute force saldırısını tespit etmek için bir Snort kuralı yaz.",
    "SQL injection denemelerini web trafiğinde yakalamak için bir Snort kuralı üret.",
    "Path traversal saldırılarını algılayacak bir Snort kuralı oluştur.",
    "Malware C2 iletişimini tespit etmek için bir Snort kuralı yaz.",
    "Ağ taraması yapan istemcileri tespit edecek bir Snort kuralı üret.",
    "XSS denemelerini tespit edecek Snort kuralını yalnızca tek satır olarak ver.",
]


def load_prompts(path: str | None):
    if not path:
        return DEFAULT_PROMPTS

    prompt_path = Path(path)
    if not prompt_path.exists():
        raise SystemExit(f"Prompt file not found: {prompt_path}")

    if prompt_path.suffix == ".jsonl":
        prompts = []
        for line in prompt_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            prompts.append(payload["prompt"])
        return prompts

    return [line.strip() for line in prompt_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_prompt(model, tokenizer, prompt_text: str, max_tokens: int):
    messages = [{"role": "user", "content": prompt_text}]
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    output = generate(model, tokenizer, prompt=prompt, max_tokens=max_tokens, verbose=False)
    return output.strip().replace("\n", " ")


def score_output(text: str):
    lowered = text.lower()
    return {
        "starts_with_alert": int(text.strip().startswith("alert ")),
        "has_sid": int("sid:" in lowered),
        "has_rev": int("rev:" in lowered),
        "balanced_parentheses": int(text.count("(") == text.count(")")),
        "has_chat_artifact": int(bool(re.search(r"<\|.*?\|>", text))),
        "has_explanation": int(
            any(marker in lowered for marker in ("here is", "let me explain", "bu kural", "açıklama"))
        ),
    }


def total_score(metrics):
    return (
        metrics["starts_with_alert"]
        + metrics["has_sid"]
        + metrics["has_rev"]
        + metrics["balanced_parentheses"]
        - metrics["has_chat_artifact"]
        - metrics["has_explanation"]
    )


def print_result(label: str, output: str):
    metrics = score_output(output)
    score = total_score(metrics)
    print(f"{label} score={score} metrics={metrics}")
    print(output)
    print()
    return score


def main():
    parser = argparse.ArgumentParser(description="Compare base model and LoRA model on Snort prompts.")
    parser.add_argument("--base-model", default="mlx-community/Meta-Llama-3-8B-Instruct-4bit")
    parser.add_argument("--adapter-path", default="adapters")
    parser.add_argument("--prompts-file", default=None, help="txt or jsonl file with eval prompts")
    parser.add_argument("--max-tokens", type=int, default=120)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    prompts = load_prompts(args.prompts_file)
    if args.limit is not None:
        prompts = prompts[: args.limit]

    print("Loading base model...")
    base_model, base_tokenizer = load(args.base_model)

    print("Loading LoRA model...")
    lora_model, lora_tokenizer = load(args.base_model, adapter_path=args.adapter_path)

    base_total = 0
    lora_total = 0

    for index, prompt_text in enumerate(prompts, start=1):
        print(f"\n=== PROMPT {index} ===")
        print(prompt_text)
        print()

        base_output = run_prompt(base_model, base_tokenizer, prompt_text, args.max_tokens)
        lora_output = run_prompt(lora_model, lora_tokenizer, prompt_text, args.max_tokens)

        base_total += print_result("BASE", base_output)
        lora_total += print_result("LORA", lora_output)

    print("=== SUMMARY ===")
    print(f"prompt_count: {len(prompts)}")
    print(f"base_total_score: {base_total}")
    print(f"lora_total_score: {lora_total}")
    if lora_total > base_total:
        print("winner: LORA")
    elif base_total > lora_total:
        print("winner: BASE")
    else:
        print("winner: TIE")


if __name__ == "__main__":
    main()
