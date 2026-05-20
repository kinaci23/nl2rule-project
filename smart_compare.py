from mlx_lm import generate, load

DEFAULT_PROMPTS = [
    "Bir sunucuya yapılan SSH brute force saldırısını tespit etmek için bir Snort kuralı yaz.",
    "SQL injection denemelerini web trafiğinde yakalamak için bir Snort kuralı üret.",
    "Path traversal saldırılarını algılayacak bir Snort kuralı oluştur.",
    "Malware C2 iletişimini tespit etmek için bir Snort kuralı yaz.",
    "Ağ taraması yapan istemcileri tespit edecek bir Snort kuralı üret.",
    "XSS denemelerini tespit edecek Snort kuralını yalnızca tek satır olarak ver."
]

def extract_clean_response(raw_text: str) -> str:
    clean = raw_text.split("<|eot_id|>")[0]
    clean = clean.split("<|start_header_id|>")[0]
    return clean.strip()

def score_output(raw_text: str):
    clean_text = extract_clean_response(raw_text)
    lowered = clean_text.lower()
    
    metrics = {
        "starts_with_alert": 0,
        "has_sid_rev": 0,
        "balanced_parens": 0,
        "no_chatter": 0,
        "is_professional": 0
    }
    
    if clean_text.startswith("alert "):
        metrics["starts_with_alert"] = 2
        
    if "sid:" in lowered and "rev:" in lowered:
        metrics["has_sid_rev"] = 1
        
    if clean_text.count("(") == clean_text.count(")") and clean_text.count("(") > 0:
        metrics["balanced_parens"] = 1
        
    banned_words = ["here is", "açıklama", "bu kural", "let me explain", "snort"]
    has_chatter = any(word in lowered for word in banned_words)
    has_markdown = "```" in clean_text
    
    if not has_chatter and not has_markdown:
        metrics["no_chatter"] = 1
        
    pro_keywords = ["metadata:", "reference:", "classtype:", "flow:", "fast_pattern"]
    if any(keyword in lowered for keyword in pro_keywords):
        metrics["is_professional"] = 1
        
    total_score = sum(metrics.values())
    return total_score, metrics, clean_text

def run_prompt(model, tokenizer, prompt_text: str, max_tokens: int) -> str:
    messages = [{"role": "user", "content": prompt_text}]
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    output = generate(model, tokenizer, prompt=prompt, max_tokens=max_tokens, verbose=False)
    return output

def print_result(label: str, raw_output: str) -> int:
    score, metrics, clean_output = score_output(raw_output)
    print(f"[{label}] Toplam Puan: {score}/6 | Metrikler: {metrics}")
    print(f"-> ÇIKTI: {clean_output}\n")
    return score

def main():
    print("=== LİMİTSİZ KARŞILAŞTIRMA TESTİ BAŞLIYOR ===")
    
    print("1. Orijinal (Base) Model Yükleniyor...")
    base_model, base_tokenizer = load("mlx-community/Meta-Llama-3-8B-Instruct-4bit")
    
    print("2. Profesyonel (LoRA) Model Yükleniyor...")
    lora_model, lora_tokenizer = load("mlx-community/Meta-Llama-3-8B-Instruct-4bit", adapter_path="adapters_real")

    base_total = 0
    lora_total = 0

    for index, prompt_text in enumerate(DEFAULT_PROMPTS, start=1):
        print(f"\n--- SENARYO {index} ---")
        print(f"SORU: {prompt_text}\n")

        # max_tokens limitini 400'den 1500'e çıkardık!
        base_raw = run_prompt(base_model, base_tokenizer, prompt_text, 1500)
        lora_raw = run_prompt(lora_model, lora_tokenizer, prompt_text, 1500)

        base_total += print_result("HAM LLAMA-3 (BASE)", base_raw)
        lora_total += print_result("EĞİTİLMİŞ UZMAN (LORA)", lora_raw)

    print("====================================")
    print("             SONUÇLAR               ")
    print("====================================")
    print(f"HAM LLAMA-3 TOPLAM PUANI : {base_total} / 36")
    print(f"EĞİTİLMİŞ UZMAN PUANI    : {lora_total} / 36")
    
    if lora_total > base_total:
        print("\n🏆 KAZANAN: EĞİTİLMİŞ UZMAN (LORA) KESİN BİR ZAFER KAZANDI!")

if __name__ == "__main__":
    main()