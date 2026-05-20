from mlx_lm import load, generate

print("Model ve Profesyonel (Real Data) LoRA adaptörü yükleniyor...")
model, tokenizer = load("mlx-community/Meta-Llama-3-8B-Instruct-4bit", adapter_path="adapters_real")

# Bu sefer oldukça karmaşık, gerçek bir zafiyet tespiti istiyoruz
messages = [
    {"role": "user", "content": "Ağ trafiğinde CVE-2021-44228 (Log4j / Log4Shell) zafiyetini sömürmeye çalışan ve JNDI lookup yapmaya çalışan bir aktiviteyi tespit edecek, pcre (regex) içeren detaylı bir Snort kuralı yazar mısın?"}
]
prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)

print("\nProfesyonel Model Düşünüyor...\n")

response = generate(model, tokenizer, prompt=prompt, max_tokens=400, verbose=False)

# PROFESYONEL FİLTRE: Kurallar her zaman ')' ile biter.
if ")" in response:
    clean_rule = response.split(")")[0] + ")"
else:
    clean_rule = response

print("--- ÜRETİLEN PROFESYONEL SNORT KURALI ---")
print(clean_rule.strip())
print("-----------------------------------------")