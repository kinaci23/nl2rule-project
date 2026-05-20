import json
import os
import ollama

output_file = "data/train.jsonl"
total_data_needed = 200 

categories = [
    "DDoS ve DoS Atakları", "SQL Injection", "Cross-Site Scripting - XSS",
    "Brute Force / Kaba Kuvvet", "Path Traversal / Dizin Atlatma",
    "Malware C2 Sunucu İletişimi", "Ağ Taraması ve Keşif", "Uzak Kod Çalıştırma - RCE"
]

os.makedirs("data", exist_ok=True)

print("Veri Üretimi Başladı (Qwen 14B - JSON Mode)...")

with open(output_file, 'w', encoding='utf-8') as f:
    for i in range(total_data_needed):
        category = categories[i % len(categories)]
        
        prompt = f"""Sen bir siber güvenlik uzmanısın.
Aşağıdaki kategori için 1 adet gerçekçi Snort IDS/IPS kuralı ve bunu isteyen bir sistem yöneticisinin Türkçe sorusunu yaz.
Kategori: {category}
'sid' değeri {200000 + i} olmalıdır.

SADECE aşağıdaki JSON yapısını doldur, başka hiçbir şey yazma:
{{
    "instruction": "Türkçe soru veya talimat",
    "rule": "Snort kuralı"
}}"""
        
        try:
            response = ollama.chat(
                model='qwen2.5-coder:14b',
                messages=[{'role': 'user', 'content': prompt}],
                format='json',
                options={'temperature': 0.7}
            )
            
            data = json.loads(response['message']['content'])
            
            lora_line = {
                "messages": [
                    {"role": "user", "content": data["instruction"].strip()},
                    {"role": "assistant", "content": data["rule"].strip()}
                ]
            }
            
            f.write(json.dumps(lora_line, ensure_ascii=False) + "\n")
            f.flush()
            print(f"[{i+1}/{total_data_needed}] ✓ {category} yazıldı.")
            
        except Exception:
            continue

print(f"\nİşlem tamam! Veriler hazır.")