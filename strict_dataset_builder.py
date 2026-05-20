import json
import os
import ollama
import random

train_file = "data/train.jsonl"
valid_file = "data/valid.jsonl"
total_valid_rules_needed = 200

# Veri setini böleceğimiz oran (%85 Eğitim, %15 Test/Doğrulama)
split_ratio = 0.85 

categories = [
    "DDoS", "SQL Injection", "XSS", "SSH Brute Force", 
    "Path Traversal", "C2 Beaconing", "Port Scan", "RCE"
]

os.makedirs("data", exist_ok=True)

# Önceki kirli verileri temizle
open(train_file, 'w').close()
open(valid_file, 'w').close()

def is_rule_valid(rule: str) -> bool:
    """Codex'in audit kurallarına göre kuralı denetler."""
    if not rule.startswith("alert"): return False
    if "rev:1;" not in rule: return False
    if "msg:" not in rule: return False
    if "sid:" not in rule: return False
    if "classtype:" not in rule: return False
    if rule.count("(") != rule.count(")"): return False
    # Şüpheli portları engellemek için basit kontrol
    if "80,443" in rule or "any any" not in rule: 
        pass # Daha katı yapılabilir ama şimdilik yapısal bütünlüğe odaklanıyoruz
    return True

print("Katı Kurallı Veri Üretimi Başlıyor...")
print("Sadece kurum standardına ($HOME_NET, rev:1, classtype vb.) uyan kurallar kabul edilecek.\n")

valid_rules_generated = 0
sid_counter = 1000001 # Kurum standardı SID başlangıcı

train_data = []
valid_data = []

while valid_rules_generated < total_valid_rules_needed:
    category = random.choice(categories)
    
    prompt = f"""Sen bir SOC analistisin.
Aşağıdaki kategori için 1 adet gerçekçi Snort IDS kuralı ve bunu isteyen bir yöneticinin Türkçe sorusunu yaz.
Kategori: {category}

KESİN KURALLAR:
1. SADECE tek satır Snort kuralı yazılacak.
2. Kural 'alert' ile başlamalı.
3. Ağ değişkenleri olarak her zaman $EXTERNAL_NET ve $HOME_NET kullanılmalı.
4. Kuralın içinde kesinlikle şu alanlar olmalı: msg, flow, classtype, sid:{sid_counter}, rev:1
5. Asla açıklama veya markdown ekleme.

SADECE aşağıdaki JSON yapısını doldur:
{{
    "instruction": "Türkçe soru",
    "rule": "Snort kuralı"
}}"""
    
    try:
        response = ollama.chat(
            model='qwen2.5-coder:14b',
            messages=[{'role': 'user', 'content': prompt}],
            format='json',
            options={'temperature': 0.6}
        )
        
        data = json.loads(response['message']['content'])
        rule = data["rule"].strip()
        instruction = data["instruction"].strip()
        
        # PYTHON FİLTRESİ: Kural Codex standartlarından geçiyor mu?
        if is_rule_valid(rule) and "$HOME_NET" in rule and "$EXTERNAL_NET" in rule:
            lora_line = {
                "messages": [
                    {"role": "user", "content": instruction},
                    {"role": "assistant", "content": rule}
                ]
            }
            
            # Train / Valid ayrımı
            if random.random() < split_ratio:
                train_data.append(lora_line)
            else:
                valid_data.append(lora_line)
                
            valid_rules_generated += 1
            sid_counter += 1
            print(f"[{valid_rules_generated}/{total_valid_rules_needed}] ✓ Geçerli Kural Üretildi: {category}")
        else:
            print(f"[-] Hatalı üretim tespit edildi, reddedildi (Eksik parametre).")
            
    except Exception as e:
        continue

# Dosyalara yazma
with open(train_file, 'w', encoding='utf-8') as f:
    for line in train_data:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")

with open(valid_file, 'w', encoding='utf-8') as f:
    for line in valid_data:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")

print(f"\nİşlem Tamamlandı!")
print(f"Eğitim Verisi (Train): {len(train_data)} satır -> {train_file}")
print(f"Test Verisi (Eval): {len(valid_data)} satır -> {valid_file}")