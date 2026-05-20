import json
import random
import re
import shutil

input_file = "data/train.jsonl"
backup_file = "data/train_backup.jsonl"

# Orijinal verinin ne olur ne olmaz yedeğini alıyoruz
shutil.copy(input_file, backup_file)

clean_data = []

with open(input_file, 'r', encoding='utf-8') as f:
    for line in f:
        if not line.strip(): continue
        row = json.loads(line)
        rule = row["messages"][1]["content"].strip()

        # 1. HATA ÇÖZÜMÜ: Eksik rev:1 ekleme
        if "rev:" not in rule:
            if rule.endswith(")"):
                rule = rule[:-1].strip()
                if not rule.endswith(";"): rule += ";"
                rule += " rev:1;)"

        # 2. HATA ÇÖZÜMÜ: Parantez dengesini bozan eval( problemini düzeltme
        rule = rule.replace('eval("', 'eval"')
        rule = rule.replace('eval(;”', 'eval";') # Olası bozukluklar
        
        # 3. HATA ÇÖZÜMÜ: Şüpheli port yazımını düzeltme (80,443 -> [80,443])
        rule = rule.replace("80,443", "[80,443]")
        rule = rule.replace("80:443", "[80:443]")

        # 4. HATA ÇÖZÜMÜ: Hatalı limit keyword'ünü temizleme
        rule = re.sub(r'limit:\s*[^;]+;', '', rule)

        # 5. HATA ÇÖZÜMÜ: Hatalı flags yazımını onarma (flags:S+)
        rule = rule.replace("flags:S+;", "flags:S;")

        # SON KONTROL: Tüm onarımlara rağmen parantez dengesizliği varsa o satırı çöpe at!
        if rule.count("(") == rule.count(")"):
            rule = re.sub(r'\s+', ' ', rule) # Çift boşlukları düzelt
            row["messages"][1]["content"] = rule
            clean_data.append(row)

# Veriyi Karıştır ve Codex'in istediği gibi Eğit/Test diye böl
random.shuffle(clean_data)
split_index = int(len(clean_data) * 0.85)

train_data = clean_data[:split_index]
valid_data = clean_data[split_index:]

# Temizlenmiş verileri aynı isimle (üzerine yazarak) kaydet
with open("data/train.jsonl", 'w', encoding='utf-8') as f:
    for row in train_data:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

with open("data/valid.jsonl", 'w', encoding='utf-8') as f:
    for row in valid_data:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

print("--- VERİ TEMİZLİĞİ TAMAM ---")
print(f"Kurtarılan ve Temizlenen Satır: {len(clean_data)} / 200")
print(f"Eğitim Verisi (train.jsonl): {len(train_data)} satır")
print(f"Test Verisi (valid.jsonl): {len(valid_data)} satır")