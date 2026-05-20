import urllib.request
import tarfile
import re
import json
import random
import os
import io

# Güncel ve kalıcı olan Suricata/Snort kural arşivi URL'si
ET_TAR_URL = "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"
OUTPUT_FILE = "data/train_real.jsonl"
VALID_FILE = "data/valid_real.jsonl"

os.makedirs("data", exist_ok=True)

print("1. Emerging Threats sunucusundan güncel kural arşivi indiriliyor (Bu birkaç saniye sürebilir)...")
req = urllib.request.Request(ET_TAR_URL, headers={'User-Agent': 'Mozilla/5.0'})

with urllib.request.urlopen(req) as response:
    # Tar.gz dosyasını belleğe alıyoruz
    tar_stream = io.BytesIO(response.read())

print("2. Arşiv açılıyor ve 'emerging-exploit.rules' dosyası ayıklanıyor...")
dataset = []

with tarfile.open(fileobj=tar_stream, mode="r:gz") as tar:
    # Arşivin içinden exploit kurallarını bul
    exploit_file = tar.extractfile("rules/emerging-exploit.rules")
    if exploit_file is None:
        raise Exception("Kurallar arşivden çıkarılamadı!")
        
    lines = exploit_file.read().decode('utf-8').split('\n')

    print("3. Kurallar analiz ediliyor ve veri setine dönüştürülüyor...")
    for line in lines:
        line = line.strip()
        # Yorum satırlarını ve boş satırları atla
        if not line or line.startswith('#') or not line.startswith('alert'):
            continue
        
        # Kuralın açıklamasını (msg) ve varsa CVE numarasını (reference:cve) çıkar
        msg_match = re.search(r'msg:\s*"([^"]+)"', line)
        cve_match = re.search(r'reference:cve,(20\d{2}-\d+)', line)
        
        if msg_match:
            raw_msg = msg_match.group(1)
            # "ET EXPLOIT" gibi etiketleri temizleyip daha doğal hale getirelim
            clean_msg = raw_msg.replace("ET EXPLOIT ", "").replace("ET WEB_SPECIFIC_APPS ", "")
            
            # Türkçe Prompt Oluşturma
            if cve_match:
                cve_id = cve_match.group(1)
                prompt = f"Ağ trafiğinde CVE-{cve_id} zafiyetini sömürmeye çalışan '{clean_msg}' aktivitesini tespit edecek gerçekçi ve detaylı bir Snort kuralı yazar mısın?"
            else:
                prompt = f"Ağ trafiğinde '{clean_msg}' aktivitesini tespit edecek detaylı (pcre, byte_test vb. içeren) bir Snort kuralı yaz."
            
            # Veriyi Llama-3'ün anlayacağı JSONL formatına sokuyoruz
            lora_line = {
                "messages": [
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": line}
                ]
            }
            dataset.append(lora_line)

# Eğitim süresini optimize etmek için en iyi 400 kuralı rastgele seçiyoruz
if len(dataset) > 400:
    dataset = random.sample(dataset, 400)
else:
    random.shuffle(dataset)

# Veriyi Train (%85) ve Valid (%15) olarak ayır
split_index = int(len(dataset) * 0.85)
train_data = dataset[:split_index]
valid_data = dataset[split_index:]

with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    for item in train_data:
        f.write(json.dumps(item, ensure_ascii=False) + '\n')

with open(VALID_FILE, 'w', encoding='utf-8') as f:
    for item in valid_data:
        f.write(json.dumps(item, ensure_ascii=False) + '\n')

print(f"\n✅ İşlem Tamamlandı!")
print(f"Eğitim Verisi (Train): {len(train_data)} satır -> {OUTPUT_FILE}")
print(f"Test Verisi (Valid): {len(valid_data)} satır -> {VALID_FILE}")
print("Gerçek siber güvenlik verileri başarıyla indirildi. Eğitime hazırız!")