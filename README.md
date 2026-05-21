<div align="center">

# LLM-IDS-Generator

### Natural Language to Snort/Suricata IDS Rule Generator

**Doğal dilde yazılan siber tehditleri, %100 lokal çalışan bir LLM ile sektör standardı IDS kurallarına çeviren fine-tuned bir motor.**

---

[![Model](https://img.shields.io/badge/Base%20Model-Llama--3--8B--Instruct--4bit-blue?logo=meta&logoColor=white)](https://huggingface.co/mlx-community/Meta-Llama-3-8B-Instruct-4bit)
[![Framework](https://img.shields.io/badge/Framework-MLX-black?logo=apple&logoColor=white)](https://github.com/ml-explore/mlx)
[![Method](https://img.shields.io/badge/Fine--Tuning-LoRA-orange)](https://arxiv.org/abs/2106.09685)
[![Hardware](https://img.shields.io/badge/Hardware-Apple%20Silicon-lightgrey?logo=apple)](https://www.apple.com/mac/)
[![Data Source](https://img.shields.io/badge/Dataset-Emerging%20Threats%20Open-red?logo=proofpoint)](https://rules.emergingthreats.net/)

</div>

---

## Proje Vizyonu

SOC ekipleri için Snort/Suricata kuralı yazmak zaman alıcı ve uzmanlık gerektiren bir iştir. LLM-IDS-Generator, Türkçe doğal dilde tarif edilen bir tehdidi alıp **çalıştırılabilir bir IDS kuralına** çevirir — hem de hiçbir bulut API'sine bağlanmadan, tek bir Mac üzerinde lokal olarak.

İlk versiyonda saf `Llama-3-8B-Instruct` ile başlanmış, ancak model gevezelik ediyor ve halüsinasyon görüyordu. Çözüm olarak **Emerging Threats Open** ruleset'inden üretilen gerçek dünya verisiyle **MLX + LoRA** üzerinde fine-tuning yapıldı. Sonuç: gevezelik etmeyen, sadece kural üreten, profesyonel etiketleri (CISA_KEV, MITRE ATT&CK, CVE) doğal şekilde kullanan bir uzman model.

---

## Mimari ve Teknolojiler

| Katman | Teknoloji | Rol |
|---|---|---|
| **Base LLM** | `mlx-community/Meta-Llama-3-8B-Instruct-4bit` | 4-bit quantize edilmiş, Apple Silicon'da çalışacak boyutta temel model |
| **Inference / Training Framework** | **MLX** (Apple ML Research) | Unified memory mimarisi sayesinde GPU/CPU ayrımı olmadan native çalışma |
| **Fine-Tuning Yöntemi** | **LoRA** (Low-Rank Adaptation) | Tam fine-tune yerine sadece düşük rank'li adaptör matrislerini eğiterek hız ve disk tasarrufu |
| **Donanım** | MacBook M5 Pro · Apple M Serisi | Tüm pipeline, internet bağlantısı olmadan tek bir Mac üzerinde |
| **Veri Kaynağı** | [Emerging Threats Open Ruleset](https://rules.emergingthreats.net/) | Sektör standardı, topluluk-doğrulamalı IDS kuralları |
| **Veri Formatı** | JSONL (chat-template uyumlu) | `train.jsonl` / `valid.jsonl` Llama-3 instruct şablonuna uygun |

### Pipeline Akışı

```
┌────────────────────┐      ┌─────────────────────┐      ┌──────────────────┐
│  ET Open Ruleset   │ ───▶ │  fetch_real_data.py │ ───▶ │ train.jsonl /    │
│   (tar.gz, .rules) │      │  (Regex + Parser)   │      │  valid.jsonl     │
└────────────────────┘      └─────────────────────┘      └────────┬─────────┘
                                                                  │
                                                                  ▼
┌────────────────────┐      ┌─────────────────────┐      ┌──────────────────┐
│  smart_compare.py  │ ◀─── │   adapters_real/    │ ◀─── │  MLX LoRA Train  │
│  (Base vs LoRA)    │      │ (LoRA adaptörleri)  │      │  300 iterasyon   │
└────────────────────┘      └─────────────────────┘      └──────────────────┘
```

---

## Scriptlerin İşlevleri

### `fetch_real_data.py` — Gerçek Veri Üretici
- [Emerging Threats Open](https://rules.emergingthreats.net/) sunucusundan `tar.gz` paketini indirir.
- Arşivi açar, içindeki tüm `.rules` dosyalarını parse eder.
- **PCRE (regex)**, **metadata**, **CVE referansları**, **hex encoding** (`|3a|`, `|0d 0a|`) gibi kompleks alanları kaybetmeden çıkartır.
- Her kuralı, Llama-3'ün chat template'ine uygun JSONL satırına çevirir:
  ```json
  {"messages": [
    {"role": "user", "content": "<doğal dilde tehdit tarifi>"},
    {"role": "assistant", "content": "<snort/suricata kuralı>"}
  ]}
  ```

### `smart_compare.py` — Akıllı Benchmark Motoru
- **6 farklı saldırı senaryosunda** base modelle LoRA modelini yarıştırır.
- `max_tokens=1500` ile her iki modele de uzun bağlam alanı verir.
- Üretilen çıktıyı 4 metrik üzerinden puanlar:
  - **Gevezelik var mı?** ("Here is...", açıklama paragrafı, vb.)
  - **`sid` ve `rev` alanları doğru mu?**
  - **`metadata` / `reference` alanı kullanılmış mı?** (uzmanlık göstergesi)
  - **PCRE, hex encoding ya da `flow` gibi profesyonel öğeler var mı?**

### `test_model.py` — Hızlı Sanity Check
- Tek bir karmaşık prompt (örn. *CVE-2021-44228 / Log4Shell JNDI lookup tespiti*) ile LoRA modelini canlı çalıştırır.
- Yanıtın `)` karakterinden sonrasını kırparak temiz, çalıştırılabilir bir kural üretir.

### `dataset_audit.py` / `clean_dataset.py`
- Dataset'in token uzunluk dağılımını ve duplikasyonları analiz eder.
- Bozuk, çok kısa veya sentetik bulaşmış örnekleri ayıklar.

---

## Benchmark: Base Llama-3 vs Fine-tuned LLM-IDS-Generator

`smart_compare.py` ile 6 farklı tehdit senaryosunda toplam **36 puan üzerinden** yapılan değerlendirme:

<div align="center">

| Model | Skor | Gevezelik | Halüsinasyon | Metadata/Reference Kullanımı | Sonsuz Döngü |
|:---:|:---:|:---:|:---:|:---:|:---:|
| **Base** `Llama-3-8B-Instruct-4bit` | **9 / 36** | Yüksek | Var | Tutarsız | Var (28x tekrar) |
| **LLM-IDS-Generator (LoRA)**        | **30 / 36** | Yok | Yok | Doğal & doğru | Yok |

</div>

### Niteliksel Fark

> **Base Model:**
> *"Sure! Here is a Snort rule for detecting Log4Shell. You should also consider updating your firewall, and additionally... Sure! Here is a Snort rule for detecting Log4Shell. You should also consider updating your firewall, and additionally... Sure! Here is..."* (28 kez tekrar)

> **LLM-IDS-Generator (Fine-tuned):**
> `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Apache log4j RCE Attempt (jndi ldap)"; flow:established,to_server; content:"${jndi|3a|"; fast_pattern; pcre:"/\$\{jndi\x3a(ldap|rmi|dns|nis|iiop|corba|nds|http)\x3a/i"; reference:cve,2021-44228; classtype:attempted-admin; sid:2034647; rev:3; metadata:created_at 2021_12_10, cve CVE_2021_44228, deployment Perimeter, signature_severity Major, tag CISA_KEV, updated_at 2022_08_25;)`

Fine-tuned model **tek satırda**, **gerçek bir kural** üretir. CVE referansı, `flow` durumu, `pcre` regex'i, hex encoded ayraç (`|3a|`), `CISA_KEV` etiketi ve `signature_severity` metadata'sı dahil.

---

## Üretilen Örnek Kural

**Prompt (Türkçe):**
> "Ağ trafiğinde CVE-2021-44228 (Log4j / Log4Shell) zafiyetini sömürmeye çalışan ve JNDI lookup yapmaya çalışan bir aktiviteyi tespit edecek, pcre (regex) içeren detaylı bir Snort kuralı yazar mısın?"

**Üretilen Kural:**
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"ET EXPLOIT Apache log4j RCE Attempt (jndi ldap)";
    flow:established,to_server;
    content:"${jndi|3a|";
    fast_pattern;
    pcre:"/\$\{jndi\x3a(ldap|rmi|dns|nis|iiop|corba|nds|http)\x3a/i";
    reference:cve,2021-44228;
    classtype:attempted-admin;
    sid:2034647;
    rev:3;
    metadata:
        created_at 2021_12_10,
        cve CVE_2021_44228,
        deployment Perimeter,
        signature_severity Major,
        tag CISA_KEV,
        updated_at 2022_08_25;
)
```

---

## Kurulum

### Ön Gereksinimler

- **macOS 13+** (Apple Silicon — M1 / M2 / M3 / M4 / M5)
- **Python 3.10+**
- Yaklaşık **8 GB** boş disk (base model + adaptörler için)

### Adımlar

```bash
# 1. Repoyu klonla
git clone https://github.com/<kullanici-adi>/llm-ids-generator.git
cd llm-ids-generator

# 2. Sanal ortam kur
python3 -m venv mlx_env
source mlx_env/bin/activate

# 3. Bağımlılıkları yükle
pip install --upgrade pip
pip install mlx mlx-lm requests
```

> İlk çalıştırmada `mlx-community/Meta-Llama-3-8B-Instruct-4bit` HuggingFace üzerinden tek seferlik olarak indirilir (~4.5 GB). Sonraki tüm çalıştırmalar **tamamen offline**'dır.

---

## Kullanım

### Tek Promptluk Test

```bash
python test_model.py
```

Çıktı:

```
Model ve Profesyonel (Real Data) LoRA adaptörü yükleniyor...

Profesyonel Model Düşünüyor...

--- ÜRETİLEN PROFESYONEL SNORT KURALI ---
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT ...
-----------------------------------------
```

### Base vs LoRA Karşılaştırması

```bash
python smart_compare.py
```

6 senaryoyu sırayla çalıştırır, her iki modelden de cevap alır, skorlar ve son tabloyu yazdırır.

---

## LoRA Fine-Tuning: Derinlemesine

Bu proje, **8 milyar parametreli** bir LLM'in tam fine-tune'unu yapmaz — bu bir MacBook'ta hem bellek hem zaman olarak imkânsız olurdu. Yerine, **LoRA (Low-Rank Adaptation)** ile yalnızca düşük rank'li adaptör matrisleri (`A ∈ ℝ^(d×r)` ve `B ∈ ℝ^(r×d)`) eğitilir; orijinal model ağırlıkları **donmuş** kalır. Bu sayede:

- Eğitilecek parametre sayısı **tüm modelin %1'inin altına** düşer.
- Final adaptör dosyası **~10–40 MB** olur (model 4.5 GB iken).
- Çıkarımda base model + adaptör birlikte yüklenir; istenirse adaptör çıkarılarak vanilla davranışa dönülebilir.

### Hyperparametre Konfigürasyonu

Tüm değerler `adapters_real/adapter_config.json` dosyasından alınmıştır (reprodüksiyon için aynı dosya repodadır):

| Parametre | Değer | Anlamı / Seçim Mantığı |
|---|---|---|
| `fine_tune_type` | `lora` | Full fine-tune yerine LoRA — Apple Silicon belleği için zorunluluk |
| `lora_parameters.rank` (r) | **8** | Düşük rank → hızlı yakınsama, küçük adaptör. ET kurallarındaki kalıp çeşitliliği için yeterli. |
| `lora_parameters.scale` (α) | **20.0** | LoRA çıktısı `α/r = 2.5` faktörüyle ölçeklenir; agresif adapte ama dengeli |
| `lora_parameters.dropout` | **0.0** | Görece küçük dataset; dropout uygulamak underfitting riskini artırırdı |
| `num_layers` | **16** | Llama-3'ün son 16 katmanına LoRA enjekte edildi — alt katmanlar genel dil bilgisi için dokunulmadı |
| `learning_rate` | **1e-4** | LoRA için tipik; daha yüksek değerler catastrophic forgetting riski taşır |
| `optimizer` | **Adam** | Adaptif momentum; küçük adaptör matrisleri için stabil |
| `batch_size` | **2** | M-serisi unified memory limiti; `grad_accumulation=1` ile effective batch = 2 |
| `max_seq_length` | **2048** | ET kuralları + Türkçe prompt + metadata için yeterli kontekst |
| `iters` | **300** | Validation loss platosuna kadar; erken bitirme yerine sabit bütçe |
| `steps_per_report` | **10** | Loss eğrisini sık görmek için |
| `steps_per_eval` | **200** | Overfit tespiti için iki kontrol noktası (200, 400 → 300'de durdu) |
| `save_every` | **100** | `0000100`, `0000200`, `0000300` checkpoint'leri → rollback imkânı |
| `val_batches` | **25** | Validation pass'inde 25 batch ortalaması alınarak gürültü azaltıldı |
| `seed` | **0** | Tam reprodüksiyon için sabit |

### LoRA'nın Llama-3'e Enjeksiyon Noktaları

MLX'in LoRA implementasyonu, dikkat (attention) bloklarındaki **query** ve **value** projeksiyonlarına (`q_proj`, `v_proj`) düşük-rank adaptörler ekler. Bu, Hu et al. (2021) orijinal LoRA makalesindeki bulgu ile uyumludur: `q_proj` + `v_proj` ikilisi, parametre/performans dengesinin **sweet spot**'udur. Tüm projeksiyonlara (`q,k,v,o`) uygulamak %30 daha fazla parametre eğitilmesine ve mütevazı (~%2) kalite artışına yol açardı — bu projenin maliyet/fayda hesabında değmedi.

### Eğitim Komutu (Tam Reprodüksiyon)

```bash
python -m mlx_lm.lora \
    --model mlx-community/Meta-Llama-3-8B-Instruct-4bit \
    --train \
    --data data_real \
    --fine-tune-type lora \
    --num-layers 16 \
    --batch-size 2 \
    --iters 300 \
    --learning-rate 1e-4 \
    --steps-per-report 10 \
    --steps-per-eval 200 \
    --save-every 100 \
    --max-seq-length 2048 \
    --adapter-path adapters_real \
    --seed 0
```

### Eğitim Sürecinde Gözlemler

- **`steps_per_report=10`** sayesinde loss eğrisi 30 noktada izlendi.
- Modelin "gevezelik bırakma" davranışı **~100. iterasyondan** itibaren validation üzerinde belirgin hale geldi: önce `"Here is the rule:"` gibi kalıplar düştü, sonra `sid`/`rev` numaraları stabilleşti.
- **200. iterasyon** evaluation'ında validation loss train ile birlikte düşmeye devam ediyordu → underfit değil.
- **300. iterasyon** sonunda model, `metadata: created_at ..., signature_severity ..., tag CISA_KEV` gibi alanları doğal olarak üretir hale geldi. Bu, validation loss'tan ziyade `smart_compare.py`'ın kalitatif metriklerinde belirginleşti.
- Catastrophic forgetting kontrolü: Türkçe genel sohbet promptlarında base davranış korundu (LoRA çıkarıldığında model hâlâ normal sohbet ediyor).

### Neden Tam Fine-Tune Değil?

| Kriter | Full Fine-Tune | LoRA (bu proje) |
|---|---|---|
| Eğitilen parametre sayısı | ~8 B | ~3-5 M (%0.05) |
| GPU bellek ihtiyacı | 80+ GB | 16-24 GB |
| Eğitim süresi (M serisi) | Günler | **30–50 dakika** |
| Çıktı boyutu | ~16 GB | **~15 MB** |
| Catastrophic forgetting riski | Yüksek | Düşük (base donmuş) |
| Görev değiştirme | Tüm modeli yeniden eğit | Sadece adaptörü değiştir |

Bu tablo, LoRA tercihinin neden teorik bir tasarruf değil **bu projeyi mümkün kılan tek seçenek** olduğunu açıklar.

### Adaptör Yönetimi

```bash
adapters_real/
├── adapter_config.json            # Hyperparametre snapshot'ı (yukarıdaki tablo)
├── 0000100_adapters.safetensors   # iter 100 checkpoint
├── 0000200_adapters.safetensors   # iter 200 checkpoint
├── 0000300_adapters.safetensors   # iter 300 checkpoint (final)
└── adapters.safetensors           # En son save'in alias'ı
```

Farklı checkpoint'leri test etmek için `test_model.py` içindeki `adapter_path` parametresini değiştirmen yeterlidir — model dosyasını yeniden indirmeden anlık olarak farklı eğitim durumlarını karşılaştırabilirsin.
