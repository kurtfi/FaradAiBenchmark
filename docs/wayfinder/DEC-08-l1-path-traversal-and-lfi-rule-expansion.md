# DEC-08: L1 Kural Genişletmesi: Path Traversal ve LFI Regex Optimizasyonu

* **Kategori:** Declarative L1 Engine / Rule Engineering
* **Durum:** 🔴 Karar Verildi & Aksiyon Bekliyor
* **Öncelik:** P1 (Yüksek)
* **Tarih:** 2026-10-04

---

## 📌 Problem ve Kök Neden (Context & Investigation)

- **Dosya:** [rules/path_traversal.yaml](file:///Users/firatkurt/Documents/Repos/faraday-laya-guard/rules/path_traversal.yaml)
- **Durum:** Smoke Test 2K havuzunda yer alan 124 Path Traversal vakasından L1 motoru yalnızca **28** tanesini yakalayabilmiş, **96** tanesini kaçırmıştır.
- **Kök Neden:**
  1. `path_traversal.yaml` regex kuralları yalnızca `../` ve `[A-Za-z]:\\` (ters slash) beklemektedir.
  2. Test vakalarındaki payload'lar incelendiğinde şunlar görülmüştür:
     - Düz slash Windows yolları: `c:/windows/system32/...`, `c:/xampp/apache/...`
     - Mutlak LFI dosya okuma yolları: `/var/log/...`, `/etc/vsftpd/vsftpd.conf`, `/etc/hostname...`, `/core/config.php`
- **Sonuç:** L1 kuralları çok dar tanımlandığı için bu tipik LFI saldırıları L2'ye sızmakta ve gereksiz L2 GPU maliyeti ya da kaçırma (False Negative) yaratmaktadır.

---

## ⚖️ Çözüm Seçenekleri (Options)

| Seçenek | Tanım | Artıları | Eksileri |
| :--- | :--- | :--- | :--- |
| **A. Deklaratif YAML Genişletmesi (Önerilen)** | `path_traversal.yaml` dosyasına forward-slash Windows sürücü kalıpları (`(?i)[a-z]:/`), `/var/log/`, genel `/etc/` ve `/proc/` LFI kalıpları eklenir. | Sıfır kod değişikliği, L1 anında 96 vakayı yakalar, L2'ye yük binmez. | Çok geniş `.*` kalıpları yazılırsa masum dosya okumalarda false positive riski olabilir; dikkatli regex yazılmalıdır. |
| **B. Sadece L2 Modeline Bırakmak** | Kuralları değiştirmeyip semantik modele güvenmek. | Kural yazma eforu gerekmez. | Yüksek gecikme ve SLM'in kaçırma riski devam eder. |

---

## 🎯 Karar (Decision)
**Seçenek A:** `rules/path_traversal.yaml` güncellenerek tipik LFI/Absolute Path okuma kalıpları ve hem `/` hem `\` Windows kalıpları kapsama alınmalıdır.
