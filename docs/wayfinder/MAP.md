# 🗺️ Wayfinder Map: Faraday Guard & SLM Benchmark Studio

* **Durum:** Aktif Harita (In Progress)
* **Kapsam:** Faraday Guard / İki Katmanlı (Statik + Semantik) DLP & Çoklu SLM Benchmark Platformu
* **Tarih:** 2026-10-01

---

## 🎯 Nihai Hedef (Destination)
Faraday Gateway ve LLM-MCP iletişimi için **mikrosaniye düzeyinde statik DLP** ile **Apple Silicon üzerinde yerel çalışan SLM semantik analizini** birleştiren; modellerin (Laya, Llama-Guard-3-1B, ShieldGemma, vb.) doğruluk, FPR ve gecikme performanslarını ölçüp görselleştiren **tam teşekküllü bir Benchmark Web Stüdyosu** oluşturmak.

---

## 🧭 Karar Biletleri (Decision Tickets Index)

| Bilet Kodu | Konu | Durum | Öncelik |
| :--- | :--- | :--- | :--- |
| **`DEC-01`** | **Statik ve Semantik Veri Kümelerinin Ayrımı** | 🟢 Tamamlandı | P0 |
| **`DEC-02`** | **Yerel SLM Alternatifleri ve MLX Desteği (Llama-Guard, Granite, ShieldGemma)** | 🟢 Tamamlandı | P0 |
| **`DEC-03`** | **Proje Dili & Mimari Sınırlar (Python vs Go / FaradayGateway Köprüsü)** | 🟢 Tamamlandı | P0 |
| **`DEC-04`** | **Test Koşu Veritabanı ve Çalışma Geçmişi Şeması (DuckDB)** | 🟢 Tamamlandı | P1 |
| **`DEC-05`** | **Web Dashboard UI & Canlı Test İzleme Mimarisi** | 🟢 Tamamlandı | P1 |
| **[`DEC-06`](./DEC-06-benchmark-dataset-label-and-parameter-cleanup.md)** | **Benchmark Veri Seti Temizliği (AgentDojo Label Inversion & InjecAgent Mismatch)** | 🟢 Tamamlandı | P0 |
| **[`DEC-07`](./DEC-07-system-prompt-and-context-isolation-refactor.md)** | **System Prompt Mimarisi ve Girdi Temsili (Untrusted Context Isolation)** | 🟢 Tamamlandı | P0 |
| **[`DEC-08`](./DEC-08-l1-path-traversal-and-lfi-rule-expansion.md)** | **L1 Kural Genişletmesi: Path Traversal ve LFI Regex Optimizasyonu** | 🟢 Tamamlandı | P1 |
| **[`DEC-09`](./DEC-09-model-threshold-calibration-and-adapter-parser-fixes.md)** | **Model Eşik Kalibrasyonu ve Adapter Parser Düzeltmeleri (Laya & ShieldGemma)** | 🟢 Tamamlandı | P1 |

---

## 🗺️ Yol Haritası ve Fazlar

### Faz 1-4: Altyapı ve Karşılaştırmalı Benchmark Stüdyosu (Tamamlandı ✅)
* Statik L1 Kural Motoru, L2 Pluggable Adapter Mimarisi, DuckDB Veri Tabanı ve Web Karşılaştırma Dashboard'u tamamlandı.

### Faz 5: Benchmark Doğrulama, Veri Seti Temizliği & Prompt Optimizasyonu (Tamamlandı ✅)
* **Adım 1 (DEC-06):** `transform_to_parquet.py` güncellendi; canonical `INJECTION_TARGET_CHECKS` ve clean baseline diffing entegre edildi. InjecAgent araç havuzundan çıkarıldı.
* **Adım 2 (DEC-07):** Context ve prompt analizi tamamlandı. Laya MLX'te RL policy head dengesini korumak için dual-check yapısı korundu.
* **Adım 3 (DEC-08):** `rules/path_traversal.yaml` dosyasına forward-slash ve genel Unix LFI / Windows path kalıpları eklendi.
* **Adım 4 (DEC-09):** Laya MCP ve runner için tiered thresholding (Exploit 0.50, Misalignment 0.65) uygulandı.
* **Adım 5:** `master_benchmark.parquet` (14.436 vaka) ve `smoke_test_2k.parquet` yeniden üretildi; testler %100 geçti ve benchmark matrix ile Laya MLX (%83.05 F1) ve Hybrid Cascade (%89.48 F1) başarıyla doğrulandı.

