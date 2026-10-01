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
| **`DEC-01`** | **Statik ve Semantik Veri Kümelerinin Ayrımı** | 🟢 Analiz Edildi / Karara Hazır | P0 |
| **`DEC-02`** | **Yerel SLM Alternatifleri ve MLX Desteği (Llama-Guard, Granite, ShieldGemma)** | 🟢 Araştırıldı / Seçime Hazır | P0 |
| **`DEC-03`** | **Proje Dili & Mimari Sınırlar (Python vs Go / FaradayGateway Köprüsü)** | 🟢 Netleştirildi | P0 |
| **`DEC-04`** | **Test Koşu Veritabanı ve Çalışma Geçmişi Şeması (DuckDB)** | 🟡 Tasarım Aşamasında | P1 |
| **`DEC-05`** | **Web Dashboard UI & Canlı Test İzleme Mimarisi** | 🟡 Tasarım Aşamasında | P1 |

---

## 🗺️ Yol Haritası ve Fazlar

### Faz 1: Tehdit ve Analiz Ayrımı (DEC-01 & DEC-02)
* Statik kural motoru (Regex + Shannon Entropy + Imza havuzu) ile Semantik SLM motorunun iş bölümü.
* Apple Silicon üzerinde yerel çalışacak en iyi 3 SLM modelinin tespiti ve MCP sunucusu olarak paketlenmesi.

### Faz 2: Çift Katmanlı Guard Motoru (Dual-Layer Engine)
* Gelen araç çağrısında önce Statik (<0.5 ms), gerekirse Semantik (10-25 ms) çalıştıran ardışık mimari.
* Her iki katman için ayrı ayrı gecikme (latency) ve karar telemetrisi.

### Faz 3: Kalıcı Test Geçmişi (Persistent Run Store)
* Her test koşusu için benzersiz `run_id`, model adı, veri seti, statik/semantik süreler, accuracy, precision, recall ve vaka detaylarını DuckDB tablosunda saklama.

### Faz 4: Benchmark Web Dashboard
* Model seçimi, veri kümesi filtresi, canlı progress bar, özet metrik kartları ve başarısız vakaların tek tek tıklandığı interaktif Web UI.
