# ADR 0004: DuckDB İlişkisel Değerlendirme Tablosu ve Uyuşmazlık (Discrepancy) Analizi

* **Tarih:** 2026-10-02
* **Durum:** Kabul Edildi (Accepted)
* **Kapsam:** Faraday Guard / Benchmark Depolama ve Karşılaştırma Altyapısı

---

## 1. Bağlam ve Problem Tanımı (Context)
10.000+ test vakasının yer aldığı benchmark koşumlarında:
1. Sonuçları `run_history` tablosunda tek bir JSON metni (`VARCHAR`) olarak saklamak bellek şişmesine, yavaş deserialization'a ve sorgu verimsizliğine yol açar.
2. Web arayüzünde iki farklı modelin 10.000 sonucunu satır satır tarayıcıya basarak diff yapmak performansı kilitler. Oysa güvenlik araştırmacılarının asıl ihtiyacı, iki modelin aynı kararı verdiği binlerce vaka değil, **kararların çeliştiği (Discrepancy / Mismatch)** alt kümedir.

---

## 2. Alınan Kararlar ve Gerekçeleri (Decision Log)

### Karar 1: Ayrık İlişkisel Tablo Yapısı
* **Karar:** DuckDB içinde iki ayrık tablo yapısına geçilecektir:
  - `run_history`: Koşumun genel özet metriklerini (F1, Accuracy, Precision, Recall, FPR, p95 Latency, süre) tutar.
  - `run_case_evaluations`: Her bir vakanın koşum sonucunu tutar (`run_id, case_id, domain, expected, predicted, correct, confidence, latency_ms`).
* **Gerekçe:** DuckDB columnar sıkıştırması sayesinde 10.000 satır yalnızca ~200 KB disk kaplar.

### Karar 2: SQL Tabanlı Uyuşmazlık (Discrepancy) Analizi
* **Karar:** İki koşum karşılaştırılırken tarayıcıya tüm veri gönderilmeyecektir. DuckDB üzerinde `JOIN` sorgusu çalıştırılarak:
  - **Mutabakat Oranı (Agreement Rate):** Modellerin % kaç oranda aynı kararı verdiği.
  - **Zıt Kararlar (Discrepancies):** Yalnızca Model A'nın `BLOCKED` deyip Model B'nin `ALLOWED` dediği (veya tersi) vakalar filtrelenip sayfalanmış (paginated) olarak UI'a iletilecektir.

---

## 3. Sonuçlar (Consequences)
* DuckDB şeması `run_case_evaluations` tablosunu içerecek şekilde güncellenecektir.
* `/api/runs/{run_id_a}/compare/{run_id_b}` REST endpoint'i eklenecek ve SQL JOIN ile uyuşmazlıkları dönecektir.
* Web arayüzünde "Compare Runs" sekmesi hafif ve anlık yanıt veren bir yapıya kavuşacaktır.
