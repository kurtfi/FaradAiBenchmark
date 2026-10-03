# ISSUE-006: Test Vaka ve Veri Kümesi Gezgini (Test Cases Dataset Explorer)

## Parent
[SPEC: Test Cases Dataset Explorer](../specs/test-cases-explorer-spec.md)

## What to build
Model test koşumlarından bağımsız olarak, güvenlik benchmark havuzumuzda ([`data/processed/master_benchmark.parquet`](../../data/processed/master_benchmark.parquet)) yer alan 16.000+ test senaryosunu incelemek üzere DuckDB tabanlı sunucu taraflı sayfalanmış (paginated) REST API ve Web Dashboard arayüzü geliştirmek.

### Yapılacaklar:
1. **Backend REST API (`web/app.py`):**
   - `GET /api/test-cases/filters`: Kaynak veri kümeleri (`source_dataset`), tehdit kategorileri (`threat_domain`) ve katmanları (`analysis_tier`) vaka sayılarıyla döner.
   - `GET /api/test-cases`: `page`, `limit` (20, 50, 100), `dataset`, `threat_domain`, `tier`, `is_malicious`, `search` parametreleriyle DuckDB üzerinden `LIMIT` / `OFFSET` ile doğrudan Parquet sorgulayan uç nokta.
2. **Web Arayüzü (`web/templates/index.html`, `web/static/app.js`, `web/static/index.css`):**
   - Üst navigasyona **`🔍 Test Cases`** sekmesi eklenmesi.
   - Filtre Çubuğu: Kaynak Dataset, Tehdit Türü, Katman, Güvenlik Durumu (Güvenli/Zararlı), Serbest Metin Arama ve Sayfa Boyutu seçicileri.
   - Özet Tablo ve Sayfalama kontrolleri (önceki, sonraki, sayfa no, toplam vaka).
   - Satıra tıklandığında sağdan kayan **Detay Çekmecesi (Side Drawer)**: Formatlı JSON argümanları, prompt context ve kopyalama butonu.
3. **Testler (`tests/test_api_test_cases.py`):**
   - API filtrelerinin, sayfalama sınırlarının ve anahtar kelime aramasının birim/entegrasyon testleri.

## Acceptance criteria
- [ ] `GET /api/test-cases/filters` doğru filtre seçeneklerini ve toplam vaka sayısını döner.
- [ ] `GET /api/test-cases` DuckDB üzerinde dinamik filtrelere ve `LIMIT/OFFSET` parametrelerine göre <50ms'de yanıt üretir.
- [ ] Web Dashboard üst menüsünde `🔍 Test Cases` sekmesi açılır ve filtreler dinamik yüklenir.
- [ ] Tabloda sayfalama (20/50/100) ve metin arama sorunsuz çalışır.
- [ ] Bir satıra tıklandığında Detay Çekmecesi açılarak prompt context ve JSON tool arguments içeriğini gösterir.
- [ ] Tüm testler `pytest tests/test_api_test_cases.py` ile yeşil geçer.

## Blocked by
- None (Hemen başlanabilir)
