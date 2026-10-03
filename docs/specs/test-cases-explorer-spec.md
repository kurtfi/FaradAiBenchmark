# Engineering Specification: Test Cases Dataset Explorer

## 1. Overview & Understanding Summary

- **Feature Name:** Test Cases Dataset Explorer (🔍 Test Cases Sekmesi)
- **Primary Goal:** Model test çalıştırmalarından (`run_case_evaluations`) bağımsız olarak, güvenlik ve kıyaslama havuzunda ([`data/processed/master_benchmark.parquet`](file:///Users/firatkurt/Documents/Repos/faraday-laya-guard/data/processed/master_benchmark.parquet)) yer alan 16.000+ test senaryosunun içeriğini, prompt bağlamını, araç argümanlarını ve güvenlik dağılımını web arayüzünden şeffaf ve hızlı bir şekilde incelemek.
- **Target Audience:** Güvenlik araştırmacıları, LLM/DLP benchmark operatörleri, veri seti küratörleri.
- **Key Constraints:**
  - Veri kümesinin tamamı belleğe yüklenmeyecektir (zero-copy streaming).
  - DuckDB `LIMIT` ve `OFFSET` ile sunucu taraflı sayfalama (pagination: 20, 50, 100 vaka) uygulanacaktır.
  - Filtreleme kriterleri: Kaynak Veri Kümesi (`source_dataset`), Tehdit Türü (`threat_domain`), Analiz Katmanı (`analysis_tier`), Güvenlik Durumu (`is_malicious`), Serbest Metin Arama (`search`).
  - Görsel Sunum: Temiz özet tablo + satıra tıklandığında sağdan açılan Detay Çekmecesi (Side Drawer).
- **Explicit Non-Goals:**
  - Çalıştırılmış benchmark koşumlarının vaka değerlendirmelerini (`run_case_evaluations`) bu ekranda göstermek (bu özellik Compare Runs ve Dashboard'da yer almaktadır).
  - Test verilerini arayüzden düzenleme, ekleme veya silme (CRUD) yapmak (salt-okunur explorer).
  - Ekstra harici veritabanı veya arama motoru kurmak.

---

## 2. Assumptions & Non-Functional Requirements

- **Performance:** DuckDB sorguları diskteki Parquet sütun sıkıştırması sayesinde <50ms içinde yanıt vermelidir; sayfa geçişleri akıcı olmalıdır.
- **Scale:** Mevcut 16.072 test vakası taranmaktadır; mimari 500.000+ vakaya kadar bellek kopyalaması olmadan ölçeklenebilir.
- **Security:** Kullanıcı filtre girdileri parametrik SQL argümanları (`?`) olarak işletilmeli; DuckDB bağlantısı read-only açılmalıdır.
- **Reliability:** Parquet dosyası eksik olduğunda backend açıklayıcı JSON hatası vermeli, dashboard arayüzü çökmeyip toast/boş durum göstermelidir.
- **Design Consistency:** Mevcut Vanilla CSS ve Vanilla JS tasarım dili, koyu tema ve typography kurallarıyla birebir uyumlu olmalıdır.

---

## 3. Decision Log

| # | Karar Konusu | Alınan Karar | Değerlendirilen Alternatifler | Karar Gerekçesi |
|---|---|---|---|---|
| **DEC-01** | **Veri Kapsamı** | Çalışmadan bağımsız ham benchmark havuzu (`master_benchmark.parquet`) | Koşum sonuçları (`run_case_evaluations`) veya ikisinin birleşimi | Test çalıştırmadan önce eldeki vaka havuzunu şeffafça görebilmek. |
| **DEC-02** | **Arayüz Konumu** | Mevcut Web Dashboard'a yeni bir sekme (Tab): `🔍 Test Cases` | Bağımsız rota (`/datasets`) veya Dashboard içinde alt panel | Mevcut tek sayfa (SPA) yapısına entegre, kesintisiz kullanıcı deneyimi. |
| **DEC-03** | **Dataset Filtreleme** | Tek birleşik havuz (`master_benchmark.parquet`) üzerinden `source_dataset` filtresi | Dosya bazlı seçim + iç filtre veya sadece dosya listesi | Tüm vakaları tek çatı altında karşılaştırıp filtreleyebilmek. |
| **DEC-04** | **Detay Gösterimi** | Özet Tablo + Satıra tıklanınca açılan Detay Çekmecesi (Side Drawer) | Genişleyen akordeon veya iki bölmeli (master-detail) ekran | Tablo düzenini bozmadan uzun JSON ve prompt metinlerini şık ve rahatça inceleyebilmek. |
| **DEC-05** | **Sayfalama & Arama** | Sayfa boyutu seçimi (20, 50, 100) + Serbest Metin Arama + İleri/Geri Butonları | Sabit 25 pagination veya Sonsuz Kaydırma (Infinite Scroll) | Kullanıcının veri hacmini kontrol edebilmesi ve spesifik saldırı/güvenli kalıpları hızlıca bulabilmesi. |
| **DEC-06** | **Mimari Yaklaşım** | Yaklaşım 1: Direct Parquet Querying via DuckDB with LIMIT/OFFSET | Yaklaşım 2: Belleğe önceden yüklenen DuckDB tablosu | Düşük RAM kullanımı, anlık veri tazeliği ve düşük bakım maliyeti. |

---

## 4. Detailed Final Design

### 4.1 Backend REST API (`web/app.py`)

#### `GET /api/test-cases/filters`
- **Amaç:** Dropdown filtrelerini doldurmak için benzersiz değerleri ve vaka sayılarını döner.
- **Dönen Veri:**
  ```json
  {
    "total_pool_cases": 16072,
    "datasets": [
      {"name": "AgentDojo_travel", "count": 1250},
      {"name": "SecLists_JWT", "count": 640}
    ],
    "threat_domains": ["COMMAND_INJECTION", "DATA_LEAK", "PATH_TRAVERSAL", "SQLI", "BENIGN", ...],
    "analysis_tiers": ["STATIC_CAPABLE", "SEMANTIC_REQUIRED", "HYBRID"]
  }
  ```

#### `GET /api/test-cases`
- **Query Parametreleri:**
  - `page`: Sayfa numarası (int, varsayılan `1`)
  - `limit`: Sayfa başı kayıt (int, varsayılan `50`, opsiyonlar: 20, 50, 100)
  - `dataset`: `source_dataset` filtresi (opsiyonel)
  - `threat_domain`: Tehdit kategorisi (opsiyonel)
  - `tier`: Analiz katmanı (`all`, `static`, `semantic`, `hybrid`, opsiyonel)
  - `is_malicious`: Güvenlik durumu (`all`, `safe`, `malicious`, opsiyonel)
  - `search`: Prompt veya argümanlar içinde anahtar kelime (opsiyonel)
- **DuckDB Sorgu Şablonu:**
  ```sql
  -- Toplam filtrelenmiş kayıt sayısı
  SELECT COUNT(*) FROM 'data/processed/master_benchmark.parquet' WHERE ...;

  -- Sayfalanmış veri dilimi
  SELECT 
      id,
      source_dataset,
      threat_domain,
      analysis_tier,
      is_malicious,
      cwe,
      owasp_llm,
      tool_name,
      tool_arguments,
      context
  FROM 'data/processed/master_benchmark.parquet'
  WHERE ...
  ORDER BY id
  LIMIT ? OFFSET ?;
  ```

---

### 4.2 Frontend Bileşenleri (`web/templates/index.html` & `web/static/app.js`)

1. **Navigasyon:**
   - `<button class="nav-btn" data-page="test-cases">🔍 Test Cases</button>`
2. **Sayfa Konteyneri (`#page-test-cases`):**
   - **Filtre Çubuğu:**
     - Dataset Select (`#tc-filter-dataset`)
     - Threat Domain Select (`#tc-filter-domain`)
     - Tier Radio / Select (`#tc-filter-tier`)
     - Safety Status Select (`#tc-filter-status`): Tümü / Güvenli (Benign) / Zararlı (Threat)
     - Arama Kutusu (`#tc-filter-search`) (300ms debounce)
     - Sayfa Boyutu Select (`#tc-filter-limit`)
     - Reset Butonu (`#tc-btn-reset`)
   - **Özet Tablo:**
     - Sütunlar: `ID`, `Dataset`, `Tehdit Türü`, `Katman`, `Durum`, `Hedef Araç`, `İşlem`
     - Renkli rozetler (Badges) ve monospace tipografi.
   - **Sayfalama Çubuğu:**
     - Kayıt bilgisi: `Gösterilen: 1 - 50 / Toplam: 16,072 vaka`
     - İlk (`«`), Önceki (`‹`), Sayfa No, Sonraki (`›`), Son (`»`) butonları.
3. **Detay Çekmecesi (Side Drawer):**
   - Kayarak açılan yan panel (`.drawer` & `.drawer-overlay`).
   - Vaka Meta Bilgileri (ID, CWE, OWASP, Katman, Güvenlik Rozeti).
   - Tool Arguments Bloğu (Formatlanmış JSON + "Panoya Kopyala" butonu).
   - Context / Prompt Bloğu (Doğal dil istemi).

---

### 4.3 Hata Yönetimi ve Uç Durumlar
- **Filtre Sonucu 0 Vaka:** Kullanıcı dostu boş durum kartı (`empty-state`) ve "Filtreleri Temizle" butonu.
- **Geçersiz Sayfa:** `page < 1` ise 1, `page > total_pages` ise son sayfaya kenetlenme.
- **Bozuk JSON / Düz Metin:** `tool_arguments` JSON parse edilemezse doğrudan düz metin olarak güvenle gösterilir.
- **Dosya Hatası:** Parquet bulunamadığında 404 JSON ve UI'da toast uyarısı.

---

### 4.4 Test ve Doğrulama
- **Birim & Entegrasyon Testleri:** `tests/test_api_test_cases.py` dosyası ile API filtreleme, LIMIT/OFFSET ve arama sorgularının doğrulanması.
- **Performans Ölçümü:** Sayfa yüklenme süresinin <30ms olduğunun teyidi.
