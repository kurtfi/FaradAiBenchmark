# Mühendislik Spesifikasyonu: Hibrit Güvenlik Motoru (L1/L2) ve Büyük Ölçekli Karşılaştırmalı Benchmark Platformu

* **Belge No:** SPEC-0002
* **Tarih:** 2026-10-02
* **Durum:** Onaylandı (Approved / Ready for Implementation)
* **Kapsam:** Faz 1 (Veri Ayrıştırma & DLP), Faz 2 (L1 Statik + L2 Semantik Hibrit Motor), Faz 3 (10K+ Ölçekli Discrepancy Analizi)
* **İlişkili ADR'ler:** ADR 0001, ADR 0002, ADR 0003, ADR 0004, ADR 0005

---

## 1. Yönetici Özeti ve Hedefler (Executive Summary & Goals)

### 1.1 Proje Amacı
Faraday Laya Guard, LLM (Büyük Dil Modelleri) ve MCP (Model Context Protocol) araçları arasındaki haberleşmede veri sızıntılarını (DLP), kod/komut enjeksiyonlarını ve yetkisiz ajan eylemlerini denetleyen yüksek başarımlı bir güvenlik katmanıdır. 

Bu spesifikasyon, **statik deterministik kurallar (L1)** ile **semantik yerel küçük dil modelleri (L2 / Laya MLX)** arasındaki performans, gecikme ve doğruluk farklarını 10.000+ ölçekli test kümeleri üzerinde bilimsel ve tekrarlanabilir biçimde ölçmeyi hedefler.

### 1.2 Temel Mühendislik Hedefleri
1. **İki Kademeli Kademeli (Fail-Fast Cascade) Motor:** Bariz saldırıların ve DLP sızıntılarının %80+'sini CPU üzerinde mikrosaniyede (<0.2ms) L1 kural motoruyla eleyerek, L2 (Laya MLX - GPU) çıkarım yükünü ve ortalama gecikmeyi %70-80 oranında düşürmek.
2. **Gerçek MCP/Ajan Veri Tabanı:** Sentetik veri üretmeksizin, yerelde mevcut olan `MCPTox` (RQ3: Privacy Middleware) ve `AgentDojo` (Ajan veri kaçırma senaryoları) repolarından gerçek DLP ve gizlilik testlerini normalize etmek.
3. **Analiz Katmanı Sınıflandırması (`analysis_tier`):** Test verilerini `STATIC_CAPABLE`, `SEMANTIC_REQUIRED` ve `HYBRID` olarak etiketleyerek modellerin yetenek sınırlarını izole etmek.
4. **10.000+ Ölçekli Uyuşmazlık (Discrepancy) Analizi:** Büyük veri kümelerinde tüm sonuçları ekrana basmak yerine, DuckDB ilişkisel SQL JOIN ile yalnızca iki modelin birbiriyle çeliştiği vakaları (Discrepancies) anlık filtreleyen hafif bir web arayüzü sunmak.

---

## 2. Sistem Mimarisi ve Bileşenler (System Architecture)

```
                                  [ MCP Tool Call İsteği ]
                                              │
                                              ▼
                        ┌───────────────────────────────────────────┐
                        │   L1 Compiled Rule Engine (rules/*.yaml)  │
                        │   - dlp_secrets.yaml                      │
                        │   - command_injection.yaml                │
                        │   - path_traversal.yaml                   │
                        │   - sqli.yaml                             │
                        └───────────────────────────────────────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      │ (Eşleşme: BLOCKED)                            │ (Temiz / Şüphesiz: ALLOWED)
                      ▼                                               ▼
          🛑 BLOCKED (Decided by L1)                    ┌──────────────────────────────┐
          - Latency: < 0.2ms                            │  L2 Semantic Engine          │
          - Reason: STATIC_RULE_MATCH                   │  - Laya MLX (Apple Silicon)  │
          - GPU Load: 0                                 │  - Contextual Intent & OWASP │
                                                        └──────────────────────────────┘
                                                                      │
                                                      ┌───────────────┴───────────────┐
                                                      ▼                               ▼
                                          🛑 BLOCKED (Decided by L2)      ✅ ALLOWED (Decided by L2)
                                          - Latency: ~15-20ms             - Latency: ~15-20ms
                                          - Confidence: Score             - Confidence: Score
                                                      │                               │
                                                      └───────────────┬───────────────┘
                                                                      ▼
                                                ┌───────────────────────────────────────────┐
                                                │        DuckDB Relational Storage          │
                                                │  - run_history (Aggregated Metrics)       │
                                                │  - run_case_evaluations (Row-level cases) │
                                                └───────────────────────────────────────────┘
                                                                      │
                                                                      ▼
                                                ┌───────────────────────────────────────────┐
                                                │   Web UI: Compare Runs (Discrepancy Diff) │
                                                │   - L1 vs L2 vs Hybrid Macro Stats        │
                                                │   - Discrepancy Table (Model A != B)      │
                                                └───────────────────────────────────────────┘
```

---

## 3. Mimari Karar Kayıtları İndeksi (ADR Index)

* **[ADR 0001: Model-Agnostik Benchmark Boru Hattı](file:///Users/firatkurt/Documents/Repos/faraday-laya-guard/docs/adr/0001-benchmark-dataset-pipeline-and-storage.md):** Parquet depolama ve in-memory DuckDB sorgulama standardı.
* **[ADR 0002: Şemada Analiz Katmanı Sınıflandırması](file:///Users/firatkurt/Documents/Repos/faraday-laya-guard/docs/adr/0002-analysis-tier-classification.md):** `analysis_tier` alanının (`STATIC_CAPABLE`, `SEMANTIC_REQUIRED`, `HYBRID`) eklenmesi.
* **[ADR 0003: Fail-Fast Kademeli Hibrit Mimari](file:///Users/firatkurt/Documents/Repos/faraday-laya-guard/docs/adr/0003-fail-fast-cascade-hybrid-architecture.md):** İsteklerin önce L1'e girip ihlal anında GPU'ya gitmeden kesilmesi.
* **[ADR 0004: İlişkisel Değerlendirme Depolaması ve Discrepancy Analizi](file:///Users/firatkurt/Documents/Repos/faraday-laya-guard/docs/adr/0004-relational-evaluation-storage-and-discrepancy-analysis.md):** 10K+ vaka için `run_case_evaluations` tablosu ve SQL tabanlı uyuşmazlık sorgulama.
* **[ADR 0005: Bildirimsel YAML Kural Mimarisi](file:///Users/firatkurt/Documents/Repos/faraday-laya-guard/docs/adr/0005-declarative-yaml-rules-for-l1-engine.md):** L1 kurallarının `rules/*.yaml` dosyalarında yönetilmesi ve başlangıçta derlenmesi.

---

## 4. Veri Modelleri ve API Kontratları (Data Models & API Contracts)

### 4.1 Parquet Veri Seti Şeması (Güncellenmiş)
```python
BENCHMARK_SCHEMA = pa.schema([
    ("id", pa.string()),
    ("source_dataset", pa.string()),      # SecLists, MCPTox, AgentDojo, PayloadsAllTheThings, vb.
    ("traffic_direction", pa.string()),  # tools/call
    ("threat_domain", pa.string()),      # COMMAND_INJECTION, SQLI, PATH_TRAVERSAL, DATA_LEAK, AGENTIC_RISK, BENIGN
    ("analysis_tier", pa.string()),      # STATIC_CAPABLE | SEMANTIC_REQUIRED | HYBRID  [ADR 0002]
    ("cwe", pa.string()),                # CWE-78, CWE-89, CWE-22, CWE-532, vb.
    ("owasp_llm", pa.string()),          # LLM01, LLM06, LLM08, NONE
    ("tool_name", pa.string()),          # execute_bash, post_webhook, read_file, vb.
    ("tool_arguments", pa.string()),     # JSON serialized string
    ("context", pa.string()),            # Çağrı senaryosu / bağlam metni
    ("is_malicious", pa.bool_()),        # True: Saldırı / Sızıntı, False: Meşru
])
```

### 4.2 DuckDB İlişkisel Şeması [ADR 0004]

#### Tablo 1: `run_history` (Makro Koşum Kayıtları)
```sql
CREATE TABLE IF NOT EXISTS run_history (
    run_id          VARCHAR PRIMARY KEY,
    dataset_name    VARCHAR NOT NULL,
    dataset_path    VARCHAR NOT NULL,
    model_name      VARCHAR NOT NULL,        -- l1-rules | laya-mlx | hybrid-cascade
    status          VARCHAR NOT NULL,        -- pending | running | completed | error
    total_cases     INTEGER DEFAULT 0,
    evaluated       INTEGER DEFAULT 0,
    tp              INTEGER DEFAULT 0,
    tn              INTEGER DEFAULT 0,
    fp              INTEGER DEFAULT 0,
    fn              INTEGER DEFAULT 0,
    accuracy        DOUBLE DEFAULT 0,
    precision_val   DOUBLE DEFAULT 0,
    recall_val      DOUBLE DEFAULT 0,
    f1_score        DOUBLE DEFAULT 0,
    fpr             DOUBLE DEFAULT 0,
    avg_latency_ms  DOUBLE DEFAULT 0,
    p95_latency_ms  DOUBLE DEFAULT 0,
    category_stats  VARCHAR DEFAULT '{}',    -- JSON string
    started_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at    TIMESTAMP,
    duration_secs   DOUBLE DEFAULT 0
);
```

#### Tablo 2: `run_case_evaluations` (Vaka Düzeyinde Sonuçlar - 10K+ Destekli)
```sql
CREATE TABLE IF NOT EXISTS run_case_evaluations (
    run_id              VARCHAR NOT NULL,
    case_id             VARCHAR NOT NULL,
    domain              VARCHAR NOT NULL,
    analysis_tier       VARCHAR NOT NULL,
    is_malicious        BOOLEAN NOT NULL,
    predicted_blocked   BOOLEAN NOT NULL,
    correct             BOOLEAN NOT NULL,
    decided_by          VARCHAR NOT NULL,     -- L1 | L2
    confidence          DOUBLE DEFAULT 0,
    latency_ms          DOUBLE DEFAULT 0,
    PRIMARY KEY (run_id, case_id)
);
CREATE INDEX IF NOT EXISTS idx_case_eval_lookup ON run_case_evaluations (run_id, correct);
```

### 4.3 REST API Kontratları

#### 1. Uyuşmazlık (Discrepancy) Karşılaştırma API'si
* **Endpoint:** `GET /api/runs/{run_id_a}/compare/{run_id_b}`
* **Query Parametreleri:**
  - `page` (default: 1)
  - `limit` (default: 25)
  - `filter`: `all_diff` | `a_blocked_b_allowed` | `b_blocked_a_allowed` | `both_failed`
* **Response:**
```json
{
  "run_a": { "id": "run-l1", "model": "L1 Static Rules", "f1": 68.4, "avg_latency": 0.08 },
  "run_b": { "id": "run-laya", "model": "Laya MLX", "f1": 94.1, "avg_latency": 17.5 },
  "agreement_summary": {
    "total_compared": 10000,
    "matching_verdicts": 8650,
    "discrepancies": 1350,
    "agreement_rate_pct": 86.5
  },
  "discrepancies": [
    {
      "case_id": "mcptox-priv-00042",
      "domain": "DATA_LEAK",
      "analysis_tier": "SEMANTIC_REQUIRED",
      "expected_blocked": true,
      "run_a_predicted": false,
      "run_a_latency_ms": 0.07,
      "run_b_predicted": true,
      "run_b_latency_ms": 16.4,
      "verdict_discrepancy": "B_CAUGHT_A_MISSED"
    }
  ],
  "pagination": { "page": 1, "limit": 25, "total_diffs": 1350 }
}
```

---

## 5. L1 Kural Motoru Formatı (`rules/*.yaml`) [ADR 0005]

Örnek Kural Dosyası (`rules/dlp_secrets.yaml`):
```yaml
version: "1.0"
category: "DLP_SECRETS"
rules:
  - id: "DLP-OPENAI-KEY"
    name: "OpenAI Secret Key Leakage"
    threat_domain: "DATA_LEAK"
    cwe: "CWE-532"
    severity: "HIGH"
    regex: "(?:sk-proj-|sk-live-|sk-)[a-zA-Z0-9_-]{20,}"
    description: "Detects exposed OpenAI API secret keys in tool arguments."

  - id: "DLP-AWS-ACCESS-KEY"
    name: "AWS Access Key ID"
    threat_domain: "DATA_LEAK"
    cwe: "CWE-532"
    severity: "CRITICAL"
    regex: "(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    description: "Detects AWS Access Keys."

  - id: "DLP-PRIVATE-KEY"
    name: "RSA/EC Private Key Header"
    threat_domain: "DATA_LEAK"
    cwe: "CWE-532"
    severity: "CRITICAL"
    regex: "-----BEGIN [A-Z ]+PRIVATE KEY-----"
    description: "Detects private cryptographic keys in parameters."
```

---

## 6. Kullanıcı Deneyimi ve Arayüz Akışları (Frontend Workflows)

### 6.1 Yeni "Compare Runs" Sekmesi
1. Kullanıcı üst menüden **"⚖️ Compare Runs"** butonuna tıklar.
2. Açılan sayfada iki açılır kutudan (Select Run A ve Select Run B) geçmiş koşumlar seçilir (örn. *Run-01: L1 Static* vs *Run-02: Laya MLX*).
3. **Kıyaslama Kartları:**
   - **Gecikme & Kaynak Radarı:** L1 (0.08ms) vs Laya MLX (17.5ms) vs Hibrit (3.1ms - %82 tasarruf).
   - **Doğruluk Matrisi:** F1 Skoru, FPR (False Positive Rate) ve Doğruluk farkları.
4. **Discrepancy (Uyuşmazlık) Tablosu:**
   - Yalnızca iki modelin çeliştiği satırlar listelenir.
   - Satıra tıklandığında sağdaki mevcut **Case Detail Drawer** açılarak gönderilen `tool_arguments` JSON'ı ve iki modelin neden farklı karar verdiği incelenir.

---

## 7. Uygulama Fazları ve Kabul Kriterleri (Implementation Plan)

### Faz 1: Veri Kümesi Ayrıştırma ve Gerçek DLP/Gizlilik Entegrasyonu
- [ ] `BENCHMARK_SCHEMA` şemasına `analysis_tier` kolonu eklenmesi.
- [ ] `data/raw/mcptox` (RQ3: Privacy Middleware) analiz edilerek gerçek MCP veri sızıntısı senaryolarının ayıklanması.
- [ ] `data/raw/agentdojo` loglarından ajanın yetkisiz tool çağırma ve veri kaçırma vakalarının ayıklanması.
- [ ] `transform_to_parquet.py` güncellenerek `dlp_secrets.parquet` ve `agent_privacy.parquet` üretilmesi.
- [ ] **Kabul Kriteri:** DuckDB ile `SELECT analysis_tier, count(*) FROM master_benchmark.parquet GROUP BY 1` sorgusunun doğru dağılım üretmesi.

### Faz 2: L1 Statik Kural Motoru ve Kademeli Hibrit (Cascade) Adaptör
- [ ] `rules/` klasörü ve ilk kural setlerinin (`dlp_secrets.yaml`, `command_injection.yaml`, `path_traversal.yaml`, `sqli.yaml`) hazırlanması.
- [ ] `L1RuleEngine` sınıfının kodlanması (başlangıçta regex derleme, microsecond latency benchmark).
- [ ] `HybridCascadeAdapter` sınıfının `benchmark_runner.py` içine eklenmesi.
- [ ] **Kabul Kriteri:** Bir test kümesinde L1'in ortalama gecikmesinin `<0.2ms` olması; Hibrit modda bariz saldırıların L2'ye gitmeden L1 tarafından bloklanması.

### Faz 3: 10K+ İlişkisel Depolama ve Web Uyuşmazlık (Discrepancy) Ekranı
- [ ] `web/app.py` içinde DuckDB şemasına `run_case_evaluations` tablosunun eklenmesi.
- [ ] Benchmark tamamlandığında vaka sonuçlarının bu tabloya toplu (bulk insert) yazılması.
- [ ] `/api/runs/{run_a}/compare/{run_b}` uyuşmazlık endpoint'inin kodlanması.
- [ ] Web arayüzüne **"Compare Runs"** sayfası ve uyuşmazlık filtreleme tablosunun eklenmesi.
- [ ] **Kabul Kriteri:** 10.000 satırlık iki koşumun 1 saniyenin altında kıyaslanması ve tarayıcıda akıcı biçimde incelenebilmesi.
