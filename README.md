# 🛡️ Faraday Laya Guard: Model-Agnostik Güvenlik Benchmark Boru Hattı

Model Context Protocol (MCP) ve LLM Ajanik güvenlik duvarlarını test etmek, doğrulamak ve kıyaslamak için tasarlanmış yüksek performanslı güvenlik benchmark boru hattı ve **Fail-Fast Cascade** koruma motoru.

---

## 🏛️ Mimari Genel Bakış (Architecture Overview)

Faraday Laya Guard, istekleri iki aşamalı hibrit bir inceleme süzgecinden geçirir:

```mermaid
flowchart TD
    Req([Gelen MCP / LLM Araç Çağrısı<br/>tool_name, tool_arguments, context]) --> L1[L1 Statik & DLP Motoru<br/>Declarative YAML Kuralları & Regex<br/>Gecikme: < 0.2ms]
    
    L1 -->|Kural Eşleşti / İhlal| BlockL1[🛑 ANINDA BLOKE<br/>0 GPU / VRAM Maliyeti]
    L1 -->|Temiz / Belirsiz| L2[L2 Semantik SLM Motoru<br/>Laya-MLX, Qwen, Granite, ShieldGemma<br/>Gecikme: ~15-40ms]
    
    L2 -->|Zararlı Tespit| BlockL2[🛑 BLOKE<br/>Semantik Niyet İhlali]
    L2 -->|Zararsız| Allow[✅ İZİN VERİLDİ<br/>Güvenli Yürütme]

    subgraph RelationalStorage [DuckDB Analitik & Raporlama]
        BlockL1 -.-> DDB[(benchmark_runs.duckdb<br/>run_history & run_case_evaluations)]
        BlockL2 -.-> DDB
        Allow -.-> DDB
    end
```

### Katmanlar ve Bileşenler
1. **L1 Motoru (Statik & DLP - `<0.2ms`):** Bildirimsel (declarative) YAML kuralları üzerinden derlenmiş yüksek hızlı regex motoru (`rules/*.yaml`). Bilinen komut enjeksiyonları (CWE-78), dizin atlama (CWE-22), SQL enjeksiyonları (CWE-89), SSRF (CWE-918) ve hassas anahtar sızıntılarını (DLP) sıfır GPU maliyetiyle anında engeller.
2. **L2 Motoru (Semantik SLM - `~15-40ms`):** Apple Silicon Metal hızlandırmalı (MLX 4-bit) yerel küçük dil modelleri (Laya MLX, Qwen-2.5-Coder, Granite Guardian, Llama Guard 3, ShieldGemma, Prompt Guard). Dolaylı bilgi istemi enjeksiyonlarını (indirect prompt injection) ve semantik iş akışı manipülasyonlarını yakalar.
3. **Fail-Fast Cascade:** Açık saldırıların %60-70'ini L1 aşamasında sonlandırarak L2 SLM üzerindeki GPU/NPU yükünü ve gecikmeyi dramatik şekilde düşürür.
4. **İlişkisel Saklama & Uyuşmazlık Analizi (DuckDB):** Koşu sonuçlarını (`run_history`) ve her bir vaka değerlendirmesini (`run_case_evaluations`) ilişkisel olarak saklar; modeller arası karşılaştırmalı uyuşmazlık (discrepancy) matrisini SQL ile anlık hesaplar.

---

## 🚀 Hızlı Başlangıç (Tek Komutla Ayağa Kaldırma)

Sistemi bağımlılıkları, örnek veri seti ve interaktif web paneliyle birlikte **tek komutla** ayağa kaldırmak için:

```bash
# 1. Ortam değişkenleri şablonunu kopyalayın
cp .env.example .env

# 2. Tek komutla kurun ve web panelini başlatın
make quickstart
```

Dashboard varsayılan olarak **http://localhost:8765** adresinde açılır:
- 📊 **Dashboard:** Gerçek zamanlı benchmark başlatma, canlı WebSocket ilerleme çubuğu, metrik kartları.
- ⚖️ **Compare Runs:** İki modelin karar uyuşmazlıklarını (Model A izin verdi, Model B engelledi) gösteren diferansiyel analiz.
- 🔍 **Test Cases Explorer:** 14.000+ test vakasını CWE, tehdit alanı ve analiz katmanına göre filtreleyen arama çekmecesi.
- 📜 **History:** Geçmiş koşuların performans metrikleri (Accuracy, FPR, F1, P95 Gecikme).

---

## 🛠️ Makefile Komut Referansı

| Komut | Açıklama |
| :--- | :--- |
| `make quickstart` | Bağımlılıkları kontrol eder, 2.000'lik örnek veri setini üretir ve web panelini başlatır. |
| `make setup` | `uv` ile sanal ortam oluşturur ve tüm bağımlılıkları (`pyproject.toml`) kurar. |
| `make download-all` | Tüm ham güvenlik veri setlerini indirir (`data/raw/`). |
| `make transform-all` | Ham verileri standart Parquet formatına dönüştürür (`data/processed/`). |
| `make sample SIZE=2000` | Kıyaslamalar için dengeli örnek Parquet veri seti üretir (`smoke_test_2k.parquet`). |
| `make test-smoke` | 2.000 vakalık duman testi kıyaslamasını çalıştırır. |
| `make test-full` | `master_benchmark.parquet` (14.000+ vaka) üzerinde tam kıyaslama çalıştırır. |
| `make test-unit` | Pytest birim ve entegrasyon testlerini çalıştırır (`tests/`). |
| `make web [PORT=9000]` | Uvicorn + FastAPI dashboard sunucusunu belirtilen portta başlatır. |
| `make clean` | `__pycache__`, pytest ve ruff önbelleklerini temizler. |

---

## ⚙️ Ortam Değişkenleri (.env Referansı)

Aşağıdaki değişkenler `.env` dosyasında yapılandırılabilir (şablon için [`.env.example`](.env.example)):

| Değişken | Varsayılan | Zorunlu? | Açıklama |
| :--- | :--- | :---: | :--- |
| `HF_TOKEN` | - | Koşullu* | Hugging Face gated modeller (Llama Guard 3, ShieldGemma) için API anahtarı. |
| `HUGGING_FACE_HUB_TOKEN` | - | Koşullu* | `HF_TOKEN` alternatifi. |
| `MLX_MEMORY_LIMIT_MB` | `1024` | Hayır | Apple Silicon üzerinde MLX Metal bellek önbellek tavanı (MB). Sızıntıyı önler. |
| `BENCHMARK_DB_PATH` | `data/benchmark_runs.duckdb` | Hayır | DuckDB analitik veritabanı dosya yolu. |
| `MASTER_DATASET_PATH` | `data/processed/master_benchmark.parquet` | Hayır | Birleşik benchmark veri havuzu yolu. |
| `HOST` | `0.0.0.0` | Hayır | Dashboard backend dinleme IP adresi. |
| `PORT` | `8765` | Hayır | Dashboard HTTP ve WebSocket portu. |

---

## 🌐 REST API ve Tip Güvenli OpenAPI Sözleşmesi

Web sunucusu çalıştığında tam OpenAPI (Swagger) dokümantasyonuna **http://localhost:8765/docs** adresinden erişilebilir.

Başlıca uç noktalar:
- `GET /api/datasets` — Kullanılabilir Parquet veri setleri listesi (`List[DatasetItem]`).
- `GET /api/models` — Kayıtlı SLM ve statik güvenlik adapter'ları (`List[ModelItem]`).
- `POST /api/runs` — Yeni kıyaslama koşusu başlatma (`RunCreateRequest` → `RunCreateResponse`).
- `GET /api/runs` — Geçmiş koşu özetleri ve metrikler (`List[RunSummary]`).
- `GET /api/runs/{run_id}` — Koşu detayları ve ilişkisel vaka sonuçları (`RunDetailResponse`).
- `GET /api/runs/{run_a}/compare/{run_b}` — İki koşu arasındaki uyuşmazlık matrisi (`CompareRunsResponse`).
- `DELETE /api/runs/{run_id}` — Koşuyu ve ilişkili tüm değerlendirmeleri silme.
- `GET /api/test-cases/filters` — Test vakaları havuzu filtre üstverileri.
- `GET /api/test-cases` — Sunucu taraflı sayfalanmış test vakaları sorgulama.
- `WS /ws` — Canlı benchmark ilerleme ve log akışı.

---

## 🔌 Model Context Protocol (FastMCP) Entegrasyonu

Faraday Guard bağımsız bir FastMCP sunucusu olarak çalıştırılabilir ve Claude Desktop, Cursor IDE veya Faraday Gateway ile JSON-RPC stdio protokolü üzerinden entegre edilebilir:

### Claude Desktop / Cursor Yapılandırması (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "laya-security-guard": {
      "command": "/bin/sh",
      "args": [
        "-c",
        "cd /Users/firatkurt/Documents/Repos/FaradayLayaBenchmark && .venv/bin/python laya_security_guard_mcp.py"
      ]
    }
  }
}
```

Dışa aktarılan standart araç:
- `inspect_tool_call(tool_name: str, tool_arguments: dict, execution_context: str = "", enable_l1_cascade: bool = False)`
  - Dönüş: `{"verdict": "BLOCKED" | "ALLOWED", "malicious_probability": float, "decision_engine": str, "latency_ms": float}`

---

## 📚 Mimari Karar Kayıtları (ADR) ve Şartnameler

- [ADR 0001: Benchmark Dataset Pipeline & Storage](docs/adr/0001-benchmark-dataset-pipeline-and-storage.md)
- [ADR 0002: Analysis Tier Classification](docs/adr/0002-analysis-tier-classification.md)
- [ADR 0003: Fail-Fast Cascade Hybrid Architecture](docs/adr/0003-fail-fast-cascade-hybrid-architecture.md)
- [ADR 0004: Relational Evaluation Storage & Discrepancy Analysis](docs/adr/0004-relational-evaluation-storage-and-discrepancy-analysis.md)
- [ADR 0005: Declarative YAML Rules for L1 Engine](docs/adr/0005-declarative-yaml-rules-for-l1-engine.md)
- [ADR 0006: Unified Benchmark Case Pool & Parquet Streaming](docs/adr/0006-unified-benchmark-case-pool-and-parquet-streaming.md)
- [ADR 0007: Multi-SLM L2 Adapter & Benchmark Architecture](docs/adr/0007-multi-slm-l2-adapter-and-benchmark-architecture.md)
- [SPEC: Hybrid Guard & Discrepancy Benchmark Specification](docs/specs/hybrid-guard-and-discrepancy-benchmark-spec.md)
- [SPEC: Multi-SLM Evaluation & FastMCP Guard Specification](docs/specs/multi-slm-evaluation-and-mcp-guard-spec.md)
