# ISSUE-005: Uyuşmazlık (Discrepancy) API'si ve Web UI "Compare Runs" Görünümü

## Parent
[SPEC-0002: Hibrit Güvenlik Motoru (L1/L2) ve Büyük Ölçekli Karşılaştırmalı Benchmark Platformu](../specs/hybrid-guard-and-discrepancy-benchmark-spec.md)

## What to build
İki farklı benchmark koşumunu (örn. Run-L1 vs Run-Laya veya Run-Laya vs Run-Hybrid) mikro-düzeyde karşılaştırmak için SQL tabanlı bir uyuşmazlık (discrepancy) motoru geliştirmek. 10.000 vakanın aynı kararı aldığı satırları filtreleyip, yalnızca iki modelin birbiriyle çeliştiği (Discrepant) vakaları dönen REST endpoint'i (`GET /api/runs/{run_a}/compare/{run_b}`) oluşturmak.

Web arayüzüne **"⚖️ Compare Runs"** sekmesi eklemek:
1. İki koşum seçimi için dinamik açılır listeler.
2. Makro karşılaştırma kartları: Gecikme tasarrufu radarı, F1 ve FPR farkları, Mutabakat Oranı (`Agreement Rate %`).
3. Discrepancy Diff Tablosu: Sayfalanmış (25'erli), zıt kararları listeleyen ve satıra tıklandığında sağdaki Case Detail Drawer ile gönderilen payload'u gösteren interaktif bileşen.

```sql
-- Core Discrepancy Query Pattern (ADR 0004)
SELECT 
    a.case_id, a.domain, a.analysis_tier, a.expected,
    a.predicted_blocked AS run_a_blocked, a.latency_ms AS run_a_latency,
    b.predicted_blocked AS run_b_blocked, b.latency_ms AS run_b_latency
FROM run_case_evaluations a
JOIN run_case_evaluations b ON a.case_id = b.case_id
WHERE a.run_id = ? AND b.run_id = ?
  AND a.predicted_blocked != b.predicted_blocked
LIMIT ? OFFSET ?;
```

## Acceptance criteria
- [x] `GET /api/runs/{run_a}/compare/{run_b}` endpoint'i iki koşumu SQL JOIN ile milisaniyeler içinde kıyaslayıp sayfalanmış uyuşmazlık listesi ve mutabakat yüzdesi döner.
- [x] Web arayüzünde üst navigasyonda **"⚖️ Compare Runs"** sekmesi aktif hale getirilmiştir.
- [x] Birinci kutuda seçilen koşumun dataset'ine göre ikinci kutu (Run B) dinamik olarak filtrelenerek yalnızca **aynı dataseti** kullanan diğer modeller listelenir (kesişim garantisi sağlanmıştır).
- [x] İki koşum seçildiğinde makro metrik kartları (F1 delta, ortalama gecikme farkı, agreement rate, A kaçırdı/B yakaladı) anında hesaplanıp gösterilir.
- [x] Discrepancy tablosunda filtreleme (Tüm Zıtlar / A'nın kaçırıp B'nin yakaladıkları / B'nin kaçırıp A'nın yakaladıkları / FP Ayrışması) çalışır.
- [x] Uyuşmazlık tablosundaki bir satıra tıklandığında sağdaki Case Detail Drawer açılarak her iki modelin kararı yan yana ve vakanın payload içeriği syntax-highlighting ile görüntülenir.

## Blocked by
- [ISSUE-004: 10.000+ Ölçekli DuckDB İlişkisel Depolama (run_case_evaluations)](./ISSUE-004-scalable-duckdb-relational-storage.md) (Done)
