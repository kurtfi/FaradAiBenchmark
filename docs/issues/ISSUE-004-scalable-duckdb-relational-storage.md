# ISSUE-004: 10.000+ Ölçekli DuckDB İlişkisel Depolama (run_case_evaluations)

## Parent
[SPEC-0002: Hibrit Güvenlik Motoru (L1/L2) ve Büyük Ölçekli Karşılaştırmalı Benchmark Platformu](../specs/hybrid-guard-and-discrepancy-benchmark-spec.md)

## What to build
Benchmark koşumlarında 10.000+ test vakasının bellek ve disk şişmesi olmadan saklanabilmesi ve hızlı sorgulanabilmesi için DuckDB şemasını iki ilişkisel tabloya ayırmak:
1. `run_history`: Koşum bazında makro metrikleri (F1, Precision, Recall, FPR, Latency, Category Stats) saklar.
2. `run_case_evaluations`: Her bir test vakasının bireysel sonucunu ilişkisel olarak saklar (`run_id, case_id, domain, analysis_tier, is_malicious, predicted_blocked, correct, decided_by, confidence, latency_ms`).

`web/app.py` benchmark yürütme motorunu, koşum bittiğinde tüm vaka sonuçlarını `run_case_evaluations` tablosuna yüksek hızlı toplu yazma (bulk insert) yapacak şekilde güncellemek.

```sql
-- Schema Reference (ADR 0004)
CREATE TABLE IF NOT EXISTS run_case_evaluations (
    run_id              VARCHAR NOT NULL,
    case_id             VARCHAR NOT NULL,
    domain              VARCHAR NOT NULL,
    analysis_tier       VARCHAR NOT NULL,
    is_malicious        BOOLEAN NOT NULL,
    predicted_blocked   BOOLEAN NOT NULL,
    correct             BOOLEAN NOT NULL,
    decided_by          VARCHAR NOT NULL,
    confidence          DOUBLE DEFAULT 0,
    latency_ms          DOUBLE DEFAULT 0,
    PRIMARY KEY (run_id, case_id)
);
CREATE INDEX IF NOT EXISTS idx_case_eval_lookup ON run_case_evaluations (run_id, correct);
```

## Acceptance criteria
- [x] `run_case_evaluations` tablosu DuckDB veritabanında oluşturulmuş ve indekslenmiştir (`idx_case_eval_lookup`).
- [x] `web/app.py` benchmark motoru her koşum sonunda tüm değerlendirme satırlarını PyArrow vektörel tablosu ile bu tabloya toplu aktarır.
- [x] 10.000 satırlık bir test kümesi tamamlandığında toplu yazma süresi 1 saniyenin altındadır (PyArrow ile ~66ms ölçülmüştür, 15x SLA marjı).
- [x] Geçmiş koşum silindiğinde (`DELETE /api/runs/{id}`) ilişkili tüm `run_case_evaluations` satırları da temizlenir (Unit test ile doğrulandı).
- [x] `/api/runs/{id}` endpoint'i geriye uyumlu kalarak vaka örneklerini bu tablodan dinamik olarak okur.

## Blocked by
- [ISSUE-003: Kademeli Fail-Fast Hibrit Güvenlik Motoru (HybridCascadeAdapter)](./ISSUE-003-fail-fast-cascade-hybrid-engine.md) (Done)
