# Faraday Laya Guard: Issue Tracker & Roadmap

Spesifikasyon [SPEC-0002](../specs/hybrid-guard-and-discrepancy-benchmark-spec.md) kapsamındaki dikey dilimler (Vertical Slices / Tracer Bullets):

| Issue ID | Başlık | Engellenen (Blocked by) | Durum |
| :--- | :--- | :--- | :--- |
| **[ISSUE-001](./ISSUE-001-analysis-tier-schema-and-dataset-normalization.md)** | Analysis Tier Şeması ve Gerçek DLP/Gizlilik Veri Normalizasyonu | *None (Hemen başlanabilir)* | ✅ Done |
| **[ISSUE-002](./ISSUE-002-declarative-l1-static-rule-engine-and-adapter.md)** | Bildirimsel L1 Statik Kural Motoru ve Bağımsız Benchmark Adaptörü | [ISSUE-001](./ISSUE-001-analysis-tier-schema-and-dataset-normalization.md) | ✅ Done |
| **[ISSUE-003](./ISSUE-003-fail-fast-cascade-hybrid-engine.md)** | Kademeli Fail-Fast Hibrit Güvenlik Motoru (HybridCascadeAdapter) | [ISSUE-002](./ISSUE-002-declarative-l1-static-rule-engine-and-adapter.md) | ✅ Done |
| **[ISSUE-004](./ISSUE-004-scalable-duckdb-relational-storage.md)** | 10.000+ Ölçekli DuckDB İlişkisel Depolama (run_case_evaluations) | [ISSUE-003](./ISSUE-003-fail-fast-cascade-hybrid-engine.md) | ✅ Done |
| **[ISSUE-005](./ISSUE-005-discrepancy-api-and-compare-runs-ui.md)** | Uyuşmazlık (Discrepancy) API'si ve Web UI "Compare Runs" Görünümü | [ISSUE-004](./ISSUE-004-scalable-duckdb-relational-storage.md) | ✅ Done |
| **[ISSUE-006](./ISSUE-006-test-cases-dataset-explorer.md)** | Test Cases Explorer — Core Paginated Table & Filters | *None* | ✅ Done |
| **[ISSUE-007](./ISSUE-007-test-cases-drawer-and-deep-linking.md)** | Test Cases Explorer — Case Detail Drawer & Deep-Linking | [ISSUE-006](./ISSUE-006-test-cases-dataset-explorer.md) | ✅ Done |
| **[ISSUE-008](./ISSUE-008-test-cases-search-and-sorting.md)** | Test Cases Explorer — Substring ILIKE Search & Dynamic Sorting | [ISSUE-006](./ISSUE-006-test-cases-dataset-explorer.md) | ✅ Done |

---

### Bağımlılık Zinciri:
```mermaid
graph LR
    ISSUE001[ISSUE-001: Veri Şeması & DLP Normalizasyonu] --> ISSUE002[ISSUE-002: L1 Kural Motoru]
    ISSUE002 --> ISSUE003[ISSUE-003: Hibrit Cascade Adaptör]
    ISSUE003 --> ISSUE004[ISSUE-004: DuckDB İlişkisel Depolama]
    ISSUE004 --> ISSUE005[ISSUE-005: Compare Runs & Discrepancy UI]
    ISSUE001 --> ISSUE006[ISSUE-006: Core Paginated Explorer]
    ISSUE006 --> ISSUE007[ISSUE-007: Drawer & Deep-Linking]
    ISSUE006 --> ISSUE008[ISSUE-008: ILIKE Search & Sorting]
```
