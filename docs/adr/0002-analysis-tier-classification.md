# ADR 0002: Analysis Tier Classification in Benchmark Test Data Schema

* **Date:** 2026-10-01
* **Status:** Accepted
* **Scope:** Faraday Guard / Data Schema & Tiered Inspection

---

## 1. Context & Problem Statement
Faraday Laya Guard evaluates both sub-millisecond deterministic static rules (L1: Regex, DLP, Pattern Matching) and contextual natural language reasoning models (L2: Semantic SLM / Laya MLX).

The legacy schema (`id, source_dataset, threat_domain, cwe, tool_name, tool_arguments, context, is_malicious`) lacked information regarding the computational mechanism necessary to detect each threat. Conflating trivial syntax patterns with complex indirect prompt injections obscured objective detection accuracy and latency evaluation.

---

## 2. Decision Log

### Decision: Adding the `analysis_tier` Column to the Benchmark Schema
* **Decision:** Add the `analysis_tier` column to the Parquet schema and data normalization pipeline. Every record receives one of three standardized values:
  1. `STATIC_CAPABLE`: Threats deterministically detectable via static signature matching, regex rules, or structured DLP checks (e.g., standard SQLi, path traversal, known tokens).
  2. `SEMANTIC_REQUIRED`: Threats that inherently depend on contextual understanding, natural language reasoning, intent analysis, or multi-turn conversational hijacking (e.g., indirect prompt injection, agent manipulation, social engineering).
  3. `HYBRID`: Threats where overt variations can be caught by static rules, but evasive or obfuscated variants require semantic reasoning.
* **Alternatives Considered:**
  - *Domain-based static grouping:* Assuming SQLi is always static and Injection is always semantic (rejected: embedded SQL within benign prompts behaves contextually).
  - *Dynamic/Unlabeled:* Leaving data untagged and measuring only runtime outcomes (rejected: prevents measuring the theoretical capability distribution of the test pool).
* **Rationale:**
  - Objectively delineates the capability boundaries of L1 (Static) versus L2 (Semantic) engines.
  - Enables granular reporting: "What percentage of threats did L1 offload before reaching L2?" and "How did L2 perform on purely semantic cases?"

---

## 3. Consequences
* Normalization scripts populate the `analysis_tier` field based on dataset taxonomy.
* Benchmark runner and web dashboard support filtering and comparing results across analysis tiers.
