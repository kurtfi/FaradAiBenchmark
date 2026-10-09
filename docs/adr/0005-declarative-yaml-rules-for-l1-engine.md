# ADR 0005: Declarative YAML Rule Architecture for L1 Static Engine

* **Date:** 2026-10-02
* **Status:** Accepted
* **Scope:** Faraday Guard / L1 Static Rule Management

---

## 1. Context and Problem Statement
The L1 Static Inspection Engine is responsible for blocking overt injection signatures (Path Traversal, SQLi, Command Injection) and DLP leaks (API keys, tokens, private keys) at sub-millisecond latencies (<0.2ms).

Hardcoding these signatures inside Python source code:
- Requires code modifications and redeployment for every new signature or pattern update.
- Prevents modular enabling or disabling of rule categories during benchmark runs.
- Limits the portability of security policies across environments.

---

## 2. Decision Log

### Decision: Declarative Rule Packages via `rules/*.yaml`
* **Decision:** Store all static security rules in domain-specific YAML packages under `rules/`:
  - `rules/dlp_secrets.yaml`: API keys, JWTs, AWS tokens, private SSH keys.
  - `rules/command_injection.yaml`: Dangerous command chaining, shell metacharacters, reverse shells.
  - `rules/path_traversal.yaml`: Directory traversal sequences and sensitive system file paths.
  - `rules/sqli.yaml`: Classic SQL injection syntax and tautologies.
* **Compilation & Execution:**
  - Rules are loaded and regular expressions are precompiled via `re.compile` at application startup.
  - Runtime evaluation performs pure in-memory regex matching with zero disk I/O.
* **Alternatives Considered:**
  - *Hardcoded Python Dictionaries:* Rejected due to lack of versioning and dynamic policy governance.
  - *YARA / Hyperscan C Libraries:* Rejected due to unnecessary native C compilation dependencies across Python and Apple Silicon environments.

---

## 3. Consequences
* Introduced the `rules/` directory with standardized YAML schemas.
* Built `L1RuleEngine` to parse, precompile, and evaluate rules via `inspect(tool_name, tool_arguments, context)`.
* Enabled independent, category-scoped benchmarking of static rules.
