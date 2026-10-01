# Context & Domain Model: Faraday Laya Guard

Glossary and ubiquitous language for the benchmark and evaluation platform.

### Analysis Tier
The classification of an inspection target based on the computational mechanism required to detect threats:
- **`STATIC_CAPABLE`**: Threats or patterns that can be detected deterministically via low-latency pattern matching, regex rules, keyword blacklists, or structured DLP checks (e.g., known path traversal strings, raw SQL syntax, secret tokens).
- **`SEMANTIC_REQUIRED`**: Threats that inherently depend on contextual understanding, natural language reasoning, intent analysis, or multi-turn conversational hijacking (e.g., indirect prompt injection, social engineering, role manipulation).
- **`HYBRID`**: Threats where overt variations can be caught by static rules, but evasive or obfuscated variants require semantic reasoning.

### Threat Domain
The security taxonomy category representing the attack vector (e.g., `COMMAND_INJECTION`, `PATH_TRAVERSAL`, `SQLI`, `SSRF`, `INDIRECT_PROMPT_INJECTION`, `DATA_LEAK`).

### DLP (Data Loss Prevention)
The detection, masking, or prevention of unauthorized transmission of sensitive information (PII, credentials, access keys, private certificates) between the LLM and MCP tools.
- **`Outbound DLP`**: The inspection of arguments emitted by the LLM (`tool_arguments`) before execution by an MCP server to prevent exfiltration.

### Engine Tiers & Pipeline
- **`L1 Engine (Static / DLP)`**: Deterministic inspection layer executing pattern matching, regular expressions, and signature rules in microseconds (<1ms).
- **`L2 Engine (Semantic / SLM)`**: Natural language intent and contextual inspection layer executing local small language models (Laya MLX) in milliseconds (~15-40ms).
- **`Fail-Fast Cascade`**: The orchestration pattern where requests pass through L1 first; immediate violations are blocked at L1 with zero GPU/SLM overhead, and only clean/inconclusive requests cascade to L2.

### Benchmark Storage & Comparison
- **`Run Case Evaluation`**: The granular, relational record of a single test case evaluation within a run (`run_id`, `case_id`, `domain`, `expected`, `predicted`, `correct`, `latency_ms`).
- **`Discrepancy Analysis`**: The differential SQL comparison between two benchmark runs to isolate disagreements (cases where Model A and Model B reached opposite verdicts).

### Declarative Rules & L1
- **`Static Security Rule`**: A declarative specification formatted in YAML containing regex match patterns, threat domain mappings, CWE IDs, and description.
- **`Compiled Rule Engine`**: The high-throughput in-memory engine that compiles declarative YAML regex rules on startup to perform sub-millisecond evaluation (<0.2ms).
