# Context & Domain Model: Farad Ai Benchmark

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
- **`Benchmark Case Pool`**: The unified, single-source repository of all standardized test scenarios (`master_benchmark.parquet`). Rather than fragmented subsets or individual files, all evaluations, exploratory filtering, and distributions are queried against this single consolidated pool using columnar metadata filters (`source_dataset`, `threat_domain`, `analysis_tier`, `is_malicious`).
- **`Run Case Evaluation`**: The granular, relational record of a single test case evaluation within a run (`run_id`, `case_id`, `domain`, `expected`, `predicted`, `correct`, `latency_ms`).
- **`Discrepancy Analysis`**: The differential SQL comparison between two benchmark runs to isolate disagreements (cases where Model A and Model B reached opposite verdicts).

### Declarative Rules & L1
- **`Static Security Rule`**: A declarative specification formatted in YAML containing regex match patterns, threat domain mappings, CWE IDs, and description.
- **`Compiled Rule Engine`**: The high-throughput in-memory engine that compiles declarative YAML regex rules on startup to perform sub-millisecond evaluation (<0.2ms).

### Multi-SLM & Adapter Architecture
- **`Security Model Adapter`**: The unified abstraction implementing standard parameter evaluation (`evaluate(tool_name, tool_arguments, context) -> Dict`) across heterogeneous SLMs (Laya, Qwen3Guard, Granite Guardian, Llama Guard, ShieldGemma, Prompt Guard).
- **`Decision Model (System 1 / Non-Autoregressive)`**: A class of models (e.g. Laya, Kev) that evaluate a document/state and typed questions (`choice`, `noul`, `score`) in a single forward pass without token-by-token text generation. They output calibrated probabilities directly, providing low latency (<25ms) and deterministic boolean decisions.
- **`Fair Quantization Baseline`**: Standardized 4-bit quantization (MLX 4-bit / Q4_K_M) enforced across generative SLMs to ensure unified memory footprint (~1.2-2.0 GB) and hardware latency parity on Apple Silicon. For ultra-lightweight decision models (Kev-0.8B), 4-bit quantization enforces a sub-1GB RAM footprint (~500-700 MB).
- **`Guard MCP Factory`**: The shared builder pattern that wraps any `SecurityModelAdapter` into an independent, zero-flag FastMCP server exposing the uniform `inspect_tool_call` tool contract.
- **`Comparative Leaderboard Run`**: The two-phased benchmark execution workflow (200-case smoke test followed by 2000+ full pool evaluation) generating side-by-side accuracy, FPR, and latency metrics across all registered adapters.

