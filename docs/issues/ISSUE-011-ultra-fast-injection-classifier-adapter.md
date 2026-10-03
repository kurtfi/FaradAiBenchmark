# ISSUE-011: Ultra-Fast Injection Classifier Adapter (Prompt-Guard-86M)

## Parent
- **Specification:** [SPEC-0004: Multi-SLM L2 Adapters, FastMCP Factory, and Comparative Benchmark Architecture](../specs/multi-slm-evaluation-and-mcp-guard-spec.md)
- **Architectural Decision:** [ADR 0007: Multi-SLM L2 Adapters and Comparative Benchmark Architecture](../adr/0007-multi-slm-l2-adapter-and-benchmark-architecture.md)

## What to build
Implement an ultra-low-latency classification adapter using `Meta Prompt-Guard-86M` running natively on Apple Silicon Metal (MPS via PyTorch) to detect indirect prompt injections and jailbreaks inside tool call argument payloads in under 6 milliseconds.

This vertical slice includes:
1. **Prompt Guard Adapter (`adapters/prompt_guard_adapter.py`):**
   - Load `meta-llama/Prompt-Guard-86M` (or local weights) using Hugging Face Transformers with PyTorch `mps` hardware acceleration.
   - Stringify structured `tool_arguments` JSON and extract embeddings/logits.
   - Compute softmax across `BENIGN`, `INJECTION`, and `JAILBREAK` classes.
   - Map maximum adversarial class probability directly to `confidence` score.
2. **Benchmark Runner Integration:**
   - Register `prompt-guard` in `benchmark_runner.py`.
   - Measure sub-6ms latency on Apple Silicon M-series.

## Status: READY FOR IMPLEMENTATION ⏳

## Acceptance criteria
- [ ] `PromptGuardAdapter` loads the 86M classifier on Apple Silicon MPS device.
- [ ] Correctly flags indirect prompt injection strings embedded in tool argument JSON payloads.
- [ ] Achieves average compute latency of < 6ms on Apple Silicon.
- [ ] Outputs standard `is_blocked`, `confidence`, and `verdict` contract.
- [ ] Unit tests verify detection of injection vs benign commands.

## Blocked by
- [ISSUE-009: Decoupled Adapter Core & Qwen2.5-Coder Model Adapter](./ISSUE-009-decoupled-adapter-core-and-qwen-coder-adapter.md)
