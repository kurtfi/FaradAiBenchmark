# ISSUE-007: Test Cases Explorer — Case Detail Drawer & Deep-Linking

## Parent
- **Specification:** [SPEC-0003: Unified Test Cases Dataset Explorer](../specs/test-cases-explorer-spec.md)
- **Architectural Decision:** [ADR 0006: Unified Benchmark Case Pool and Streaming Parquet Exploration](../adr/0006-unified-benchmark-case-pool-and-parquet-streaming.md)

## What to build
Connect the slide-in detail panel (`.case-detail-drawer`) to display full prompt contexts and formatted JSON tool arguments when clicking on any test case row, and implement URL Hash Deep-Linking for bookmarkable, shareable case links.

This vertical slice encompasses:
1. **Case Detail Drawer Interaction (`web/static/app.js`, `web/static/index.css`):**
   - Clicking any table row opens `.case-detail-drawer.open` from the right edge.
   - Header displays Case ID, Safety Status Badge (`🚨 Threat` / `🛡️ Safe`), CWE ID, OWASP LLM category, and Analysis Tier.
   - `tool_arguments` section: Pretty-printed, syntax-highlighted JSON block with a "📋 Copy" button that copies the raw payload to the clipboard with animated confirmation.
   - `context` section: Formatted natural language user prompt and conversational context.
   - Smooth dismissibility via close button (`✕`), overlay backdrop click, or pressing the `Escape` key.
2. **URL Hash Deep-Linking:**
   - Active page, pagination, and filter changes update the browser URL hash dynamically (`#test-cases?page=2&status=malicious`).
   - Opening a case drawer appends the case ID to the hash (`#test-cases?id=seclists-cmd-000042`).
   - Loading or refreshing the page with a hash link automatically navigates to the `Test Cases` tab, applies the filters, and opens the specified case drawer.

## Status: DONE ✅

## Acceptance criteria
- [x] Clicking any table row opens the `.case-detail-drawer` with smooth CSS transition.
- [x] Valid JSON `tool_arguments` are formatted with indentation; malformed payloads fallback gracefully to safe plain text.
- [x] Clicking "Copy" copies the payload to clipboard and displays transient visual feedback.
- [x] Opening a case updates the URL hash to `#test-cases?id=<case_id>`.
- [x] Visiting a direct URL with hash `#test-cases?id=...` opens the page and drawer automatically.
- [x] Closing the drawer (via `✕`, overlay click, or `Escape`) clears the case ID from the hash.

## Blocked by
- [ISSUE-006: Test Cases Explorer — Core Paginated Table & Filters](./ISSUE-006-test-cases-dataset-explorer.md) (Done)
