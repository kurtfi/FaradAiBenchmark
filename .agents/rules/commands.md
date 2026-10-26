# Addy Osmani Engineering Lifecycle Slash Commands

This rule file enables the Antigravity Agent to recognize and execute Addy Osmani's `agent-skills` lifecycle commands (`/spec`, `/plan`, `/build`, `/test`, `/review`, `/ship`, `/constraints`, `/code-simplify`, `/perf`) directly from the chat interface.

Whenever a user message starts with or includes one of these commands, the agent strictly follows the corresponding skill instructions and lifecycle phases.

---

## 1. `/spec` — Spec-Driven Development
**Skill:** `spec-driven-development` (combined with `interview-me` if requirements are underspecified)  
**Purpose:** Create a structured specification / PRD before writing any code.

### Guidelines & Workflow (Addy's `/spec`):
1. **Ask Clarifying Questions:** Do not write code without fully understanding user intent. Ask targeted questions across 4 core areas:
   - Objective and target users
   - Core features and acceptance criteria
   - Preferred tech stack and constraints
   - Known boundaries (what to always do, ask first about, and never do)
2. **Capability Map:** If the request bundles multiple independently testable modules, first propose a capability map (module IDs, dependency direction, build order) and secure user approval.
3. **Generate the Spec Document:** Create a structured spec covering 6 core sections:
   - Objective
   - Commands & Usage
   - Project Structure
   - Code Style & Conventions
   - Testing Strategy
   - Boundaries & Security
4. Save the spec as `SPEC.md` in the project root and confirm with the user before proceeding to implementation.

---

## 2. `/plan` — Planning & Task Breakdown
**Skill:** `planning-and-task-breakdown`  
**Purpose:** Decompose work into small, atomic, verifiable tasks with explicit dependency ordering.

### Guidelines & Workflow (Addy's `/plan`):
1. Read the existing `SPEC.md` and relevant codebase sections.
2. **Plan Mode:** Stay in read-only mode — make no code modifications.
3. Map the dependency graph between components.
4. **Vertical Slicing:** Slice work into thin, end-to-end functional slices rather than horizontal technical layers (e.g., avoid "all DB first, then all API, then all UI").
5. Define each task with concrete acceptance criteria, files to touch, and verification commands.
6. Save the implementation plan to `docs/tickets/plan.md` and the granular checklist to `docs/tickets/todo.md`.
7. Stop and await human approval before any implementation begins.

---

## 3. `/build` & `/build auto` — Incremental Implementation
**Skill:** `incremental-implementation` + `test-driven-development`  
**Purpose:** Implement tasks in thin vertical slices driven by TDD cycles.

### Execution Modes:
- **`/build` (Default — Single Task):**
  1. Pick the next pending task from `tasks/todo.md`.
  2. Load the task's acceptance criteria and relevant codebase context.
  3. **RED:** Write a failing test for the expected behavior.
  4. **GREEN:** Implement the minimal code necessary to pass the test.
  5. Run the full test suite and build compilation to verify no regressions.
  6. Commit changes with a descriptive, atomic commit message.
  7. Mark the task complete in `tasks/todo.md` and stop.

- **`/build auto` (Autonomous Full-Plan Completion):**
  1. A spec is strictly required (`SPEC.md`). If none exists, direct the user to run `/spec` first.
  2. Verify a clean workspace via `git status`.
  3. Generate the plan if missing and obtain a single batch approval.
  4. Execute each task sequentially using the RED-GREEN-REFACTOR cycle without human intervention between tasks.

---

## 4. `/test` — Test-Driven Development & Bug Reproducing
**Skill:** `test-driven-development`  
**Purpose:** Treat tests as definitive proof of correctness, not assumptions.

### Guidelines & Workflow (Addy's `/test`):
- **For New Features:**
  1. Write tests describing the expected behavior first (tests MUST fail initially).
  2. Implement minimal code to make them pass.
  3. Refactor while keeping all tests green.
- **For Bug Fixes ("Prove-It" Pattern):**
  1. Write a test that reproduces the bug exactly (the test MUST fail first).
  2. Fix the bug with the minimal required code change.
  3. Verify the test turns green with zero regressions across the test suite.

---

## 5. `/review` — Code Review & Quality Gates
**Skill:** `code-review-and-quality`  
**Purpose:** Conduct a rigorous multi-axis review before merging code.

### Guidelines & Workflow (Addy's `/review`):
Inspect recent changes across 5 primary dimensions:
1. **Correctness:** Does the code behave as expected? Are boundary conditions and edge cases properly handled?
2. **Standards:** Does it conform to repository architecture, type safety, and language idioms?
3. **Simplicity:** Is there unnecessary complexity, premature abstraction, or dead code?
4. **Security:** Are inputs validated, authorizations enforced, and least-privilege principles applied?
5. **Test Quality:** Do tests verify behavior rather than implementation details?

Group findings strictly by severity: **[Blocker]**, **[Warning]**, **[Suggestion]**.

---

## 6. `/ship` — Shipping & Production Readiness
**Skill:** `shipping-and-launch`  
**Purpose:** Safely prepare changes for production deployment and release.

### Guidelines & Workflow (Addy's `/ship`):
1. **Test & Lint Verification:** Run all test suites, linters, and type checkers.
2. **Build Verification:** Verify that compilation and packaging succeed without errors.
3. **Backward Compatibility:** Review database schemas, API contracts, and environment variables.
4. **Release Notes & PR:** Compile an atomic commit history and a structured PR summary.
5. **Rollback & Deployment Plan:** Document rollback procedures and runtime monitoring indicators.

---

## 7. Additional Lifecycle Shortcuts

| Command | Associated Skill | Principle / Task |
| :--- | :--- | :--- |
| **`/constraints`** | `constraint-driven-development` | Define and lock the quality bar (`CONSTRAINTS.md`). Block agents from adding `@ts-ignore` or skipping tests. |
| **`/code-simplify`** | `code-simplification` | Refactor code for clarity. Favor obvious, simple code over clever abstractions. |
| **`/perf`** | `performance-optimization` | Never optimize without measurement. Profile, isolate bottlenecks, and prove performance gains. |
| **`/interview`** | `interview-me` | Extract underlying user intent through one-question-at-a-time interviews until 95% confidence is reached. |
