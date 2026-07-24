---
name: agent-orchestrator
description: Run the full agent team iteration loop — from baseline validation through merge decision
user_invocable: true
recommended_model: opus
---

# Orchestrator

Run the full iteration loop as defined in the Agent Team Plan. Manages the handoff chain, enforces gate ordering, and tracks progress.

> **Model:** run inline on the session's top-tier model (Opus) — this role drives
> the loop's judgement calls and gate ordering. The mechanical sub-roles it hands
> off to (validation/tinyloop/test-runner/benchmark → Haiku; generality/test-author/
> test-critic → Sonnet) should be **dispatched as subagents** via the matching
> `.claude/agents/*.md` definitions so each runs on its cheaper tier.

## Arguments

- `mode` (optional) — `full` (default) runs the complete loop. `resume` picks up from where the last run left off.
- `opportunity` (optional) — specific improvement to implement (passed to Improvement Agent)

## Instructions

### Full Loop Execution

Execute the steps in order. Each gate must pass before proceeding.

```
Step 1: BASELINE          → /agent-validation on main
Step 2: ANALYZE            → read gap analysis
Step 3: IMPLEMENT          → /agent-improvement
Step 4a: GENERALITY GATE   → /agent-generality (blocks Step 4b on FAIL)
Step 4b: TEST AUTHORING    → /agent-test-author
Step 4c: TEST CRITIC GATE  → /agent-test-critic (blocks Step 5 on FAIL)
Step 5: AWS VALIDATION     → /agent-validation + /agent-test-runner + /agent-benchmark (parallel, same run-id)
Step 6: REVIEW GATE        → /agent-review
Step 7: UPDATE BASELINE    → merge if approved
```

### Gate Handling

**On FAIL at Step 4a (Generality):**
- Pass the Generality Agent's objections to the Improvement Agent
- Re-run Step 3 → 4a
- Max 3 attempts. After 3, escalate to the user.

**On FAIL at Step 4c (Test Critic):**
- Pass the Test Critic's objections to the Test Author
- Re-run Step 4b → 4c
- Max 2 attempts. After 2, escalate to the user.

**On FAIL at Step 6 (Review):**
- Analyze which criterion failed
- If test failures: re-run Steps 3 → 4 (code needs fixing)
- If performance regression: re-run Step 3 with optimization constraint
- If solve rate dropped: re-run Step 3 with different approach
- Max 2 rework cycles. After 2, escalate to the user.

### Run ID Management

Generate a single run ID for the iteration:
```bash
RUN_ID="iteration-$(date +%Y%m%d-%H%M%S)"
```

Pass this to ALL agents so their results are correlated in S3.

### Progress Tracking

After each step, report status:
```
[Step 1/7] ✓ Baseline validated — 31% solve rate
[Step 2/7] ✓ Top opportunity: SPA route crawling
[Step 3/7] ✓ Implemented on branch improve/spa-crawling
[Step 4a/7] ✗ Generality FAIL — Angular-specific regex (attempt 1/3)
[Step 3/7] ✓ Reworked — framework-agnostic patterns
[Step 4a/7] ✓ Generality PASS (attempt 2/3)
[Step 4b/7] ✓ 12 tests written
[Step 4c/7] ✓ Test Critic PASS
[Step 5/7] ⏳ AWS validation running... (3 tasks in parallel)
[Step 5/7] ✓ Validation: 34% (+3%) | Tests: 12/12 | Benchmark: +45s
[Step 6/7] ✓ Review: MERGE recommended
[Step 7/7] ⏳ Awaiting user confirmation to merge
```

### Stall Detection

Read `docs/CHRONICLE.md` before starting. If:
- Solve rate hasn't improved in 2 consecutive iterations → warn user, suggest changing strategy
- Same improvement class has been attempted 3+ times → skip it, try next opportunity
- Cumulative cost exceeds $50 without solve rate improvement → pause and escalate

### Resume Mode

If `mode=resume`:
1. Read the most recent chronicle entry to determine last completed step
2. Check for partial results in `./agent-results/`
3. Pick up from the next incomplete step

## Notes

- The orchestrator coordinates but does NOT make implementation decisions — that's the Improvement Agent's job.
- Always confirm with the user before starting (this will trigger AWS costs).
- A single iteration typically takes 30-60 minutes depending on scan time and rework cycles.
- Keep the user informed of progress. Long silences during AWS tasks should include periodic status updates.
