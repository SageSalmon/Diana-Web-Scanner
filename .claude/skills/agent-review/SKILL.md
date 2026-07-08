---
name: agent-review
description: Final quality gate — synthesize all agent results and produce merge decision + chronicle entry
user_invocable: true
recommended_model: sonnet
---

# Review Agent

Pull results from all agents for a given iteration. Apply pass/fail criteria. Produce a merge recommendation and write the chronicle entry.

> **Model:** Sonnet is sufficient — this role synthesizes results the other agents
> already gathered and writes the chronicle entry. If run inline it inherits the
> session model; when the merge decision is high-stakes, keep it on Opus.

## Arguments

- `run-id` (required) — iteration identifier to review

## Instructions

### Step 1: Gather All Results

Fetch all agent results if not already local:
```bash
./scripts/fetch-agent-results.sh "$RUN_ID"
```

Read the following files:
- `./agent-results/$RUN_ID/validation/results.json` — scan results + challenge solve rate
- `./agent-results/$RUN_ID/validation/gap-analysis.md` — what was missed
- `./agent-results/$RUN_ID/test-runner/results.json` — test pass/fail
- `./agent-results/$RUN_ID/benchmark/results.json` — performance + cost

Also check for local gate results (these are in the conversation context, not files):
- Generality Agent verdict (from `/agent-generality`)
- Test Critic verdict (from `/agent-test-critic`)

### Step 2: Evaluate Pass/Fail Criteria

| Criterion | Source | Pass | Fail |
|---|---|---|---|
| Solve rate improved | Validation | Higher than baseline | Lower than baseline |
| No test regressions | Test Runner | All tests pass | Any failure |
| Performance acceptable | Benchmark | Within thresholds | >20% slower AND >50% more costly |
| Code is generic | Generality | PASS or WARN | FAIL |
| Tests are sound | Test Critic | PASS | FAIL |

**Merge decision:**
- **ALL PASS** → recommend merge
- **ANY FAIL** → reject with specific feedback for the Improvement Agent
- **WARN only** → recommend merge with notes

### Step 3: Calculate Iteration Cost

Sum costs across all scans run in this iteration:
- Validation scan tokens + Benchmark scan tokens
- If there were rejected attempts (re-runs), include those too
- Use `scripts/bedrock-pricing.json` for price calculation
- Track cumulative cost from previous chronicle entries

### Step 4: Write Chronicle Entry

#### S3 (structured JSON)

Write to `./agent-results/$RUN_ID/chronicle.json`:
```json
{
  "iteration": <N>,
  "date": "<YYYY-MM-DD>",
  "branch": "<branch-name>",
  "outcome": "merged|rejected|reworked",
  "detection": { "challenges_solved": N, "challenges_total": N, "solve_rate": 0.XX, "solve_rate_delta": +/-0.XX },
  "performance": { "scan_duration_seconds": N, "duration_delta": N, "llm_tokens_used": N, "token_delta": N },
  "tests": { "total": N, "passed": N, "failed": N, "coverage_pct": N },
  "cost": { "scans_run": N, "attempts": N, "total_input_tokens": N, "total_output_tokens": N, "estimated_cost_usd": X.XX, "cumulative_cost_usd": X.XX },
  "synopsis": "<narrative>",
  "verdicts": { "generality": "...", "test_critic": "...", "test_runner": "...", "validation": "...", "benchmark": "..." },
  "next_opportunities": ["...", "..."]
}
```

Upload to S3:
```bash
ARTIFACTS_BUCKET=$(terraform -chdir=tf/environments/dev output -raw agent_artifacts_bucket)
aws s3 cp ./agent-results/$RUN_ID/chronicle.json "s3://$ARTIFACTS_BUCKET/chronicle/$RUN_ID.json"
```

#### Local Narrative (docs/CHRONICLE.md)

Append an entry to `docs/CHRONICLE.md` (create if it doesn't exist):

```markdown
## Iteration <N> — <Short Title> (<date>) <outcome symbol>

**Solve rate: X% → Y% (+Z%)**  |  Duration: Xs → Ys  |  Tests: N pass
**Cost: $X.XX (N scans, N attempts)**  |  Cumulative: $X.XX

<2-4 sentence synopsis: what was changed, why, what it unlocked or why it failed.
Note any Generality Agent rejections and how they were resolved.>

---
```

Outcome symbols: `✓ MERGED`, `✗ REJECTED`, `↻ REWORKED`

### Step 5: Merge Decision

**If recommending merge:**
```bash
git checkout main
git merge --no-ff <branch>
git push origin main
```

Wait for user confirmation before executing the merge.

**If rejecting:**
Report specific feedback:
- Which criterion failed
- What the Improvement Agent should change
- Suggested next approach

### Step 6: Report Summary

Print a final summary:
- Merge decision with rationale
- Key metrics (solve rate, tests, performance, cost)
- What the next iteration should focus on
- Link to chronicle entry

## Notes

- The Review Agent is the only agent whose output the human needs to check.
- Always wait for user confirmation before merging.
- The chronicle is the project's institutional memory across conversations.
- If this is the first iteration, there's no baseline — just record the initial metrics.
