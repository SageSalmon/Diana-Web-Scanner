---
name: agent-benchmark
description: Run timed Diana scan on AWS ECS and compare performance against baseline
user_invocable: true
---

# Benchmark Agent

Run a timed Diana scan on AWS ECS, capture performance metrics and token usage, compare against the baseline.

## Arguments

- `branch` (optional) — branch to benchmark. Defaults to current branch.
- `run-id` (optional) — iteration identifier. Auto-generated if omitted.

## Instructions

### Step 1: Determine Branch and Run ID

```bash
BRANCH="${ARGUMENTS_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
RUN_ID="${ARGUMENTS_RUN_ID:-iteration-$(date +%Y%m%d-%H%M%S)}"
```

### Step 2: Launch ECS Task

```bash
./scripts/run-agent-task.sh benchmark "$BRANCH" "$RUN_ID"
```

### Step 3: Wait for Completion

Poll every 30 seconds:
```bash
aws ecs describe-tasks \
  --cluster diana-cluster \
  --tasks "$TASK_ARN" \
  --query 'tasks[0].{status:lastStatus,exit:containers[0].exitCode}'
```

Timeout after 40 minutes.

### Step 4: Fetch Results

```bash
./scripts/fetch-agent-results.sh "$RUN_ID" benchmark
```

### Step 5: Calculate Cost

Read `./agent-results/$RUN_ID/benchmark/results.json` and `scripts/bedrock-pricing.json`:

```python
cost = (input_tokens / 1_000_000 * input_price) + (output_tokens / 1_000_000 * output_price)
```

### Step 6: Compare Against Baseline

Look for the most recent previous benchmark results in `./agent-results/`. If found, calculate deltas:

| Metric | Baseline | Current | Delta | Threshold |
|---|---|---|---|---|
| Duration (s) | | | | >20% slower = WARN |
| Input tokens | | | | >30% more = WARN |
| Output tokens | | | | >30% more = WARN |
| LLM calls | | | | >25% more = WARN |
| Estimated cost | | | | >50% more = FAIL |

### Step 7: Report

- Performance metrics with deltas
- Per-module token breakdown (which scanner modules consume the most)
- Estimated cost for this scan
- PASS / WARN / FAIL verdict based on thresholds

## Notes

- This agent runs in parallel with `/agent-validation` and `/agent-test-runner`.
- The Juice Shop sidecar adds ~15s startup overhead — account for this in duration comparisons.
- Cost estimate uses `scripts/bedrock-pricing.json` which should be kept up to date.
