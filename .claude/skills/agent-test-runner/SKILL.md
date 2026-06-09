---
name: agent-test-runner
description: Run Diana test suite on AWS ECS and fetch results
user_invocable: true
---

# Test Runner Agent

Launch the test suite on AWS ECS Fargate and fetch the results. Pure compute — no judgment.

## Arguments

- `branch` (optional) — branch to test. Defaults to current branch.
- `run-id` (optional) — iteration identifier. Auto-generated if omitted.

## Instructions

### Step 1: Determine Branch and Run ID

```bash
BRANCH="${ARGUMENTS_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
RUN_ID="${ARGUMENTS_RUN_ID:-iteration-$(date +%Y%m%d-%H%M%S)}"
```

### Step 2: Launch ECS Task

```bash
./scripts/run-agent-task.sh test "$BRANCH" "$RUN_ID"
```

Capture the task ARN.

### Step 3: Wait for Completion

Poll every 15 seconds (test runs are faster than scans):
```bash
aws ecs describe-tasks \
  --cluster diana-cluster \
  --tasks "$TASK_ARN" \
  --query 'tasks[0].{status:lastStatus,exit:containers[0].exitCode}'
```

Timeout after 10 minutes — test suite should not take this long.

### Step 4: Fetch Results

```bash
./scripts/fetch-agent-results.sh "$RUN_ID" test-runner
```

### Step 5: Report

Read `./agent-results/$RUN_ID/test-runner/results.json` and report:
- PASSED or FAILED
- Total / passed / failed / skipped counts
- If any failures: test name + failure message for each
- Duration

## Notes

- This is the lightest AWS task (1 vCPU / 2GB, no target sidecar).
- This agent is typically run in parallel with `/agent-validation` and `/agent-benchmark` during Step 5 of the handoff chain.
