---
name: agent-validation
description: Run Diana validation scan on AWS — build image from branch, launch ECS task, fetch results from S3, produce gap analysis
user_invocable: true
---

# Validation Agent

Run a Diana scan against Juice Shop on AWS ECS, compare results to the known challenge list, and produce a structured gap analysis for the Improvement Agent.

## Arguments

- `branch` (optional) — git branch to validate. Defaults to current branch.
- `run-id` (optional) — iteration identifier. Auto-generated if omitted.

## Instructions

### Step 1: Determine Branch and Run ID

```bash
BRANCH="${ARGUMENTS_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
RUN_ID="${ARGUMENTS_RUN_ID:-iteration-$(date +%Y%m%d-%H%M%S)}"
```

Report the branch and run ID to the user before proceeding.

### Step 2: Ensure Branch is Pushed

Check that the branch exists on the remote. If not, push it:
```bash
git ls-remote --heads origin "$BRANCH"
# If empty, push:
git push -u origin "$BRANCH"
```

### Step 3: Launch ECS Task

Trigger the build and ECS task using the launcher script:
```bash
./scripts/run-agent-task.sh validation "$BRANCH" "$RUN_ID"
```

Capture the task ARN from the output.

### Step 4: Wait for Task Completion

Poll the ECS task status until it reaches STOPPED:
```bash
aws ecs describe-tasks \
  --cluster diana-cluster \
  --tasks "$TASK_ARN" \
  --query 'tasks[0].{status:lastStatus,stop:stoppedReason,exit:containers[0].exitCode}'
```

Poll every 30 seconds. If the task has been running for more than 30 minutes, warn the user and ask whether to continue waiting.

### Step 5: Fetch Results

```bash
./scripts/fetch-agent-results.sh "$RUN_ID" validation
```

### Step 6: Produce Gap Analysis

Read `./agent-results/$RUN_ID/validation/results.json` and produce a gap analysis:

1. **Headline metrics**: Challenges solved / total, solve rate, finding count, duration
2. **Per-category breakdown**: For each Juice Shop category, list solved vs missed challenges
3. **Missed vulnerability classes**: Group missed challenges by the type of scanner improvement needed (SPA crawling, parameter discovery, file upload, auth flows, etc.)
4. **Ranked opportunities**: Order missed classes by general applicability to real-world web apps (not Juice Shop-specific value)
5. **Comparison to baseline**: If a previous iteration exists in `./agent-results/`, compare solve rate delta

Write the gap analysis to `./agent-results/$RUN_ID/validation/gap-analysis.md`.

### Step 7: Report Summary

Print a concise summary to the user:
- Solve rate (and delta if baseline exists)
- Top 3 improvement opportunities
- Cost estimate (read token usage from results.json + `scripts/bedrock-pricing.json`)

## Notes

- This skill triggers AWS resources (CodeBuild + ECS Fargate). Confirm with user before launching if this is the first run.
- The ECS task takes 15-30 minutes depending on Bedrock latency.
- Results land in S3 at `s3://<artifacts-bucket>/$RUN_ID/validation/results.json`
- The gap analysis is the primary input for the Improvement Agent.
