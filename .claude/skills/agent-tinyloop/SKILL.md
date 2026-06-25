---
name: agent-tinyloop
description: Fast inner-loop iteration on a single scanner module in its AWS sandbox — reuses a cached crawl, runs only the changed module(s), and asserts against the Juice Shop scoreboard. Use to iterate a non-crawler fix without a full validation scan.
---

Base directory for this skill: /Users/bdoss/code/web-scanner/.claude/skills/agent-tinyloop

# Tiny-Loop Agent

A lean alternative to the full Validation Agent for iterating on a single module's
logic. It runs in the **same AWS sandbox** as the validation agent (it reuses the
`diana-agent-validation` task definition, swapping the entrypoint via an env var —
no Terraform change), but does far less work per iteration:

- **reuses a cached sitemap** (`--sitemap-cache`) so the expensive crawl + Playwright
  phases are skipped;
- **runs only the module(s) under test** instead of the full suite;
- **asserts against the Juice Shop scoreboard** (`/api/Challenges`) for the specific
  challenges your change targets.

Per-iteration cost is a CodeBuild image build plus a single-module scan on a cached
crawl — minutes, not the ~50 minutes of a full validation. Use it to converge a fix,
then run **one** full `agent-validation` as the merge gate.

## When NOT to use it

The tiny loop is only sound when the change does **not** touch the crawler — a stale
cached sitemap would mask crawler regressions. This skill enforces that guard and
aborts to the full loop if the diff touches the crawler set:
`src/diana/core/crawler.py`, `src/diana/core/spa_crawler.py`, `src/diana/core/models.py`.

## Arguments

- `modules` (optional) — comma-separated module(s) to run. Default: `access_control`.
- `target-challenges` (optional) — comma-separated Juice Shop challenge names to
  report solved/unsolved (e.g. `Admin Section,View Basket,Manipulate Basket`).
- `branch` (optional) — git branch to test. Defaults to current branch.
- `run-id` (optional) — iteration identifier. Auto-generated if omitted.

## Instructions

### Step 1: Crawler guard

Determine the branch and check its diff against `main` does not touch the crawler set:

```bash
BRANCH="${ARGUMENTS_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
git diff --name-only main..."$BRANCH"
```

If any of `src/diana/core/crawler.py`, `src/diana/core/spa_crawler.py`, or
`src/diana/core/models.py` appear, **STOP** and tell the user to use `agent-validation`
instead — the cached sitemap would be stale. Otherwise continue.

### Step 2: Determine run ID and push the branch

```bash
RUN_ID="${ARGUMENTS_RUN_ID:-tinyloop-$(date +%Y%m%d-%H%M%S)}"
git ls-remote --heads origin "$BRANCH"   # if empty: git push -u origin "$BRANCH"
```

Report branch, run ID, modules, and target challenges to the user.

### Step 3: Launch the tiny-loop task

```bash
MODULES="${ARGUMENTS_MODULES:-access_control}" \
TARGET_CHALLENGES="${ARGUMENTS_TARGET_CHALLENGES:-}" \
./scripts/run-agent-task.sh tinyloop "$BRANCH" "$RUN_ID"
```

This builds the image from the branch and runs the task in the validation sandbox with
`AGENT_ENTRYPOINT=/app/scripts/entrypoint-tinyloop.sh`. Capture the task ARN.

The **first** run for a given crawler version seeds the shared sitemap cache at
`s3://<artifacts-bucket>/cache/juiceshop-sitemap.json` (it crawls once); every run after
reuses it. To force a fresh crawl (e.g. after the crawler changed), delete that S3 object.

### Step 4: Wait for completion

Poll the ECS task until STOPPED (every ~20s):

```bash
aws ecs describe-tasks --cluster diana-cluster --tasks "$TASK_ARN" \
  --query 'tasks[0].{status:lastStatus,exit:containers[0].exitCode}'
```

### Step 5: Fetch and report

```bash
./scripts/fetch-agent-results.sh "$RUN_ID" tinyloop
```

Read `./agent-results/$RUN_ID/tinyloop/results.json` and report:

- **Targeted challenges**: which of `target-challenges` flipped to `solved` (the headline).
- **Module findings** and **scan duration**.
- **Overall solved** count (sanity check; not the focus).

### Step 6: Iterate or graduate

- If targeted challenges are still unsolved: inspect `scan-output.log` (did the module
  enqueue work? did it error?), adjust the module in `src/diana/scanners/<module>.py`,
  and repeat from Step 3 with the same `run-id` prefix.
- Once the targets solve: hand off to `agent-validation` for one full scan (fresh crawl,
  full module suite, real benchmark timing) as the merge gate.

## Notes

- Triggers AWS resources (CodeBuild + ECS Fargate in the existing dev stack). It does not
  stand up or tear down infrastructure — the stack must already be applied.
- The scoreboard is the *measurement* signal; the *fix* must still be general — run
  `agent-generality` on the change before merging.
- Results: `s3://<artifacts-bucket>/$RUN_ID/tinyloop/results.json`.
