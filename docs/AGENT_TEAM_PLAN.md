# Diana Agent Team — Planning Document

## Goal

Build a team of Claude Code agents that iteratively improve Diana's vulnerability detection capabilities. The first objective: **increase Juice Shop challenge coverage by 5%** while keeping all improvements generic — nothing Juice Shop-specific enters the codebase.

---

## The Agents

### Cross-Validation Matrix

No agent validates its own work. Every producer has a different consumer:

| Agent | Produces | Validated by |
|-------|----------|-------------|
| Improvement Agent | Code changes | Generality Agent, Test Critic (via Test Author), Validation Agent, Benchmark Agent |
| Test Author Agent | Tests | Test Critic Agent |
| Test Critic Agent | Approve/reject on tests | Review Agent (checks critic was thorough) |
| Generality Agent | Approve/reject on code | Review Agent (checks generality was thorough) |
| Validation Agent | Scan results | Review Agent (compares to baseline) |
| Test Runner Agent | Pass/fail | Review Agent (correlates with Validation results) |
| Benchmark Agent | Performance metrics | Review Agent (compares to baseline thresholds) |
| Review Agent | Merge decision | Human (you) — the Review Agent is the only one whose output you need to check |

### 1. Improvement Agent (local)
**Role:** Analyze missed vulnerabilities and implement scanner improvements.
**Input:** Gap analysis from the Validation Agent (which challenges were missed and why).
**Output:** Code changes on a feature branch — new scanner logic, better payloads, improved crawling.
**Runs:** Locally in Claude Code. Reads code, writes code, pushes branches.

### 2. Validation Agent (AWS)
**Role:** Run Diana against Juice Shop on AWS, capture results, compare to known challenge list.
**Input:** A branch ref to test (from Improvement Agent or main).
**Output:** Structured results in S3 — findings, challenge solve rate, per-category breakdown, gap analysis.
**Runs:** ECS Fargate task. Pulls Diana image, checks out branch, runs scan against a Juice Shop instance on the same cluster.

### 3. Generality Agent (local)
**Role:** Police every code change to ensure nothing is target-specific.
**Input:** Diff of proposed changes from the Improvement Agent.
**Output:** Approve/reject with specific objections. Flags any code that:
  - References "juice" / "juice-shop" / known Juice Shop endpoints or challenge names
  - Hardcodes target-specific paths, parameters, or response patterns
  - Adds detection logic that only works against Node.js/Express (Juice Shop's stack) rather than being stack-agnostic
  - Trains on Juice Shop's specific error messages, HTML structure, or API shape
**Principle:** If the improvement wouldn't also help scan a Django app, a Spring Boot API, or a Rails monolith, it fails review.

### 4. Test Author Agent (local)
**Role:** Write tests for code changes produced by the Improvement Agent.
**Input:** Diff of changes from the Improvement Agent + the code being changed.
**Output:** New or updated test files on the feature branch.
**Runs:** Locally in Claude Code. Reads code, writes tests, commits to the feature branch.
**Note:** The test suite is currently empty (`tests/unit/` and `tests/integration/` have no test files). This agent bootstraps coverage and grows it with each iteration.

### 5. Test Critic Agent (local)
**Role:** Review tests written by the Test Author for correctness, completeness, and independence.
**Input:** Tests written by the Test Author + the code they're testing.
**Output:** Approve/reject with specific objections. Evaluates:
  - **Correctness:** Does the test actually assert the behavior it claims to? Are assertions meaningful, not vacuous?
  - **Completeness:** Are edge cases covered? Are failure modes tested, not just happy paths?
  - **Independence:** Would the test still pass if the code under test was broken? (Mutation testing mindset — if you delete the feature, does the test fail?)
  - **Generality:** No test should only work against Juice Shop responses, structure, or API shapes
  - **Isolation:** Unit tests must not depend on network, database, or external services. Integration tests must be clearly marked as such.
**Principle:** A test that passes regardless of whether the code works is worse than no test — it provides false confidence.

### 6. Test Runner Agent (AWS)
**Role:** Execute the test suite against proposed changes. Pure compute, no judgment.
**Input:** Branch ref from Improvement Agent (after Test Author + Test Critic have approved).
**Output:** Test results (pass/fail/coverage) in S3.
**Runs:** ECS Fargate task. Lightweight — no target instance needed, just pytest in the Diana container.

### 7. Benchmark Agent (AWS)
**Role:** Measure scan performance — duration, token spend, request count — and flag regressions.
**Input:** Branch ref + baseline metrics from the previous run on main.
**Output:** Performance comparison in S3 — deltas for duration, token cost, HTTP request count.
**Runs:** ECS Fargate task with its own Juice Shop instance.

### 8. Review Agent (local)
**Role:** Final quality gate before merge. Synthesizes outputs from all other agents.
**Input:** Results from Validation, Generality, Test Critic, Test Runner, and Benchmark agents.
**Output:** Merge decision — approve, request changes, or reject. Creates PR summary.
**Runs:** Locally in Claude Code.

---

## What Runs Where

### Local (Claude Code harness)

| Agent | What it does locally | AWS interaction |
|-------|---------------------|-----------------|
| Improvement | Reads gap analysis, writes code, pushes branch | None |
| Test Author | Writes tests for Improvement Agent's changes | None |
| Test Critic | Reviews tests for correctness and completeness | None |
| Generality | Reviews diffs for target-specific code | None |
| Review | Reads all agent results, makes merge decision | Reads from S3 |

### AWS (ECS Fargate)

| Agent | Task definition | Needs target instance? | Resources |
|-------|----------------|----------------------|-----------|
| Validation | `diana-validation-task` | Yes (Juice Shop sidecar) | 2 vCPU / 4GB |
| Test Runner | `diana-test-task` | No | 1 vCPU / 2GB |
| Benchmark | `diana-benchmark-task` | Yes (Juice Shop sidecar) | 2 vCPU / 4GB |

### Shared AWS Infrastructure

| Resource | Purpose |
|----------|---------|
| ECR repo: `diana-agent` | Diana image built from branch ref |
| S3 bucket: `diana-agent-artifacts` | All agent results (JSON), organized by `run-id/agent-name/` |
| ECS cluster: existing `diana` cluster | Runs all Fargate tasks |
| CloudWatch log group | Per-task logs for debugging |
| CodeBuild project: `diana-build` | Builds Diana image from branch, pushes to ECR |

---

## Agent Handoff Chain

A single iteration cycle looks like this:

```
Step 1: VALIDATE BASELINE
  Validation Agent runs against main branch
  → Output: baseline results in S3 (challenges solved, findings, metrics)

Step 2: ANALYZE GAPS
  Improvement Agent reads baseline results
  → Identifies top opportunities ranked by general applicability
  → Picks one improvement to implement

Step 3: IMPLEMENT
  Improvement Agent writes code on feature branch
  → Pushes branch to remote

Step 4: LOCAL GATES (run sequentially — each gates the next)

  Step 4a: GENERALITY CHECK (gate)
    Generality Agent reviews the diff (branch vs main)
    → PASS: continue to Step 4b
    → FAIL: return to Step 3 with specific objections

  Step 4b: TEST AUTHORING
    Test Author Agent writes tests for the new/changed code
    → Commits tests to the feature branch

  Step 4c: TEST CRITIQUE (gate)
    Test Critic Agent reviews the tests
    → PASS: continue to Step 5
    → FAIL: return to Step 4b with specific objections
      (e.g., "test_xss_detection passes even if you delete the
       detection logic — it's asserting on the mock, not the code")

Step 5: PARALLEL VALIDATION (all on AWS, run concurrently)
  ┌─ Validation Agent runs scan with new branch → S3
  ├─ Test Runner Agent runs pytest with new branch → S3
  └─ Benchmark Agent runs timed scan with new branch → S3

Step 6: REVIEW (gate)
  Review Agent pulls all results from S3 and evaluates:
  - Did challenge solve rate improve? (Validation)
  - Did any tests break? (Test Runner)
  - Did performance regress beyond threshold? (Benchmark)
  - Are the generality and test critic checks clean? (Step 4 gates)
  → ALL PASS: merge branch, update baseline
  → ANY FAIL: return to Step 3 with consolidated feedback

Step 7: UPDATE BASELINE
  Merged main becomes the new baseline
  → Loop back to Step 1 for the next improvement
```

### Failure Modes & Recovery

| Failure | Who catches it | What happens |
|---------|---------------|--------------|
| Improvement breaks tests | Test Runner Agent | Review Agent sends failure back to Improvement Agent with test output |
| Improvement is Juice Shop-specific | Generality Agent | Blocks at Step 4a before tests are even written (saves time + cost) |
| Tests are tautological / vacuous | Test Critic Agent | Blocks at Step 4c; Test Author rewrites with specific objections |
| Tests only work against Juice Shop responses | Test Critic Agent | Same gate — generality applies to tests too |
| Tests pass but code is broken (false confidence) | Test Critic Agent | Mutation analysis mindset: "would this test fail if the feature was deleted?" |
| Scan rate drops | Validation Agent | Review Agent rejects; Improvement Agent gets gap analysis showing regression |
| Scan gets slower / costs more tokens | Benchmark Agent | Review Agent rejects if delta exceeds threshold (e.g., >20% slower, >30% more tokens) |
| Improvement helps Juice Shop but hurts generality | Generality Agent + Review Agent | Double gate — Generality catches target-specific code, Review catches narrowed detection |

---

## Task Breakdown

### Phase 0: Foundation (do first)

- [ ] **T0.1** Create S3 bucket `diana-agent-artifacts` with run-id prefix structure
- [ ] **T0.2** Create IAM role `diana-agent-runner` with permissions for: ECS RunTask, S3 read/write to artifacts bucket, ECR pull, CloudWatch logs, Bedrock InvokeModel
- [ ] **T0.3** Create CodeBuild project `diana-build` that takes a branch ref, builds Diana image, pushes to ECR with branch tag
- [ ] **T0.4** Create ECS task definitions:
  - `diana-validation-task` (Diana + Juice Shop sidecar)
  - `diana-test-task` (Diana only)
  - `diana-benchmark-task` (Diana + Juice Shop sidecar)
- [ ] **T0.5** Write a launcher script (`scripts/run-agent-task.sh`) that: accepts task-def name + branch ref, triggers CodeBuild, waits for image, runs ECS task, returns task ARN
- [ ] **T0.6** Write a results fetcher script (`scripts/fetch-agent-results.sh`) that: accepts run-id + agent name, pulls JSON results from S3

### Phase 1: First Agent Loop (Validation + Improvement)

- [ ] **T1.1** Build the **Validation Agent** as a Claude Code skill
  - Calls launcher script with `diana-validation-task` + branch ref
  - Waits for ECS task completion (polls `ecs describe-tasks`)
  - Fetches results from S3
  - Parses challenge solve rate, generates gap analysis
- [ ] **T1.2** Build container entrypoint script (`scripts/entrypoint-validation.sh`) that:
  - Waits for Juice Shop sidecar to be healthy
  - Resets Juice Shop challenge state
  - Runs Diana scan with standard engagement config
  - Fetches challenge results from Juice Shop API
  - Writes structured JSON to S3: `{run_id}/{agent}/results.json`
- [ ] **T1.3** Build the **Improvement Agent** as a Claude Code skill
  - Reads gap analysis from Validation Agent
  - Analyzes missed vulnerability classes
  - Implements one improvement per cycle on a feature branch
- [ ] **T1.4** Run first end-to-end cycle: baseline scan → gap analysis → one improvement → re-scan → measure delta

### Phase 2: Add Guardrails

- [ ] **T2.1** Build the **Generality Agent** as a Claude Code skill
  - Runs `git diff main...<branch>` and analyzes every changed line
  - Checks against target-specific patterns (string literals, endpoint paths, response patterns)
  - Checks that new detection logic is stack-agnostic (not Node/Express-specific)
  - Produces approve/reject with line-by-line justification
- [ ] **T2.2** Build the **Test Author Agent** as a Claude Code skill
  - Reads the diff from the Improvement Agent
  - Writes unit tests for new/changed scanner logic (mocked HTTP, no live targets)
  - Writes integration tests for end-to-end scan flows (marked separately, run on AWS)
  - Commits tests to the feature branch
- [ ] **T2.3** Build the **Test Critic Agent** as a Claude Code skill
  - Reads tests from the Test Author + the code under test
  - Checks correctness: are assertions testing real behavior, not mocks?
  - Checks completeness: edge cases, error paths, boundary conditions
  - Checks independence: would the test fail if the feature was deleted? (mental mutation test)
  - Checks generality: no Juice Shop-specific fixtures, responses, or assertions
  - Produces approve/reject with specific objections per test
- [ ] **T2.4** Build the **Test Runner Agent** as a Claude Code skill
  - Calls launcher with `diana-test-task` + branch ref
  - Fetches pytest results from S3
  - Reports pass/fail/coverage
- [ ] **T2.5** Build the **Benchmark Agent** as a Claude Code skill
  - Calls launcher with `diana-benchmark-task` + branch ref
  - Compares against baseline metrics stored in S3
  - Reports deltas: duration, token count, HTTP requests, findings count
- [ ] **T2.6** Build container entrypoint scripts for test and benchmark tasks

### Phase 3: Orchestration

- [ ] **T3.1** Build the **Review Agent** as a Claude Code skill
  - Pulls results from all agents for a given run-id
  - Applies pass/fail criteria
  - Generates merge recommendation with evidence
- [ ] **T3.2** Build the **Orchestrator** as a Claude Code skill
  - Runs the full Step 1-7 loop
  - Manages run-ids, triggers agents in correct order
  - Handles the generality gate (Step 4) before spending AWS compute (Step 5)
  - Tracks cumulative progress across iterations
- [ ] **T3.3** Build the **Chronicle** system (see Chronicle section below)
  - Chronicle writer integrated into the Review Agent
  - S3 stores structured data, local `docs/CHRONICLE.md` is the human-readable narrative

### Phase 4: Hardening

- [ ] **T4.1** Add DVWA and WebGoat as additional validation targets (prevents overfitting to Juice Shop even further)
- [ ] **T4.2** Add cost tracking — sum Bedrock token usage + Fargate vCPU-hours per iteration
- [ ] **T4.3** Add timeout/circuit breaker — if an iteration hasn't converged in 3 attempts, pause and surface the blocker

---

## First Objective: +5% Juice Shop Coverage

Based on the existing skill output and scanner architecture, the most likely improvement areas (in order of general applicability):

1. **SPA route crawling** — Playwright is disabled in orchestrator. Enabling it unlocks hash-route endpoints that many modern apps use. General: all SPAs.
2. **POST body / JSON schema discovery** — Current crawler extracts form params but may miss JSON API bodies. General: all REST APIs.
3. **Deeper parameter discovery** — Crawl API responses for field names that suggest injectable parameters. General: all dynamic apps.
4. **File upload testing** — No dedicated upload scanner exists. General: any app with file uploads.
5. **Authentication flow attacks** — Current auth scanner tests IDOR but not password reset, credential stuffing patterns, or session fixation. General: all authenticated apps.

The Improvement Agent will start from this ranked list, implement the top opportunity, and the Generality Agent will verify each change helps beyond just Juice Shop.

---

## Chronicle

Each iteration cycle produces a chronicle entry. The git log captures the small stuff — the chronicle captures the arc.

### What Gets Recorded

Each entry is written by the Review Agent at the end of Step 6 (whether the iteration passed or failed):

```yaml
# S3: diana-agent-artifacts/chronicle/{iteration-number}.json
iteration: 7
date: "2026-06-07"
branch: "improve/spa-route-crawling"
outcome: "merged"  # or "rejected" or "reworked"

# Metrics snapshot — cumulative, not just this iteration
detection:
  juice_shop_challenges_solved: 34
  juice_shop_challenges_total: 100
  solve_rate: 0.34
  solve_rate_delta: +0.03        # vs previous iteration
  diana_findings_total: 48
  false_positives_rejected: 6

performance:
  scan_duration_seconds: 1140
  duration_delta: +45             # seconds vs previous
  llm_tokens_used: 128400
  token_delta: +12000
  http_requests: 2340

tests:
  total: 87
  passed: 87
  failed: 0
  coverage_pct: 62

# Cost tracking for this iteration
cost:
  scans_run: 3                    # baseline + branch validation + benchmark
  attempts: 2                     # first attempt rejected by Generality Agent
  per_scan_tokens:
    - scan: "baseline"
      input_tokens: 42000
      output_tokens: 12400
      calls: 87
    - scan: "branch-validation"
      input_tokens: 48200
      output_tokens: 14100
      calls: 94
    - scan: "benchmark"
      input_tokens: 47800
      output_tokens: 13900
      calls: 93
  total_input_tokens: 138000
  total_output_tokens: 40400
  estimated_cost_usd: 0.89        # calculated from Bedrock pricing
  cumulative_cost_usd: 5.42       # running total across all iterations

# Per-module breakdown (from TokenTracker) — shows where tokens go
token_breakdown:
  sqli_agent:    { input: 18200, output: 5400, calls: 22 }
  xss_agent:     { input: 14800, output: 4100, calls: 18 }
  discovery_agent: { input: 11200, output: 3200, calls: 14 }
  ai_validator:  { input: 6400,  output: 1800, calls: 12 }
  configurator:  { input: 2200,  output: 800,  calls: 2 }
  auth_agent:    { input: 1400,  output: 600,  calls: 4 }

# The narrative — this is what the git log doesn't capture
synopsis: |
  Enabled Playwright-based SPA crawling in the orchestrator. The crawler
  now discovers hash-route endpoints (#/admin, #/accounting, etc.) that
  were previously invisible. This unlocked 3 new Juice Shop challenges
  in the "Broken Access Control" category. Scan duration increased by
  ~45s due to browser startup overhead — acceptable tradeoff.

  The Generality Agent flagged the first attempt: the route extraction
  regex was matching Angular-specific patterns only. Reworked to detect
  React Router, Vue Router, and generic hash-fragment patterns.

  Cost note: 2 attempts meant 3 scans instead of 2. The rejected first
  attempt cost ~$0.30 in wasted Bedrock tokens. Generality gate caught
  it before the full validation suite ran, saving ~$0.60.

# Agent verdicts — the audit trail
verdicts:
  generality: "PASS (2nd attempt — first rejected for Angular-only regex)"
  test_critic: "PASS"
  test_runner: "PASS — 87/87, no regressions"
  validation: "PASS — solve rate 31% → 34%"
  benchmark: "PASS — +45s duration within threshold"

# What the Improvement Agent should focus on next
next_opportunities:
  - "JSON API body discovery — 8 challenges involve REST endpoints with POST bodies the crawler doesn't extract"
  - "File upload scanner — 5 challenges involve upload endpoints, no scanner module exists"
```

### Cost Calculation

The Validation and Benchmark entrypoint scripts already have access to `TokenTracker` data (it's persisted to the DB per scan). The entrypoint writes token totals into the S3 results JSON. The Review Agent then calculates cost using Bedrock pricing:

```
# DeepSeek V3.2 on Bedrock (us-east-1) — as of June 2026
input:  $X.XX per 1M tokens
output: $X.XX per 1M tokens

estimated_cost = (total_input * input_price) + (total_output * output_price)
```

Pricing will be pinned in a config file (`scripts/bedrock-pricing.json`) so it's easy to update when rates change. The Review Agent reads this file to compute costs — no hardcoded prices in agent logic.

The cumulative cost is tracked across chronicle entries so you can see the running total. If cost-per-iteration starts climbing (e.g., because improvements add more scanner turns), the Review Agent flags it in the synopsis.

### The Human-Readable Narrative: `docs/CHRONICLE.md`

The Review Agent also appends a summary to a local markdown file that stays in the repo. This is the version you read — S3 has the structured data, this has the story.

```markdown
# Diana Agent Team — Chronicle

## Iteration 7 — SPA Route Crawling (2026-06-07) ✓ MERGED

**Solve rate: 31% → 34% (+3%)**  |  Duration: 1095s → 1140s  |  Tests: 87 pass
**Cost: $0.89 (3 scans, 2 attempts)**  |  Cumulative: $5.42

Enabled Playwright-based SPA crawling. The crawler now discovers hash-route
endpoints that were previously invisible, unlocking 3 new challenges in Broken
Access Control. First attempt was rejected by the Generality Agent for
Angular-only route patterns — reworked to be framework-agnostic.

---

## Iteration 6 — Deeper Parameter Extraction (2026-06-06) ✓ MERGED

**Solve rate: 28% → 31% (+3%)**  |  Duration: 1050s → 1095s  |  Tests: 74 pass
**Cost: $0.62 (2 scans, 1 attempt)**  |  Cumulative: $4.53

...
```

### What the Chronicle Is NOT

- **Not a replacement for git log** — individual file changes, line diffs, and commit messages stay in git
- **Not a debug log** — CloudWatch has the per-task execution logs
- **Not an artifact store** — S3 has the raw scan results, test output, and benchmark data

The chronicle captures **the decisions, the trajectory, and the why** — the things that evaporate between conversations.

### Who Writes It

The **Review Agent** owns the chronicle. It's the only agent that sees all the results, so it's the only one qualified to write the synopsis. It writes:

1. Structured JSON to S3 (machine-readable, queryable)
2. Narrative append to `docs/CHRONICLE.md` (human-readable, committed to git)

The Orchestrator can read previous chronicle entries to inform the Improvement Agent's priorities — "we've been stuck on file upload for 3 iterations, try a different approach" or "solve rate hasn't moved in 2 cycles, escalate to human."

---

## Terraform Changes Required

All new resources extend the existing `tf/` structure:

```
tf/modules/agent_infra/        # NEW module
  main.tf                      # S3 bucket, CodeBuild, task definitions
  variables.tf
  outputs.tf

tf/environments/dev/main.tf    # ADD module "agent_infra" block
```

This keeps agent infrastructure separate from the core scanner infra while sharing the existing VPC, ECS cluster, and IAM foundations.
