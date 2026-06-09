---
name: agent-improvement
description: Analyze gap analysis from Validation Agent and implement one scanner improvement per iteration
user_invocable: true
---

# Improvement Agent

Read the gap analysis from the Validation Agent, select the highest-impact generic improvement, and implement it on a feature branch.

## Arguments

- `run-id` (required) — iteration identifier whose gap analysis to read
- `opportunity` (optional) — specific improvement to implement (skips selection)

## Instructions

### Step 1: Read Gap Analysis

Read the gap analysis from the most recent validation run:
```
./agent-results/$RUN_ID/validation/gap-analysis.md
./agent-results/$RUN_ID/validation/results.json
```

If the files don't exist, tell the user to run `/agent-validation` first.

### Step 2: Read Previous Chronicle

Check if `docs/CHRONICLE.md` exists and read it. This tells you:
- What improvements have already been made
- What has been tried and failed
- What the Improvement Agent should focus on next (from Review Agent notes)

Do NOT repeat an approach that was already rejected unless you have a meaningfully different strategy.

### Step 3: Select Improvement

If no `opportunity` argument was provided, select the top-ranked opportunity from the gap analysis based on:

1. **General applicability** — would this help scan ANY web app, not just Juice Shop?
2. **Challenge coverage** — how many missed challenges would this unlock?
3. **Feasibility** — can this be implemented in a single focused change?
4. **Not already attempted** — check chronicle for prior attempts

Present the selection to the user with a brief rationale. Wait for confirmation before proceeding.

### Step 4: Create Feature Branch

```bash
git checkout main
git pull origin main
git checkout -b improve/<short-description>
```

### Step 5: Implement the Improvement

Read the relevant scanner code before making changes. The key files are:

- Scanner modules: `src/diana/scanners/`
- Crawler: `src/diana/core/crawler.py`
- SPA Crawler: `src/diana/core/spa_crawler.py`
- Orchestrator: `src/diana/core/orchestrator.py`
- AI Agent base: `src/diana/ai/tool_agent.py`
- Scanner registry: `src/diana/scanners/registry.py`
- Models: `src/diana/core/models.py`

**Rules:**
- ONE improvement per iteration. Keep the change focused.
- No Juice Shop-specific code. No references to "juice", challenge names, or Juice Shop API paths.
- No hardcoded target-specific patterns — detection logic must be stack-agnostic.
- If adding a new scanner module, register it in `src/diana/scanners/registry.py`.
- If adding a new vuln type, add it to `VulnType` enum in `src/diana/core/models.py`.
- Follow existing patterns in the codebase — look at how `xss.py` and `xss_agent.py` are structured.

### Step 6: Push Branch

```bash
git add <specific files changed>
git commit -m "<description of improvement>

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
git push -u origin improve/<short-description>
```

### Step 7: Report

Tell the user:
- What was implemented and why
- Which files were changed
- Which missed challenges this should help detect (framed generically, not Juice Shop-specific)
- That the branch is ready for `/agent-generality` review

## Notes

- This agent only writes code. It does NOT run scans, tests, or validation.
- The Generality Agent must review the diff before any AWS tasks run.
- If the improvement requires changes to the Dockerfile or engagement configs, note that explicitly.
- Keep changes minimal. A 50-line scanner improvement is better than a 500-line refactor.
