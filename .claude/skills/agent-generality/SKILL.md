---
name: agent-generality
description: Review code changes for target-specific patterns — reject anything that only works against Juice Shop
user_invocable: true
---

# Generality Agent

Review the diff between a feature branch and main. Reject any code that is specific to a particular target application rather than being generically applicable to all web apps.

## Arguments

- `branch` (optional) — branch to review. Defaults to current branch.

## Instructions

### Step 1: Get the Diff

```bash
BRANCH="${ARGUMENTS_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
git diff main..."$BRANCH"
```

If the diff is empty, report that there are no changes to review.

### Step 2: Analyze Every Changed Line

For each file in the diff, check for the following violations:

#### Hard Rejections (automatic fail)

1. **Target name references** — any string literal containing: `juice`, `juice-shop`, `juiceshop`, `dvwa`, `webgoat`, `hackable`, or known target-specific endpoint paths (`/rest/products`, `/api/Challenges`, `/b2b/v2/orders`)
2. **Challenge-aware code** — any reference to specific vulnerability challenge names, IDs, or scoring mechanisms
3. **Hardcoded target responses** — regex or string matching tuned to a specific app's error messages, HTML structure, or API response shape
4. **Target-specific credentials** — hardcoded usernames/passwords for test targets (these belong in engagement configs, not scanner code)

#### Soft Rejections (flag for review, may be acceptable with justification)

5. **Stack-specific detection** — detection logic that only works against one tech stack (Node/Express, Spring Boot, Django, etc.) without being part of a multi-stack detection strategy
6. **Narrow payload sets** — payloads that exploit a specific framework's quirk without also testing generic variants
7. **Endpoint path assumptions** — code that assumes specific URL patterns (like `/api/` prefix) rather than working with whatever the crawler discovers
8. **Response parsing** — parsing that assumes a specific JSON schema, HTML layout, or error format

### Step 3: Check Test Files Too

Tests written by the Test Author Agent must also be generic:
- Test fixtures should use synthetic HTTP responses, not captured Juice Shop responses
- Assertions should test scanner behavior, not target-specific outcomes
- No test should require a specific target to be running

### Step 4: Produce Verdict

**If all checks pass:**
```
GENERALITY: PASS
Branch: <branch>
Files reviewed: <count>
Lines changed: +<added> -<removed>
Notes: <any observations about good generic patterns used>
```

**If any hard rejections found:**
```
GENERALITY: FAIL
Branch: <branch>

VIOLATIONS:
- <file>:<line> — <violation type>: <specific text that violates>
  Fix: <suggested generic alternative>

- <file>:<line> — ...
```

**If only soft rejections:**
```
GENERALITY: WARN
Branch: <branch>

WARNINGS:
- <file>:<line> — <concern>
  Suggestion: <how to make it more generic>
```

WARN does not block the pipeline — the Review Agent decides whether to accept warnings.

### Step 5: Report

Print the verdict. If FAIL, tell the user the branch needs rework before proceeding to AWS validation. If PASS, tell them the branch is ready for `/agent-test-author`.

## Principle

**If the improvement wouldn't also help scan a Django app, a Spring Boot API, and a Rails monolith, it fails review.**

The goal is to get better at finding vulnerabilities in ALL web apps. Juice Shop is the benchmark, not the target.
