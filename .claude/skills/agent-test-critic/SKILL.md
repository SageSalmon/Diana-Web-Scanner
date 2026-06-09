---
name: agent-test-critic
description: Review tests for correctness, completeness, and independence — reject vacuous or target-specific tests
user_invocable: true
---

# Test Critic Agent

Review tests written by the Test Author Agent. Ensure they are correct, complete, independent, and generic. A test that passes regardless of whether the code works is worse than no test.

## Arguments

- `branch` (optional) — branch to review. Defaults to current branch.

## Instructions

### Step 1: Identify Test Files

```bash
BRANCH="${ARGUMENTS_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
git diff main..."$BRANCH" --name-only -- 'tests/'
```

Read each test file. Also read the source code being tested so you can evaluate whether the tests actually cover the behavior.

### Step 2: Evaluate Each Test Function

For every test function, answer these five questions:

#### 2a. Correctness
- Does the assertion actually test what the test name claims?
- Are mock return values realistic? (A mock that returns `None` when the real function returns a `Finding` object is testing nothing.)
- Is the test asserting on the RIGHT thing? (Asserting that a method was called is weaker than asserting what it returned.)

#### 2b. Completeness
- Is the happy path tested? (Vulnerability IS present → scanner detects it)
- Is the negative path tested? (Vulnerability is NOT present → scanner reports nothing)
- Are edge cases tested? (Empty response, timeout, malformed input, non-ASCII content)
- If the code has branching logic (if/else, try/except), is each branch exercised?

#### 2c. Independence (The Mutation Test)
For each test, perform this mental exercise:
> "If I deleted the feature this test covers, would the test fail?"

If the answer is no, the test is vacuous. Common causes:
- Asserting on mock behavior rather than real logic
- Testing that a function runs without error rather than testing its output
- Over-mocking: the test is exercising the mock framework, not the code

#### 2d. Generality
- Do test fixtures contain Juice Shop-specific data? (Endpoint paths, response bodies, challenge names)
- Would the test still make sense if Diana was scanning a Django app instead?
- Are assertions tied to a specific target's behavior?

#### 2e. Isolation
- Unit tests must not require network, database, or filesystem access
- Integration tests must be clearly marked (`@pytest.mark.integration` or in `tests/integration/`)
- No test should depend on another test's side effects (ordering independence)

### Step 3: Produce Verdict

**If all tests pass review:**
```
TEST CRITIC: PASS
Branch: <branch>
Tests reviewed: <count>
Notes: <any positive observations>
```

**If issues found:**
```
TEST CRITIC: FAIL
Branch: <branch>

ISSUES:
- <file>::<test_name> — <issue type>
  Problem: <what's wrong>
  Fix: <specific suggestion>

- <file>::<test_name> — ...

SUMMARY: <N> tests reviewed, <M> issues found
```

### Step 4: Report

If FAIL, tell the user the tests need rework by `/agent-test-author` before proceeding. If PASS, tell them the branch is ready for AWS validation (Step 5 in the handoff chain: `/agent-validation`, `/agent-test-runner`, `/agent-benchmark` in parallel).

## The Standard

A good test suite for a security scanner should:
1. Catch regressions when detection logic changes
2. Fail when a scanner would miss a vulnerability it previously caught
3. NOT give false confidence by passing when the scanner is broken
4. Work against any web application, not just the benchmark target
