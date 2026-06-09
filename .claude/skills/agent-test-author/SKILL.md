---
name: agent-test-author
description: Write tests for code changes made by the Improvement Agent
user_invocable: true
---

# Test Author Agent

Write unit and integration tests for code changes on the current feature branch. Tests must be meaningful, generic, and catch real regressions.

## Arguments

- `branch` (optional) — branch to write tests for. Defaults to current branch.

## Instructions

### Step 1: Identify What Changed

```bash
BRANCH="${ARGUMENTS_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
git diff main..."$BRANCH" --name-only
```

Read each changed file to understand what was added or modified.

### Step 2: Determine Test Strategy

For each changed component, decide what tests are needed:

| Change Type | Test Type | Location |
|---|---|---|
| New scanner module | Unit: test payload generation, response parsing. Integration: test against mock HTTP responses | `tests/unit/scanners/` |
| Modified scanner logic | Unit: test new detection paths + regression for existing paths | `tests/unit/scanners/` |
| Crawler changes | Unit: test URL/form extraction. Integration: test against mock HTML pages | `tests/unit/core/` |
| Orchestrator changes | Integration: test phase execution order, queue routing | `tests/integration/` |
| New vuln type / model changes | Unit: test enum values, model validation | `tests/unit/core/` |
| AI prompt changes | Unit: test prompt construction with various inputs | `tests/unit/ai/` |

### Step 3: Write Tests

**Rules:**

1. **No live targets.** Unit tests use `unittest.mock` or `pytest` fixtures with synthetic HTTP responses. Never connect to Juice Shop, DVWA, or any external service.

2. **No target-specific fixtures.** Don't capture a Juice Shop response and use it as test data. Create synthetic responses that represent the CLASS of response (e.g., "a page with a reflected parameter" not "Juice Shop's search page").

3. **Test behavior, not implementation.** Assert on what the scanner FINDS, not on internal method calls. If you refactor the scanner internals, the tests should still pass.

4. **Test failure modes.** Every happy-path test needs a corresponding test where the vulnerability is NOT present and the scanner correctly reports nothing.

5. **Test edge cases.** Empty responses, timeouts, malformed HTML, non-UTF8 content, redirects, binary content.

6. **Use descriptive names.** `test_xss_scanner_detects_reflected_param_in_html_attribute` not `test_xss_1`.

7. **Keep tests fast.** No `sleep`, no network calls, no subprocess spawning. Unit tests should complete in under 1 second each.

### Step 4: Create Test Directory Structure

If test directories don't exist yet:
```
tests/
  unit/
    __init__.py
    scanners/
      __init__.py
      test_<module>.py
    core/
      __init__.py
      test_<module>.py
    ai/
      __init__.py
      test_<module>.py
  integration/
    __init__.py
    test_<feature>.py
  conftest.py          # shared fixtures
```

### Step 5: Write conftest.py If Needed

If `tests/conftest.py` doesn't exist, create shared fixtures:
- `mock_http_client` — returns configurable mock responses
- `sample_endpoint` — creates an Endpoint model with common defaults
- `sample_sitemap` — creates a SiteMap with a few endpoints and forms

### Step 6: Commit Tests

```bash
git add tests/
git commit -m "Add tests for <description of what's being tested>

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

### Step 7: Report

Tell the user:
- How many test files created/modified
- How many test functions written
- What's covered and what's explicitly NOT covered (and why)
- That the branch is ready for `/agent-test-critic`

## Notes

- This agent writes tests but does NOT run them. The Test Critic reviews them, then the Test Runner executes on AWS.
- If the test suite was previously empty, note that this is bootstrapping coverage — not all existing code will be covered, only the new/changed code.
