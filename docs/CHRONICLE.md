# Diana Agent Team — Chronicle

## Iteration 0 — Baseline (2026-06-06)

**Solve rate: 6.2% (7/112)**  |  Duration: 1708s  |  Tests: 0
**Cost: ~$0.50 (1 scan)**  |  Cumulative: ~$0.50

First successful end-to-end validation scan. Established baseline: 7 challenges
solved (3 Injection, 1 Broken Auth, 1 Security Misconfig, 1 Misc, 1 Observability).
Biggest gaps: Sensitive Data Exposure (0/16), Broken Access Control (0/12),
Improper Input Validation (0/12), XSS (0/9).

---

## Iteration 1 — XSS Detection Fixes (2026-06-07) ✗ REJECTED

**Solve rate: 6.2% → 6.2% (+0%)**  |  Duration: 1708s → 1646s  |  Tests: 21 written (not yet run)
**Cost: ~$0.75 (3 scans, 1 attempt)**  |  Cumulative: ~$1.25

Fixed three bugs in the static XSS scanner: GET params never reaching the
server, canary insertion failing for AI-generated payloads, and overly strict
reflection detection requiring exact payload match. Added DOM XSS source/sink
static analysis. Code passed generality review and test critique (21 tests).

However, solve rate did not improve — 0/9 XSS challenges still missed. The
detection logic is now correct but the root cause is upstream: the crawler
likely isn't discovering the vulnerable endpoints, or the parameters aren't
being dispatched to the XSS queue. Next iteration should investigate the
crawl-to-queue pipeline or try a different improvement target (Access Control
0/12, Input Validation 0/14).

---

## Iteration 2 — Crawl-to-Queue Diagnostics (2026-06-07) ✓ MERGED

**Solve rate: 6.2% → 6.2% (+0%)**  |  Duration: 1650s  |  Tests: 21
**Cost: ~$0.50 (1 scan)**  |  Cumulative: ~$1.75

Added diagnostic logging to the orchestrator: crawl results and per-module
queue stats after dispatch. Key discoveries:

- Crawler finds 69 endpoints, 20 with params, 12 POST — but **0 HTML forms**
  (Juice Shop is a pure SPA, all forms are Angular-rendered)
- XSS queue gets 31 items including `/rest/products/search?q=` — the scanner
  IS running, but Juice Shop's XSS is in client-side DOM rendering of JSON API
  responses, not in server-rendered HTML
- access_control module gets 0 items — not in the default module list
- AI validator rejected 30 false positives — actively working

Root cause confirmed: **SPA rendering gap**. The scanner sees JSON API responses
but XSS lives in how the Angular frontend renders that JSON into the DOM. This
requires either Playwright-based response analysis or testing the hash-route
URLs that Angular renders.

Next: try Access Control or Input Validation (less SPA-dependent), or enable
Playwright rendering for XSS detection.

---

## Iteration 3 — Enable Playwright SPA Crawling (2026-06-09) ✓ MERGED

**Solve rate: 6.2% → 7.1% (+0.9%)**  |  Duration: 1708s → 1394s  |  Tests: 21
**Cost: ~$1.00 (2 scans across old+new repo)**  |  Cumulative: ~$2.75

First solve rate improvement. Enabled the previously disabled Playwright browser
phases by running them in asyncio.to_thread(). The SPA crawler now discovers 49
client-side routes, renders 15 with headless Chromium, and tests DOM XSS by
injecting payloads into URL parameters and checking for alert dialog execution.

Unlocked: **DOM XSS (1*)** — Playwright navigated to hash routes with XSS payloads
and detected an alert dialog firing, confirming DOM-based cross-site scripting.
Also fixed Playwright browser path (/opt/playwright) so the non-root diana user
can access Chromium binaries.

Scan duration decreased 18% despite adding browser rendering — likely due to
Playwright discovering routes that helped the AI agents work more efficiently.

This is the first complete iteration loop with a successful improvement:
baseline → implement → generality pass → AWS validation → merge → chronicle.

Next opportunities:
- Access Control (0/12) — add to default module list, test auth level variations
- Reflected XSS via rendered DOM — Playwright renders pages but we only test
  hash-route injection; could also check if API response data is reflected
  unsanitized in the rendered page
- Input Validation fuzzing (0/14) — zero/empty/boundary values on API endpoints

---
