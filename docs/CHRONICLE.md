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

## Iteration 4 — Make access_control work + tiny-loop tooling (2026-06-26) ✓ MERGED

**Solve rate: 7.1% → 7.1% (unchanged)**  |  access_control findings: 0 → 26 (2 CRITICAL, 24 HIGH)
**Cost: ~$3 (1 seed + 3 cached tiny-loop runs)**  |  Cumulative: ~$5.75

A capability win the solve-rate metric doesn't capture. Enabled the
access_control module by default — then discovered, via a new fast inner-loop
harness, that it was broken end-to-end and fixed it across four iterations.

**New tooling — the tiny loop (`agent-tinyloop`):** a lean iteration harness in
the same AWS sandbox as validation. It reuses a cached crawl (`--sitemap-cache`)
to skip the expensive Playwright crawl, runs only the module under test, and
asserts against the Juice Shop scoreboard. First (seed) run 2660s; cached runs
**~530–580s (4.5× faster)**. Reuses the validation task definition via an
`AGENT_ENTRYPOINT` env shim — no Terraform change. This made the four-iteration
debug loop below cheap enough to do in an afternoon.

**Four blockers found and fixed (each surfaced by one tiny-loop run):**
1. The deterministic authenticated IDOR/method/role sweep only ran in the
   no-AI fallback — the AI agent fixated on easy unauthenticated reads and never
   did the authenticated sweep. → always run the deterministic sweep.
2. `report_finding` had no dedup — one flaw reported ~25× (78 noise findings).
   → dedup by (title, endpoint, method).
3. The orchestrator dispatch dropped endpoint parameters (`has_params` only), so
   the sweep's `"id" in ep.parameters` gate matched nothing. → pass parameters.
4. `claim_work(50)` claimed only the first ~16 endpoints; the numeric-id
   resources sit at sitemap positions 57–68. → claim the full queue + dedup
   endpoints across auth levels.

**Result:** access_control now authenticates as both admin and a low-priv user,
sweeps every id-endpoint, and produces **26 confirmed authorization findings**
(real IDOR: a low-priv user reads `/api/Users/2`, `/api/Feedbacks/2`,
`/api/BasketItems/2`, etc.). All scanner logic stays framework-agnostic
(generality PASS) — it tests whatever the crawler discovers, no target paths.

**The honest boundary:** the 5 targeted Broken Access Control challenges stayed
**0/5 solved**. Juice Shop's scoreboard fires only on the *exact* exploit
fingerprint (e.g. `GET /rest/basket/{id}`, a meaningful `PUT` body, a forged
`UserId` on `POST /api/Feedbacks`), which differs from generic IDOR detection.
Closing that gap would require target-specific exploit code that the generality
gate correctly rejects. So solve-rate is a poor proxy here: the scanner got
materially better at finding real authorization flaws (0 → 26) without the
benchmark moving.

Next opportunities:
- Generalizable exploit primitives that may also fingerprint-match: test
  `/rest/basket/{id}` style resource paths, meaningful PUT bodies, forged-id
  POSTs — staying framework-agnostic.
- Apply the tiny loop to cheaper modules (Input Validation, headers) where fast
  iteration pays off even more than for the AI-heavy access_control module.

---

## Iteration 6 — Sensitive Data Exposure scanner (2026-07-07) ✓ MERGED

**Solve rate: 9.7% → 14.2% (11/113 → 16/113, +5 net)**  |  Findings: 200 (2 critical, 36 high)
**Cost: ~$0.20 Fargate (Bedrock tokens not captured this run)**  |  Cumulative: ~$6

The largest single-iteration jump so far. Built a generic `sensitive_data_exposure`
scanner that attacks exposed content three ways, all driven off whatever the
crawler discovered: **open directory listings** (serve-index style, recursing
into subdirectories up to depth 2), **backup-file probing** (`.bak ~ .old .orig`
… on discovered static files), and **poison-null-byte extension-filter bypass**
(`%00`/`%2500` + an allowed tail once a direct fetch is blocked). Soft-404s are
suppressed by body-head comparison, not response length, so SPA shells don't
generate phantom findings.

**Six new solves (one over the tiny-loop's prediction of five):**
- *Confidential Document*, *Misplaced Signature File*, *Easter Egg* — open
  directory-listing exposure.
- *Forgotten Sales Backup*, *Forgotten Developer Backup* — backup-file probes.
- *Poison Null Byte* — the extension-filter bypass registered its own challenge.

Sensitive Data Exposure category 0→3/16 (the rest of the new solves score under
Miscellaneous/other categories). All logic is framework-agnostic (generality
PASS): candidate directories are ancestors of discovered paths plus a generic
wordlist, with no target paths or challenge fingerprints. 11 new unit tests pass.

**One non-causal regression:** *Repetitive Registration* (Improper Input
Validation, from Iteration 5) dropped. It's solved by the untouched
`input_validation` module — which actually ran *harder* this run (178 probes /
143 findings vs. 174 / 133) and still solved its sibling *Admin Registration*.
The SDE module runs `auth=none` against different paths and never touches
registration, so there is no causal path; the challenge needs the same signup
POSTed several times in sequence and is inherently scoreboard-race sensitive.
Counted against the +6 for a net +5.

**The harness bug that cost three runs:** the scanner, registry, config, and
orchestrator dispatch were all correct, yet three full validations returned
10/113 with `sensitive_data_exposure` absent from the Queue-dispatch block. Root
cause was two layers deep: `scripts/entrypoint-validation.sh` passes an explicit
`--modules` list that overrides the `config.py` defaults and never listed the new
module (the tiny-loop passes `--modules` explicitly, which is why it saw the
solves and the full scan didn't); and once fixed, the commit sat **unpushed**
while CodeBuild builds from the *remote* branch. Lesson recorded: enabling a new
module means updating the entrypoint `--modules` lists, and a branch must be
pushed before `run-agent-task.sh` will build the change.

---

## Iteration 5 — Input Validation module + SPA body capture (2026-07-02) ✓ MERGED

**Solve rate: 7.1% → 9.7% (8/113 → 11/113, +3)**  |  Findings: 214 (14 critical, 30 high)
**Cost: ~$0.20 Fargate (Bedrock tokens not captured this run)**  |  Cumulative: ~$6

The first metric-moving iteration since access_control — and the solves are
causally attributable to the change, with **zero regressions**. Built a generic
`input_validation` scanner (replay-and-mutate: takes discovered request
bodies/params and resubmits them with zero/negative/empty/null/oversized/
type-mismatch values, flagging invalid-input-accepted) plus **SPA XHR body
capture** in the crawler (`page.on("request")` + best-effort fill-and-submit) so
POST/PUT payloads are actually discovered for mutation.

**Three new solves, all traceable to the change:**
- *Admin Registration* (d3) and *Repetitive Registration* (d1) — both Improper
  Input Validation, the exact class the scanner targets (category 0→2 / 12).
- *Five-Star Feedback* (d2, Broken Access Control) — surfaced because the new
  SPA body capture fed a POST body into the downstream access_control sweep.

All logic stays framework-agnostic (generality PASS): it mutates whatever the
crawler discovers, with no target paths or exploit fingerprints. Full
`agent-validation` was used (not the tiny loop) because the crawler changed,
invalidating the cached-crawl shortcut. 31 new unit/integration tests pass; the
two pre-existing XSS failures in `test_xss.py` are unrelated and unchanged.

**The honest boundary (as predicted):** cart/checkout challenges like *Payback
Time* stayed unsolved. They need authenticated, multi-step journeys that passive
body capture cannot synthesize — the motivating case for the proposed Iteration
6 archetype profiler (`docs/FUTURE_ARCHETYPE_PROFILER.md`): crawl → profile (tag
archetypes) → dispatch matching playbooks, gating cart-journey exploitation to
detected shopping-cart archetypes.

Next opportunities (from the gap analysis):
- **Sensitive Data Exposure (0/16)** — largest untouched category, highest
  real-world value: content/path discovery (well-known paths, backup
  extensions, source-map exposure). Top pick.
- Extend injection probes to the request bodies the SPA capture now discovers
  (Injection tail 3/14).
- The archetype profiler to unlock authenticated multi-step BAC/cart journeys.

Housekeeping: `token_usage` came back empty this run — the emitter needs a fix
so future runs record Bedrock cost.

---
