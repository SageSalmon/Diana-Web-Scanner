# Capability Archetype Profiler — Design

> Status: **proposed** (design-first; not yet built). Substrate dependency:
> the generic `input_validation` module (Iteration 5).

## Problem

Some of the highest-value vulnerabilities are **business-logic abuses** tied to
a specific *kind* of application: a negative shopping-cart quantity (Payback
Time), a zero-star rating (Zero Stars), a forged price (Product Tampering). The
naive ways to chase these are both bad:

1. **Special-case the target** — `if "basket" in url: test_negative_quantity()`.
   Fast to write, but it only works against Juice Shop and the generality gate
   correctly rejects it.
2. **Always-on heavy machinery** — run authenticated multi-step "add to cart,
   mutate quantity, checkout" journeys on *every* scan. Generic, but wasteful:
   on a blog or marketing site that whole apparatus runs and finds nothing, and
   it bloats every module with cart/rating/account conditionals that rarely fire.

This design takes a third path: **detect the application's capability archetypes
first, then invoke only the matching abuse playbooks.** It turns a
special-casing problem into an *orchestration* problem.

## Core idea

Insert a lightweight **profiling phase** between crawl and dispatch:

```
crawl → PROFILE (tag archetypes) → dispatch only the relevant playbooks → test
```

"Is this a shopping cart?" is a **generic** question — every e-commerce app has
carts — so recognizing the *archetype* stays framework-agnostic as long as the
signals are semantic patterns (a resource carrying `quantity`/`price` line
items), never the literal string `/api/BasketItems`.

Detection is deliberately decoupled from exploitation:

- **Detection runs on read-side signals** that are cheap and already available
  (resource names in discovered GETs, JS route names, DOM buttons, field
  vocab). It does **not** require the expensive write-side endpoints.
- **Exploitation (incl. authenticated multi-step journeys) is gated** — it only
  spins up for archetypes the profiler actually found.

So on a site with no cart, the cart journey machinery never starts.

## Design philosophy / generality contract

The generality gate's real concern is not "does the word cart appear" — it's
"would this code do something useful against an arbitrary app of this class."
This design satisfies that by construction:

- **One auditable lexicon.** All the domain vocabulary lives in a single
  archetype registry, not scattered `if` statements across modules. The
  generality reviewer audits one file.
- **Breadth over specificity.** The cart lexicon is a *commerce vocabulary*
  (cart, basket, bag, trolley, order, checkout, line-item, sku, quantity,
  price, total…), not one app's nouns.
- **AI for the judgment call.** "Does this resource look like a shopping cart?"
  is exactly the kind of semantic call an LLM generalizes well. The registry
  carries an optional classifier prompt; the deterministic lexicon is the cheap
  first pass and the AI is the confirmation/expansion pass.
- **Playbooks are generic abuse classes**, not exploits: "submit an
  out-of-range value for a bounded numeric field" is generic; "POST rating=0 to
  /api/Feedbacks" is not.

## Archetype registry schema

A declarative registry — each entry is data, not code:

```python
@dataclass(frozen=True)
class Archetype:
    name: str                      # "commerce_cart", "rating", "account_registration"
    # --- detection (read-side, cheap) ---
    resource_lexicon: tuple[str, ...]   # name hints: cart, basket, order, checkout...
    field_lexicon: tuple[str, ...]      # body/param hints: quantity, qty, price, total...
    route_lexicon: tuple[str, ...]      # SPA route hints: basket, order-completion...
    ai_classifier_prompt: str | None    # "Does this resource represent a shopping cart?"
    min_signals: int = 1                # how many independent hits to assert the archetype
    # --- exploitation (write-side, gated) ---
    playbook: tuple[Probe, ...]         # which abuse classes to apply
    requires_journey: bool = False      # needs an authed multi-step setup to reach


@dataclass(frozen=True)
class Probe:
    kind: str          # "numeric_out_of_range" | "negative" | "empty_required" | "client_price"
    target_fields: tuple[str, ...]   # field lexicon this probe applies to (e.g. quantity)
    # Probes are executed by an existing module (input_validation today), so a
    # Probe is a *targeting hint*, not new sending logic.
```

Initial registry (illustrative):

| Archetype | Detect on | Playbook | Journey? |
|---|---|---|---|
| `commerce_cart` | cart/basket/order/checkout resources, `quantity`/`price` fields, `order-completion` route | negative & zero & fractional quantity; client-supplied price | **yes** |
| `rating` | `rating`/`stars`/`score` field in a 1–5 range | out-of-range (0, 6, −1), non-integer | no |
| `account_registration` | create endpoint with `email`+`password` | empty / missing required fields | no |

## Where it lives in the orchestrator

A new phase in `ScanOrchestrator.scan()`, between the existing seams
(`orchestrator.py`):

```
  sitemap = await self._obtain_sitemap()          # ~line 183 (existing)
+ sitemap.capabilities = await self._profile_capabilities(sitemap)   # NEW
  self._dispatch_to_queues(sitemap, modules)      # ~line 216 (existing, now archetype-aware)
```

- **Carrier:** add `capabilities: list[CapabilityTag]` to `SiteMap`
  (`models.py`). A `CapabilityTag` records the archetype name, the
  endpoints/fields that triggered it, and a confidence. This rides along in the
  cached sitemap JSON like any other field, so the tiny-loop cache benefits too.
- **`_profile_capabilities`** does the deterministic lexicon pass over
  `sitemap.endpoints` / `forms` / `static_files` (JS route names) first; if
  `self.ai_agent` is present and a candidate is borderline, it confirms via the
  AI classifier prompt — mirroring the existing `ai_agent.analyze_surface(sitemap)`
  hook already called at ~line 229.
- **Dispatch becomes archetype-aware:** the `input_validation` branch in
  `_dispatch_to_queues` enqueues a field's negative/zero probes *only* when an
  archetype tagged that endpoint/field, instead of blanket-fuzzing every field.
  This shrinks noise and request budget.

## Journey-gating contract

The expensive part — driving an authenticated, multi-step flow so a write XHR
(e.g. `POST /api/BasketItems`) fires and gets captured — is **owned by the
crawler/journey layer and invoked only when** `requires_journey` archetypes are
present:

```
profiler finds `commerce_cart`  →  orchestrator schedules a CartJourney:
    1. ensure an authenticated session (reuse existing auth: http._auth_headers
       / state.get_auth, same as access_control)
    2. perform the generic journey: list products → add an item → open the
       collection resource → observe the create/update XHR (captured via the
       existing page.on("request") body capture from Iteration 5)
    3. the observed body flows into SiteMap.endpoints as a request_body endpoint
    4. input_validation replays-and-mutates it (quantity → -1) — existing logic
```

The journey is described generically ("find an add-to-collection affordance and
exercise it"), and if it fails (captcha, unexpected UI) it degrades to no-op —
no archetype-specific assertions, no scoreboard fingerprints.

## How it composes with what already exists

- **`input_validation` (built, I5)** is the execution arm — unchanged sending
  logic; it just receives archetype-targeted work instead of blanket work.
- **`access_control`** can consume the same tags (e.g. only run cross-user IDOR
  on resources an archetype marks as user-owned).
- **Detect once, reuse everywhere** — the profiler is a shared upstream phase,
  not per-module logic.

## Generality analysis (what the gate will check)

| Concern | Mitigation |
|---|---|
| Lexicon is Juice-Shop-flavored | Use broad commerce/account/rating vocab; document each term's general rationale; cover ≥3 unrelated apps in review reasoning |
| "Cart journey" hardcodes one UI | Journey is described as generic affordances (add-to-collection button, quantity input); failure is a clean no-op |
| Profiler keys on exact paths | Profiler keys on *name/field/route lexicon + AI*, never exact URLs |
| Playbook encodes the exploit | Playbook is abuse *classes* (out-of-range, negative, empty); the value sent is generic, the target is discovered |

## Risks & open questions

1. **Chicken-and-egg detection.** If even read-side signals are absent (an
   unusual SPA), the archetype isn't detected and the playbook never runs.
   Acceptable: it degrades to today's behavior, never worse.
2. **AI cost/latency of classification.** Keep the deterministic pass as the
   default; only invoke the AI for borderline candidates. Bounded.
3. **Journey fragility.** The cart journey is the riskiest, most app-variable
   piece. Recommend building rating/registration (no journey) first to prove the
   profiler end-to-end cheaply, then tackle the cart journey.
4. **Where do tags persist?** Proposed on `SiteMap.capabilities`; revisit if the
   DB-backed queue needs them at claim time (may need a `capability` column on
   the queue item).

## Suggested phased rollout

- **P0 — Profiler + no-journey archetypes.** Registry, `_profile_capabilities`,
  `SiteMap.capabilities`, archetype-aware dispatch. Wire `rating` and
  `account_registration` (no journey). Proves the orchestration end-to-end and
  can already sharpen `input_validation` targeting. Tiny-loop friendly (no
  crawler change).
- **P1 — Cart journey.** Add the gated authenticated multi-step capture for
  `commerce_cart`. Crawler-touching → full `agent-validation` gate.
- **P2 — Reuse tags in other modules** (access_control, etc.).

## Decision needed

Whether to build P0 on top of the merged I5 module, or fold the profiler into
the current branch before any validation. Recommendation: merge I5 first
(generic substrate), then P0 as Iteration 6.
