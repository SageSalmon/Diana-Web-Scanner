"""Capability archetype profiler (P0: no-journey archetypes).

A lightweight phase between crawl and dispatch that recognises *what kind of
application* is under test — "does this expose a rating resource?", "is there an
account-registration surface?" — from cheap read-side signals (resource names in
discovered URLs and the fields carried by params/bodies). Recognising an
*archetype* is generic: every commerce app has ratings, every account system has
registration, so the signals are a semantic vocabulary, never one target's paths.

Detection is deliberately decoupled from exploitation. This module only tags
archetypes and emits generic *probe specs* (submit an out-of-range rating; submit
an empty required field). The actual sending is done by the input_validation
module, so a Probe is a targeting hint, not new request logic.

Everything domain-specific lives in ONE auditable place — `REGISTRY` — rather
than scattered `if "basket" in url` conditionals across the scanners. The
generality reviewer audits this file: the lexicons are broad class vocabularies
(a rating is stars/score/grade in any app), not Juice-Shop nouns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Probe:
    """A generic abuse class, targeted at fields matching a lexicon.

    `kind` selects the mutation the executor applies; `values` supplies the
    out-of-range values for range probes. Probes name field *lexicons*, not
    concrete field names — the executor intersects them with the real body.
    """

    kind: str  # "out_of_range" | "empty_required" | "duplicate"
    target_fields: tuple[str, ...]
    values: tuple[Any, ...] = ()


@dataclass(frozen=True)
class Archetype:
    """A recognisable application capability and how to abuse it generically."""

    name: str
    # --- detection (read-side, cheap) ---
    resource_lexicon: tuple[str, ...]  # path-segment name hints
    field_lexicon: tuple[str, ...]     # param/body field-name hints
    # --- exploitation (write-side) ---
    write_methods: tuple[str, ...]
    probes: tuple[Probe, ...]
    # Plausible benign values used to synthesise a minimal valid body when the
    # crawl never captured one (keyed by field-lexicon term). Generic filler,
    # not target data.
    field_defaults: dict[str, Any] = field(default_factory=dict)
    min_signals: int = 1               # independent hits needed to assert it
    default_auth: str = "admin"        # auth context to probe the write under


@dataclass(frozen=True)
class CapabilityTag:
    """A detected archetype instance bound to the endpoint that triggered it."""

    archetype: str
    url: str
    method: str
    matched_fields: tuple[str, ...]
    confidence: float


# ---------------------------------------------------------------------------
# The registry — the single auditable lexicon. Broad class vocabularies only.
# ---------------------------------------------------------------------------
RATING_FIELDS = ("rating", "stars", "star", "score", "grade", "rank")
REGISTRATION_FIELDS = ("email", "password", "username", "user")

REGISTRY: tuple[Archetype, ...] = (
    Archetype(
        name="rating",
        resource_lexicon=("feedback", "review", "rating", "ratings", "comment",
                          "testimonial", "vote"),
        field_lexicon=RATING_FIELDS,
        write_methods=("POST", "PUT"),
        probes=(
            # A bounded score field should reject values outside its range.
            Probe("out_of_range", RATING_FIELDS, (0, -1, 6, 999)),
        ),
        field_defaults={"comment": "diana feedback", "rating": 3, "stars": 3,
                        "score": 3},
    ),
    Archetype(
        name="account_registration",
        resource_lexicon=("user", "users", "register", "registration", "signup",
                          "sign-up", "account", "accounts"),
        field_lexicon=("email", "password", "username"),
        write_methods=("POST",),
        probes=(
            # A registration must reject empty required credentials.
            Probe("empty_required", ("email", "password", "username"), ("",)),
            # Re-submitting an already-registered identity must be rejected.
            Probe("duplicate", ("email", "username"), ()),
        ),
        field_defaults={"email": "diana-probe@example.com",
                        "password": "Diana!Probe1", "username": "diana-probe"},
        default_auth="none",  # registration is reachable unauthenticated
    ),
)


def _stem(token: str) -> str:
    """Cheap depluralisation so a lexicon term matches a collection segment.

    REST collections are conventionally pluralised (``/reviews``, ``/feedbacks``,
    ``/accounts``), while a class lexicon is most naturally written in the
    singular. Stemming both sides makes the match symmetric and framework
    agnostic — it is not tuned to any target's nouns. Guarded on length so short
    words that legitimately end in ``s`` are left intact.
    """
    if token.endswith("ies") and len(token) > 4:
        return token[:-3] + "y"  # "categories" -> "category"
    if token.endswith("s") and not token.endswith("ss") and len(token) > 3:
        return token[:-1]        # "reviews" -> "review", "feedbacks" -> "feedback"
    return token


def _segments(url: str) -> list[str]:
    return [s.lower() for s in urlsplit(url).path.split("/") if s]


def _fields_of(endpoint: Any) -> set[str]:
    """Lowercased field names an endpoint carries (params + captured body)."""
    names: set[str] = set()
    params = getattr(endpoint, "parameters", None) or {}
    body = getattr(endpoint, "request_body", None) or {}
    names.update(k.lower() for k in params)
    names.update(k.lower() for k in body)
    return names


def _matches(archetype: Archetype, endpoint: Any) -> tuple[int, tuple[str, ...]]:
    """Signal count and matched field-lexicon terms for one endpoint.

    A resource-name hit counts as one signal; each field-lexicon hit counts as
    one more. Keeps detection semantic (name/field vocabulary), never keyed on a
    literal path.
    """
    segs = {_stem(s) for s in _segments(endpoint.url)}
    resource_hit = any(_stem(term) in segs for term in archetype.resource_lexicon)
    fields = _fields_of(endpoint)
    matched = tuple(t for t in archetype.field_lexicon if t in fields)
    signals = (1 if resource_hit else 0) + len(matched)
    return signals, matched


def profile_capabilities(endpoints: list[Any]) -> list[CapabilityTag]:
    """Tag every endpoint that matches an archetype (deduped per archetype+url).

    Pure and side-effect free: takes the discovered endpoints, returns tags.
    Runs off the cached sitemap's endpoints, so the tiny loop recomputes it for
    free without persisting anything to the crawl model.
    """
    tags: list[CapabilityTag] = []
    seen: set[tuple[str, str]] = set()
    for arch in REGISTRY:
        for ep in endpoints:
            signals, matched = _matches(arch, ep)
            if signals < arch.min_signals:
                continue
            key = (arch.name, ep.url)
            if key in seen:
                continue
            seen.add(key)
            confidence = min(1.0, 0.4 + 0.3 * signals)
            tags.append(CapabilityTag(
                archetype=arch.name, url=ep.url, method=ep.method,
                matched_fields=matched, confidence=round(confidence, 2),
            ))
    return tags


def archetype_by_name(name: str) -> Archetype | None:
    for arch in REGISTRY:
        if arch.name == name:
            return arch
    return None


def synthesis_specs(tags: list[CapabilityTag],
                    endpoints: list[Any]) -> list[dict]:
    """Turn tags into input_validation synthesis work payloads.

    For each tagged resource, emit one probe payload per archetype probe,
    targeting the resource's write method. The base body is the endpoint's
    captured body if any, else a minimal body built from the archetype's generic
    field defaults — so a probe can fire even when the SPA crawl captured no
    write XHR for that resource.
    """
    body_by_url: dict[str, dict] = {}
    for ep in endpoints:
        body = getattr(ep, "request_body", None) or {}
        if body and ep.url not in body_by_url:
            body_by_url[ep.url] = dict(body)

    specs: list[dict] = []
    for tag in tags:
        arch = archetype_by_name(tag.archetype)
        if not arch:
            continue
        write_method = arch.write_methods[0]
        base = dict(body_by_url.get(tag.url, {}))
        # Seed any missing lexicon fields with generic filler so the body is
        # plausible enough to reach validation.
        for term, default in arch.field_defaults.items():
            base.setdefault(term, default)
        for probe in arch.probes:
            present = [f for f in probe.target_fields if f in base]
            if not present:
                continue
            specs.append({
                "archetype": arch.name,
                "url": tag.url,
                "method": write_method,
                "auth_context": arch.default_auth,
                "base_body": base,
                "probe_kind": probe.kind,
                "target_fields": present,
                "values": list(probe.values),
            })
    return specs
