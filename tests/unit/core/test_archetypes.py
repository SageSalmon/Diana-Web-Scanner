"""Tests for the capability archetype profiler.

All inputs are synthetic Endpoint-like objects — no live target, no Juice Shop
fixtures. The profiler must key on generic name/field vocabulary, never on a
literal path, so the tests use neutral URLs (/shop/reviews, /accounts) that a
Django or Rails app could equally expose.
"""

from __future__ import annotations

from types import SimpleNamespace

from diana.core.archetypes import (
    profile_capabilities,
    synthesis_specs,
)


def _ep(url, method="GET", parameters=None, request_body=None):
    return SimpleNamespace(
        url=url, method=method,
        parameters=parameters or {}, request_body=request_body or {},
    )


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_detects_rating_from_resource_and_field():
    eps = [_ep("http://x/shop/reviews", "POST",
               request_body={"rating": 5, "comment": "ok"})]
    tags = profile_capabilities(eps)
    assert any(t.archetype == "rating" for t in tags)


def test_detects_registration_from_fields_only():
    # Neutral path — matched purely on email+password field vocabulary.
    eps = [_ep("http://x/accounts", "POST",
               request_body={"email": "a@b.c", "password": "x"})]
    tags = profile_capabilities(eps)
    reg = [t for t in tags if t.archetype == "account_registration"]
    assert reg
    assert set(reg[0].matched_fields) >= {"email", "password"}


def test_no_false_positive_on_unrelated_endpoint():
    eps = [_ep("http://x/api/products", "GET", parameters={"q": "abc"})]
    tags = profile_capabilities(eps)
    assert tags == []


def test_generic_vocabulary_not_target_paths():
    # A totally different app's nouns still match on lexicon.
    eps = [
        _ep("http://blog/testimonial", "POST", request_body={"stars": 4}),
        _ep("http://api/signup", "POST", request_body={"email": "x", "password": "y"}),
    ]
    names = {t.archetype for t in profile_capabilities(eps)}
    assert names == {"rating", "account_registration"}


def test_dedupes_per_archetype_and_url():
    eps = [_ep("http://x/reviews", "POST", request_body={"rating": 1})] * 3
    tags = [t for t in profile_capabilities(eps) if t.archetype == "rating"]
    assert len(tags) == 1


def test_matches_pluralised_collection_segment():
    # A REST collection pluralises the resource noun; the singular lexicon term
    # must still match. Framework-agnostic: same for /reviews, /feedbacks, etc.
    for path in ("http://x/api/feedbacks/1", "http://x/reviews", "http://x/votes"):
        tags = profile_capabilities([_ep(path, "GET", parameters={"id": "1"})])
        assert any(t.archetype == "rating" for t in tags), path


def test_stemming_does_not_overmatch_short_words():
    # A short word ending in 's' that is not a plural must not be truncated into
    # a spurious lexicon hit.
    tags = profile_capabilities([_ep("http://x/gas", "GET", parameters={"q": "1"})])
    assert tags == []


# ---------------------------------------------------------------------------
# Synthesis specs
# ---------------------------------------------------------------------------

def test_rating_synthesis_targets_out_of_range():
    eps = [_ep("http://x/reviews", "POST", request_body={"rating": 5, "comment": "c"})]
    tags = profile_capabilities(eps)
    specs = synthesis_specs(tags, eps)
    oor = [s for s in specs if s["archetype"] == "rating" and s["probe_kind"] == "out_of_range"]
    assert oor
    assert 0 in oor[0]["values"] and -1 in oor[0]["values"]
    assert "rating" in oor[0]["target_fields"]


def test_registration_synthesis_has_empty_and_duplicate():
    eps = [_ep("http://x/register", "POST",
               request_body={"email": "a@b.c", "password": "x"})]
    tags = profile_capabilities(eps)
    kinds = {s["probe_kind"] for s in synthesis_specs(tags, eps)
             if s["archetype"] == "account_registration"}
    assert {"empty_required", "duplicate"} <= kinds


def test_synthesis_fills_missing_fields_from_defaults():
    # No captured body: profiler must synthesise plausible filler so the probe
    # body is complete enough to reach validation.
    eps = [_ep("http://x/accounts/signup", "POST")]  # matched on resource lexicon
    tags = profile_capabilities(eps)
    specs = synthesis_specs(tags, eps)
    reg = [s for s in specs if s["archetype"] == "account_registration"]
    assert reg
    assert "email" in reg[0]["base_body"] and "password" in reg[0]["base_body"]


def test_registration_probes_unauthenticated():
    eps = [_ep("http://x/register", "POST", request_body={"email": "a", "password": "b"})]
    specs = synthesis_specs(profile_capabilities(eps), eps)
    reg = [s for s in specs if s["archetype"] == "account_registration"]
    assert all(s["auth_context"] == "none" for s in reg)
