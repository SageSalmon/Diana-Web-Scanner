"""Tests for the input_validation scanner — mutation generation, anomaly
detection, bounds, and auth routing.

All inputs are synthetic. No live target, no Juice Shop fixtures. HTTP is
intercepted with respx so no real network calls are made.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from diana.core.models import VulnType
from diana.scanners.input_validation import (
    MAX_REQUESTS,
    OVERSIZED,
    InputValidationScanner,
    _mutations_for,
)

# ---------------------------------------------------------------------------
# _mutations_for — type-aware mutation generation
# ---------------------------------------------------------------------------

class TestMutationGeneration:
    def test_numeric_includes_zero_and_negative(self):
        labels = {m[0] for m in _mutations_for(5)}
        assert {"zero", "negative", "negative-large", "overflow"} <= labels

    def test_numeric_zero_value_is_actually_zero(self):
        by_label = {m[0]: m[1] for m in _mutations_for(5)}
        assert by_label["zero"] == 0
        assert by_label["negative"] == -1

    def test_float_treated_as_numeric(self):
        labels = {m[0] for m in _mutations_for(2.5)}
        assert "negative" in labels and "zero" in labels

    def test_string_includes_empty_oversized_null(self):
        labels = {m[0] for m in _mutations_for("hello")}
        assert {"empty", "oversized", "null", "null-byte"} <= labels
        by_label = {m[0]: m[1] for m in _mutations_for("hello")}
        assert by_label["empty"] == ""
        assert by_label["oversized"] == OVERSIZED

    def test_bool_not_mistaken_for_int(self):
        # bool is a subclass of int; it must use the boolean branch, so it should
        # NOT generate the numeric 'zero'/'negative' probes.
        labels = {m[0] for m in _mutations_for(True)}
        assert "zero" not in labels
        assert "negative" not in labels

    def test_every_field_type_offers_omit(self):
        for value in (5, "x", True, {"nested": 1}, [1, 2]):
            labels = {m[0] for m in _mutations_for(value)}
            assert "omit" in labels, f"omit missing for {value!r}"

    def test_all_mutations_marked_expect_reject(self):
        # Every generated mutation is an invalid value a validating server should
        # refuse, so all drive findings when accepted.
        for value in (5, "x", True):
            assert all(expect for _, _, expect in _mutations_for(value))


# ---------------------------------------------------------------------------
# Scanner wiring — auth token routing and graceful degradation
# ---------------------------------------------------------------------------

def _make_scanner(work_items, auth_headers=None, user_token=""):
    http = SimpleNamespace(
        _auth_headers=auth_headers or {},
        enforcer=MagicMock(),
    )
    scanner = InputValidationScanner(http, ai_agent=None)
    state = MagicMock()
    state.claim_work.return_value = work_items
    state.get_auth.return_value = {"user_token": user_token}
    scanner.scan_state = state
    scanner.scan_id = "scan-1"
    return scanner, state


@pytest.mark.asyncio
async def test_no_work_items_returns_empty():
    scanner, _ = _make_scanner(work_items=[])
    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))
    assert findings == []


def test_token_for_resolves_by_auth_context():
    scanner, _ = _make_scanner(work_items=[], auth_headers={"Authorization": "Bearer ADMIN"},
                               user_token="USERTOK")
    scanner._admin_token = "ADMIN"
    scanner._user_token = "USERTOK"
    assert scanner._token_for("admin") == "ADMIN"
    assert scanner._token_for("user") == "USERTOK"
    assert scanner._token_for("none") == ""


# ---------------------------------------------------------------------------
# Anomaly detection — server accepting invalid input is a finding
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_accepted_invalid_body_value_is_a_finding():
    """A 2xx response to a mutated (invalid) body field is reported."""
    route = respx.post("http://app/api/Feedbacks").mock(
        return_value=httpx.Response(201, json={"status": "created"})
    )
    work = [{
        "queue_id": 1,
        "url": "http://app/api/Feedbacks",
        "method": "POST",
        "auth_context": "none",
        "payload": {"request_body": {"rating": 5, "comment": "nice"}},
    }]
    scanner, state = _make_scanner(work_items=work)

    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))

    assert route.called
    assert findings, "expected findings when server accepts invalid input"
    assert all(f.vuln_type == VulnType.IMPROPER_INPUT_VALIDATION for f in findings)
    # The malicious mutations were actually sent (this is what trips a scoreboard).
    sent_bodies = [c.request.content for c in route.calls]
    assert any(b'"rating": 0' in body or b'"rating":0' in body for body in sent_bodies)
    state.complete_work.assert_called_once_with(1)


@pytest.mark.asyncio
@respx.mock
async def test_rejected_invalid_value_is_not_a_finding():
    """A 4xx response (server correctly rejects) yields no finding."""
    respx.post("http://app/api/Feedbacks").mock(
        return_value=httpx.Response(400, json={"error": "invalid"})
    )
    work = [{
        "queue_id": 1,
        "url": "http://app/api/Feedbacks",
        "method": "POST",
        "auth_context": "none",
        "payload": {"request_body": {"rating": 5}},
    }]
    scanner, _ = _make_scanner(work_items=work)
    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_findings_deduped_per_field_mutation():
    """The same (url, method, field, mutation) is reported once even though the
    field appears across many endpoints."""
    respx.post("http://app/api/Feedbacks").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    body = {"rating": 5}
    work = [
        {"queue_id": i, "url": "http://app/api/Feedbacks", "method": "POST",
         "auth_context": "none", "payload": {"request_body": body}}
        for i in range(3)
    ]
    scanner, _ = _make_scanner(work_items=work)
    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))
    keys = {(f.endpoint.url, f.endpoint.method, f.title) for f in findings}
    assert len(keys) == len(findings), "duplicate findings were not collapsed"


@pytest.mark.asyncio
@respx.mock
async def test_request_budget_is_capped():
    """The scanner must not exceed MAX_REQUESTS probes regardless of queue size."""
    route = respx.route(method="POST").mock(return_value=httpx.Response(200))
    # Many distinct endpoints, each with several fields.
    body = {"a": 1, "b": "s", "c": 2}
    work = [
        {"queue_id": i, "url": f"http://app/api/x/{i}", "method": "POST",
         "auth_context": "none", "payload": {"request_body": body}}
        for i in range(500)
    ]
    scanner, _ = _make_scanner(work_items=work)
    await scanner.scan(config=SimpleNamespace(no_ai=True))
    assert scanner._requests_sent <= MAX_REQUESTS
    assert route.call_count <= MAX_REQUESTS


# ---------------------------------------------------------------------------
# Archetype synthesis probes — active construct-and-submit (profiler-driven)
# ---------------------------------------------------------------------------

def _synth_work(spec, queue_id=1):
    return [{
        "queue_id": queue_id,
        "url": spec["url"],
        "method": spec["method"],
        "auth_context": spec.get("auth_context", "none"),
        "payload": {"synthesize": spec},
    }]


@pytest.mark.asyncio
@respx.mock
async def test_synthesis_out_of_range_accepted_is_finding():
    """A rating write that accepts an out-of-range value (0) is reported."""
    route = respx.post("http://app/shop/reviews").mock(
        return_value=httpx.Response(201, json={"id": 1})
    )
    spec = {
        "archetype": "rating", "url": "http://app/shop/reviews",
        "method": "POST", "auth_context": "admin",
        "base_body": {"rating": 3, "comment": "diana feedback"},
        "probe_kind": "out_of_range", "target_fields": ["rating"],
        "values": [0, -1, 6],
    }
    scanner, _ = _make_scanner(work_items=_synth_work(spec),
                               auth_headers={"Authorization": "Bearer ADMIN"})
    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))

    assert route.called
    assert findings and all(f.cwe_id == "CWE-20" for f in findings)
    # The out-of-range value 0 was actually submitted with the rest of the body intact.
    sent = [c.request.content for c in route.calls]
    assert any(b'"rating": 0' in b or b'"rating":0' in b for b in sent)
    assert any(b'comment' in b for b in sent)


@pytest.mark.asyncio
@respx.mock
async def test_synthesis_out_of_range_rejected_is_not_finding():
    respx.post("http://app/shop/reviews").mock(
        return_value=httpx.Response(400, json={"error": "bad rating"})
    )
    spec = {
        "archetype": "rating", "url": "http://app/shop/reviews",
        "method": "POST", "auth_context": "admin",
        "base_body": {"rating": 3}, "probe_kind": "out_of_range",
        "target_fields": ["rating"], "values": [0, 6],
    }
    scanner, _ = _make_scanner(work_items=_synth_work(spec),
                               auth_headers={"Authorization": "Bearer ADMIN"})
    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_synthesis_empty_required_accepted_is_finding():
    """A registration accepting an empty required field is reported, and the
    empty value is actually sent."""
    route = respx.post("http://app/accounts").mock(
        return_value=httpx.Response(201, json={"id": 9})
    )
    spec = {
        "archetype": "account_registration", "url": "http://app/accounts",
        "method": "POST", "auth_context": "none",
        "base_body": {"email": "diana-probe@example.com", "password": "Diana!Probe1"},
        "probe_kind": "empty_required", "target_fields": ["email", "password"],
        "values": [],
    }
    scanner, _ = _make_scanner(work_items=_synth_work(spec))
    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))

    assert route.called
    assert findings
    sent = [c.request.content for c in route.calls]
    assert any(b'"email": ""' in b or b'"email":""' in b for b in sent)


@pytest.mark.asyncio
@respx.mock
async def test_synthesis_duplicate_second_success_is_finding():
    """Duplicate registration: two identical POSTs; the second succeeding means
    uniqueness isn't enforced."""
    route = respx.post("http://app/accounts").mock(
        return_value=httpx.Response(201, json={"id": 1})
    )
    spec = {
        "archetype": "account_registration", "url": "http://app/accounts",
        "method": "POST", "auth_context": "none",
        "base_body": {"email": "dup@example.com", "password": "x"},
        "probe_kind": "duplicate", "target_fields": ["email"], "values": [],
    }
    scanner, _ = _make_scanner(work_items=_synth_work(spec))
    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))

    assert route.call_count == 2  # setup + duplicate
    assert findings and "duplicate" in findings[0].evidence


@pytest.mark.asyncio
@respx.mock
async def test_synthesis_duplicate_second_rejected_is_not_finding():
    # First create succeeds, second is rejected (uniqueness enforced).
    responses = [httpx.Response(201, json={"id": 1}), httpx.Response(409, json={"error": "exists"})]
    respx.post("http://app/accounts").mock(side_effect=responses)
    spec = {
        "archetype": "account_registration", "url": "http://app/accounts",
        "method": "POST", "auth_context": "none",
        "base_body": {"email": "dup@example.com", "password": "x"},
        "probe_kind": "duplicate", "target_fields": ["email"], "values": [],
    }
    scanner, _ = _make_scanner(work_items=_synth_work(spec))
    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))
    assert findings == []
