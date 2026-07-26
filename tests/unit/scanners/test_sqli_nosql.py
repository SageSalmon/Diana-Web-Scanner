"""Tests for the sqli scanner's NoSQL (document-DB) operator injection.

Covers the two generic classes the module exercises against JSON request
bodies: selector *manipulation* (differential match-nothing vs match-all) and
time-based *denial of service* ($where server-side-JS sleep). All inputs are
synthetic — no live target, no Juice Shop fixtures. HTTP is a scripted fake so
no real network calls are made.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from diana.core.models import Endpoint, Severity, VulnType
from diana.scanners import sqli as sqli_mod
from diana.scanners.sqli import (
    NOSQL_MANIPULATION_OPERATORS,
    SQLiScanner,
    _nosql_sleep_operators,
)


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class FakeHTTP:
    """Records every request and dispatches to a scripted handler.

    handler(method, url, body) -> (FakeResponse, sleep_seconds)
    """

    def __init__(self, handler):
        self._handler = handler
        self.enforcer = MagicMock()
        self._auth_headers = {}
        self.sent: list[tuple[str, str, object]] = []

    async def request(self, method, url, *, json=None, **kwargs):
        self.sent.append((method, url, json))
        resp, sleep_s = self._handler(method, url, json)
        if sleep_s:
            await asyncio.sleep(sleep_s)
        return resp


def _scanner(handler):
    scanner = SQLiScanner(FakeHTTP(handler), ai_agent=None)
    return scanner


# ---------------------------------------------------------------------------
# Payload construction — operators must be structured JSON, not strings
# ---------------------------------------------------------------------------

class TestOperatorShape:
    def test_manipulation_operators_are_objects_not_strings(self):
        # The whole point: an operator only bites when it reaches the DB as an
        # object. A string that merely looks like one is inert.
        assert NOSQL_MANIPULATION_OPERATORS, "expected manipulation operators"
        for op in NOSQL_MANIPULATION_OPERATORS:
            assert isinstance(op, dict)
            assert all(k.startswith("$") for k in op)

    def test_sleep_operators_encode_requested_duration(self):
        ops = _nosql_sleep_operators(1234)
        assert ops and all(isinstance(o, dict) and "$where" in o for o in ops)
        assert any("1234" in o["$where"] for o in ops)


# ---------------------------------------------------------------------------
# Manipulation — differential detection
# ---------------------------------------------------------------------------

class TestManipulation:
    @pytest.mark.asyncio
    async def test_match_all_operator_flips_failure_to_success(self):
        """A non-matching scalar 404s; the $ne operator matches all -> 200."""

        def handler(method, url, body):
            val = body.get("id")
            # Only an operator object broadens the query; a scalar marker misses.
            if isinstance(val, dict):
                return FakeResponse(200, '{"updated": 42}'), 0
            return FakeResponse(404, "not found"), 0

        scanner = _scanner(handler)
        ep = Endpoint(url="http://app/rest/records", method="PATCH")
        findings = await scanner._test_nosql_body(ep, {"id": 7, "message": "x"})

        manip = [f for f in findings if f.severity == Severity.CRITICAL]
        assert manip, "expected a manipulation finding"
        f = manip[0]
        assert f.vuln_type == VulnType.SQLI
        assert f.cwe_id == "CWE-943"
        assert "id" in f.title

    @pytest.mark.asyncio
    async def test_operator_payload_actually_transmitted_as_object(self):
        """The exploit request is sent with a real operator object (scoreboard)."""

        def handler(method, url, body):
            if isinstance(body.get("id"), dict):
                return FakeResponse(200, "ok"), 0
            return FakeResponse(404, ""), 0

        scanner = _scanner(handler)
        ep = Endpoint(url="http://app/rest/records", method="PATCH")
        await scanner._test_nosql_body(ep, {"id": 7})

        object_ids = [b["id"] for (_, _, b) in scanner.http.sent
                      if isinstance(b.get("id"), dict)]
        assert object_ids, "no operator object was ever transmitted"
        # At least one recognised selector operator was sent.
        assert any(any(k.startswith("$") for k in oid) for oid in object_ids)

    @pytest.mark.asyncio
    async def test_endpoint_that_accepts_anything_is_not_flagged(self):
        """If the control scalar also succeeds and size is stable, no finding."""

        def handler(method, url, body):
            return FakeResponse(200, "same-body-every-time"), 0

        scanner = _scanner(handler)
        ep = Endpoint(url="http://app/rest/records", method="PATCH")
        findings = await scanner._test_nosql_body(ep, {"id": 7})

        assert not [f for f in findings if f.vuln_type == VulnType.SQLI], (
            "must not flag an endpoint whose behaviour never changes"
        )


# ---------------------------------------------------------------------------
# Denial of service — time-based detection
# ---------------------------------------------------------------------------

class TestDoS:
    @pytest.mark.asyncio
    async def test_where_sleep_delay_is_flagged(self, monkeypatch):
        # Keep the test fast: shrink the delay thresholds and simulate a short
        # server sleep only for the $where payload.
        monkeypatch.setattr(sqli_mod, "NOSQL_DELAY_MARGIN_S", 0.05)
        monkeypatch.setattr(sqli_mod, "NOSQL_DELAY_FLOOR_S", 0.05)

        def handler(method, url, body):
            val = body.get("id")
            if isinstance(val, dict) and "$where" in val:
                return FakeResponse(200, "ok"), 0.12
            return FakeResponse(200, "ok"), 0

        scanner = _scanner(handler)
        ep = Endpoint(url="http://app/rest/records", method="PATCH")
        findings = await scanner._test_nosql_body(ep, {"id": 7})

        dos = [f for f in findings if f.vuln_type == VulnType.SQLI_BLIND]
        assert dos, "expected a time-based DoS finding"
        assert dos[0].severity == Severity.HIGH
        assert dos[0].cwe_id == "CWE-943"

    @pytest.mark.asyncio
    async def test_no_delay_means_no_dos_finding(self, monkeypatch):
        monkeypatch.setattr(sqli_mod, "NOSQL_DELAY_MARGIN_S", 0.05)
        monkeypatch.setattr(sqli_mod, "NOSQL_DELAY_FLOOR_S", 0.05)

        def handler(method, url, body):
            return FakeResponse(200, "ok"), 0  # never slow

        scanner = _scanner(handler)
        ep = Endpoint(url="http://app/rest/records", method="PATCH")
        findings = await scanner._test_nosql_body(ep, {"id": 7})

        assert not [f for f in findings if f.vuln_type == VulnType.SQLI_BLIND]


# ---------------------------------------------------------------------------
# scan() wiring — request_body work items route to the NoSQL probe
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_routes_request_body_to_nosql_probe():
    def handler(method, url, body):
        if isinstance(body.get("id"), dict):
            return FakeResponse(200, "matched-all-records-here"), 0
        return FakeResponse(404, ""), 0

    scanner = _scanner(handler)
    state = MagicMock()
    state.claim_work.return_value = [{
        "queue_id": 1,
        "url": "http://app/rest/records",
        "method": "PATCH",
        "auth_context": "admin",
        "payload": {"request_body": {"id": 7, "message": "x"}},
    }]
    scanner.scan_state = state
    scanner.scan_id = "scan-1"

    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))

    assert any(f.vuln_type == VulnType.SQLI for f in findings)
    state.complete_work.assert_called_once_with(1)
    # The PATCH method (not a hardcoded POST) was used for the injection.
    assert all(m == "PATCH" for (m, _, _) in scanner.http.sent)
