"""Tests for the SQLi scanner — error/UNION detection, login auth-bypass, and
the targeted-account harvesting added on top of the generic login bypass.

All HTTP interaction is synthetic (in-memory fakes); no real network calls and
no target-specific fixtures. URLs are neutral (http://app/...).
"""

from __future__ import annotations

import pytest

from diana.core.models import Endpoint, Payload, VulnType
from diana.scanners.sqli import MAX_TARGETED_ACCOUNTS, SQLiScanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scanner(mock_http_client, response_map=None, default_response=None):
    """Create an SQLiScanner with mocked HTTP and no AI."""
    client = mock_http_client(response_map, default_response)
    scanner = SQLiScanner(http=client, ai_agent=None)
    return scanner


class FakeState:
    """Minimal scan_state stand-in for scan()-level integration tests."""

    def __init__(self, items: list[dict]):
        self._items = items
        self.completed: list[int] = []

    def claim_work(self, scan_id, name, limit):
        return self._items[:limit]

    def complete_work(self, queue_id):
        self.completed.append(queue_id)


# ---------------------------------------------------------------------------
# _harvest_emails — collecting account names leaked in responses
# ---------------------------------------------------------------------------

class TestHarvestEmails:
    def test_collects_email_address_from_response_text(self):
        scanner = SQLiScanner(http=None, ai_agent=None)
        scanner._discovered_emails = set()

        scanner._harvest_emails("<tr><td>alice@example.com</td><td>hash</td></tr>")

        assert "alice@example.com" in scanner._discovered_emails

    def test_dedupes_same_email_across_multiple_calls(self):
        scanner = SQLiScanner(http=None, ai_agent=None)
        scanner._discovered_emails = set()

        scanner._harvest_emails("user: bob@example.com")
        scanner._harvest_emails("again: bob@example.com")

        assert scanner._discovered_emails == {"bob@example.com"}

    def test_normalizes_case(self):
        scanner = SQLiScanner(http=None, ai_agent=None)
        scanner._discovered_emails = set()

        scanner._harvest_emails("Carol@Example.COM")

        assert scanner._discovered_emails == {"carol@example.com"}

    def test_skips_diana_test_probe_addresses(self):
        scanner = SQLiScanner(http=None, ai_agent=None)
        scanner._discovered_emails = set()

        scanner._harvest_emails("probe account: diana-test-abc123@example.com")

        assert scanner._discovered_emails == set()

    def test_skips_diana_role_probe_addresses(self):
        scanner = SQLiScanner(http=None, ai_agent=None)
        scanner._discovered_emails = set()

        scanner._harvest_emails("role account: diana-role-admin@example.com")

        assert scanner._discovered_emails == set()

    def test_skips_test_local_domain_addresses(self):
        scanner = SQLiScanner(http=None, ai_agent=None)
        scanner._discovered_emails = set()

        scanner._harvest_emails("synthetic canary: whatever@test.local")

        assert scanner._discovered_emails == set()

    def test_noop_on_empty_text(self):
        scanner = SQLiScanner(http=None, ai_agent=None)
        scanner._discovered_emails = set()

        scanner._harvest_emails("")

        assert scanner._discovered_emails == set()

    def test_lazily_initializes_state_when_attribute_missing(self):
        """A scanner that never touched _discovered_emails (e.g. called
        directly in a test) should still work rather than raising."""
        scanner = SQLiScanner(http=None, ai_agent=None)
        assert not hasattr(scanner, "_discovered_emails")

        scanner._harvest_emails("dave@example.com")

        assert scanner._discovered_emails == {"dave@example.com"}

    def test_caps_collection_at_max_targeted_accounts(self):
        scanner = SQLiScanner(http=None, ai_agent=None)
        scanner._discovered_emails = set()

        many = " ".join(f"user{i}@example.com" for i in range(MAX_TARGETED_ACCOUNTS + 10))
        scanner._harvest_emails(many)

        assert len(scanner._discovered_emails) <= MAX_TARGETED_ACCOUNTS

    def test_further_calls_are_noop_once_cap_reached(self):
        scanner = SQLiScanner(http=None, ai_agent=None)
        scanner._discovered_emails = {
            f"user{i}@example.com" for i in range(MAX_TARGETED_ACCOUNTS)
        }

        scanner._harvest_emails("brandnew@example.com")

        assert "brandnew@example.com" not in scanner._discovered_emails
        assert len(scanner._discovered_emails) == MAX_TARGETED_ACCOUNTS


# ---------------------------------------------------------------------------
# _test_payload — regression: harvesting must not change existing detections
# ---------------------------------------------------------------------------

class TestPayloadDetectionRegression:
    @pytest.mark.asyncio
    async def test_error_based_sqli_still_detected(self, mock_http_client, sample_endpoint):
        endpoint = sample_endpoint(url="http://app/items", parameters={"id": "1"})
        scanner = _make_scanner(mock_http_client, default_response=None)
        scanner.http = mock_http_client({}, default_response=None)

        async def erroring_get(url, **kwargs):
            from tests.conftest import MockResponse
            return MockResponse(text="You have an error in your SQL syntax near '1'")

        scanner.http.get = erroring_get

        payload = Payload(value="'", vuln_type=VulnType.SQLI)
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is not None
        assert finding.vuln_type == VulnType.SQLI

    @pytest.mark.asyncio
    async def test_no_finding_on_clean_response(self, mock_http_client, sample_endpoint):
        from tests.conftest import MockResponse

        endpoint = sample_endpoint(url="http://app/items", parameters={"id": "1"})
        scanner = _make_scanner(
            mock_http_client, default_response=MockResponse(text="<html>no results</html>"),
        )

        payload = Payload(value="'", vuln_type=VulnType.SQLI)
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is None

    @pytest.mark.asyncio
    async def test_harvests_emails_that_leak_via_union_extraction(self, mock_http_client, sample_endpoint):
        """A UNION payload that dumps user rows should populate discovered
        accounts even though it doesn't itself raise a distinctive finding
        this call (no union_indicators present)."""
        from tests.conftest import MockResponse

        endpoint = sample_endpoint(url="http://app/items", parameters={"id": "1"})
        scanner = _make_scanner(
            mock_http_client,
            default_response=MockResponse(
                text="1,eve@example.com,somehash\n2,frank@example.com,otherhash",
            ),
        )
        scanner._discovered_emails = set()

        payload = Payload(
            value="' UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
            vuln_type=VulnType.SQLI,
        )
        await scanner._test_payload(endpoint, payload)

        assert "eve@example.com" in scanner._discovered_emails
        assert "frank@example.com" in scanner._discovered_emails


# ---------------------------------------------------------------------------
# _test_payload — UNION-based detection branch
# ---------------------------------------------------------------------------

class TestUnionBasedDetection:
    """The UNION-indicator branch of _test_payload: a UNION payload whose
    response both grows substantially relative to baseline AND contains a
    schema/data artifact (e.g. 'password', 'sqlite_master') should be flagged
    as a UNION-based SQLi finding, distinct from error-based detection."""

    @pytest.mark.asyncio
    async def test_union_payload_flagged_when_indicator_present_and_response_grows(
        self, mock_http_client, sample_endpoint,
    ):
        from tests.conftest import MockResponse

        endpoint = sample_endpoint(url="http://app/items", parameters={"id": "1"})
        scanner = _make_scanner(mock_http_client)

        baseline_text = "<html><body>no results</body></html>"
        # Substantially longer than baseline and contains a union_indicator.
        leaked_text = "<html><body>" + ("id,email,password,hash;" * 10) + "</body></html>"

        calls = {"n": 0}

        async def get(url, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return MockResponse(status_code=200, text=baseline_text)
            return MockResponse(status_code=200, text=leaked_text)

        scanner.http.get = get

        payload = Payload(
            value="' UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
            vuln_type=VulnType.SQLI,
        )
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is not None
        assert finding.vuln_type == VulnType.SQLI
        assert "UNION" in finding.title
        assert finding.cwe_id == "CWE-89"
        assert finding.payload_used == payload.value

    @pytest.mark.asyncio
    async def test_union_payload_not_flagged_when_no_indicator_present(
        self, mock_http_client, sample_endpoint,
    ):
        """A UNION payload whose response grows but leaks nothing recognizable
        (no schema/data artifact) must not be reported as a finding."""
        from tests.conftest import MockResponse

        endpoint = sample_endpoint(url="http://app/items", parameters={"id": "1"})
        scanner = _make_scanner(mock_http_client)

        baseline_text = "<html><body>no results</body></html>"
        grown_but_clean_text = "<html><body>" + ("just more ordinary content " * 10) + "</body></html>"

        calls = {"n": 0}

        async def get(url, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return MockResponse(status_code=200, text=baseline_text)
            return MockResponse(status_code=200, text=grown_but_clean_text)

        scanner.http.get = get

        payload = Payload(
            value="' UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
            vuln_type=VulnType.SQLI,
        )
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is None

    @pytest.mark.asyncio
    async def test_union_payload_not_flagged_when_response_not_significantly_larger(
        self, mock_http_client, sample_endpoint,
    ):
        """An indicator word alone isn't enough — the response must also grow
        meaningfully relative to baseline (guards against false positives on
        pages that merely mention 'password' in a static footer/label)."""
        from tests.conftest import MockResponse

        endpoint = sample_endpoint(url="http://app/items", parameters={"id": "1"})
        scanner = _make_scanner(mock_http_client)

        baseline_text = "<html><body>Please enter your password to continue</body></html>"
        similar_size_text = "<html><body>Invalid password, try again</body></html>"

        calls = {"n": 0}

        async def get(url, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return MockResponse(status_code=200, text=baseline_text)
            return MockResponse(status_code=200, text=similar_size_text)

        scanner.http.get = get

        payload = Payload(
            value="' UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
            vuln_type=VulnType.SQLI,
        )
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is None


# ---------------------------------------------------------------------------
# _test_login_injection — generic bypass (regression) + targeted bypass (new)
# ---------------------------------------------------------------------------

class TestLoginInjectionGenericRegression:
    """Baseline behavior that must survive the targeted-account addition."""

    @pytest.mark.asyncio
    async def test_generic_auth_bypass_reported_when_no_accounts_discovered(self, mock_http_client):
        from tests.conftest import MockResponse

        endpoint = Endpoint(url="http://app/login", method="POST", parameters={})

        async def auth_bypass_post(url, **kwargs):
            data = kwargs.get("json", {})
            if data.get("email") == "' OR 1=1--":
                return MockResponse(status_code=200, text='{"token": "abc123"}')
            return MockResponse(status_code=401, text='{"error": "invalid"}')

        scanner = SQLiScanner(http=mock_http_client({}), ai_agent=None)
        scanner.http.post = auth_bypass_post
        scanner._discovered_emails = set()

        findings = await scanner._test_login_injection([endpoint])

        assert len(findings) == 1
        assert findings[0].vuln_type == VulnType.SQLI
        assert "Auth Bypass" in findings[0].title
        assert findings[0].payload_used == "' OR 1=1--"

    @pytest.mark.asyncio
    async def test_error_based_login_sqli_reported(self, mock_http_client):
        from tests.conftest import MockResponse

        endpoint = Endpoint(url="http://app/login", method="POST", parameters={})

        async def erroring_post(url, **kwargs):
            return MockResponse(
                status_code=500, text="You have an error in your SQL syntax",
            )

        scanner = SQLiScanner(http=mock_http_client({}), ai_agent=None)
        scanner.http.post = erroring_post
        scanner._discovered_emails = set()

        findings = await scanner._test_login_injection([endpoint])

        assert len(findings) == 1
        assert "SQL Injection in login" in findings[0].title

    @pytest.mark.asyncio
    async def test_no_findings_when_login_endpoint_not_vulnerable(self, mock_http_client):
        from tests.conftest import MockResponse

        endpoint = Endpoint(url="http://app/login", method="POST", parameters={})
        scanner = SQLiScanner(
            http=mock_http_client({}, default_response=MockResponse(
                status_code=401, text='{"error": "invalid credentials"}',
            )),
            ai_agent=None,
        )
        scanner._discovered_emails = set()

        findings = await scanner._test_login_injection([endpoint])

        assert findings == []

    @pytest.mark.asyncio
    async def test_empty_login_endpoints_returns_no_findings(self):
        scanner = SQLiScanner(http=None, ai_agent=None)
        findings = await scanner._test_login_injection([])
        assert findings == []


class TestLoginInjectionTargetedAccounts:
    """New behavior: accounts discovered elsewhere become precise bypass
    targets (`{email}'--`) once the injection point is confirmed."""

    @pytest.mark.asyncio
    async def test_targeted_payload_used_for_discovered_account(self, mock_http_client):
        from tests.conftest import MockResponse

        endpoint = Endpoint(url="http://app/login", method="POST", parameters={})
        seen_payloads = []

        async def targeted_post(url, **kwargs):
            data = kwargs.get("json", {})
            value = data.get("email", "")
            seen_payloads.append(value)
            if value in ("' OR 1=1--", "alice@example.com'--"):
                return MockResponse(status_code=200, text='{"token": "abc123"}')
            return MockResponse(status_code=401, text='{"error": "invalid"}')

        scanner = SQLiScanner(http=mock_http_client({}), ai_agent=None)
        scanner.http.post = targeted_post
        scanner._discovered_emails = {"alice@example.com"}

        findings = await scanner._test_login_injection([endpoint])

        # Generic bypass finding + one targeted finding for the discovered account.
        titles = [f.title for f in findings]
        assert any("Auth Bypass" in t and "alice@example.com" not in t for t in titles)
        assert any("alice@example.com" in t for t in titles)
        assert "alice@example.com'--" in seen_payloads

    @pytest.mark.asyncio
    async def test_targeted_finding_records_account_and_payload(self, mock_http_client):
        from tests.conftest import MockResponse

        endpoint = Endpoint(url="http://app/login", method="POST", parameters={})

        async def targeted_post(url, **kwargs):
            data = kwargs.get("json", {})
            value = data.get("email", "")
            if value in ("' OR 1=1--", "bob@example.com'--"):
                return MockResponse(status_code=200, text='{"token": "abc123"}')
            return MockResponse(status_code=401, text='{"error": "invalid"}')

        scanner = SQLiScanner(http=mock_http_client({}), ai_agent=None)
        scanner.http.post = targeted_post
        scanner._discovered_emails = {"bob@example.com"}

        findings = await scanner._test_login_injection([endpoint])
        targeted = [f for f in findings if "bob@example.com" in f.title]

        assert len(targeted) == 1
        assert targeted[0].payload_used == "bob@example.com'--"
        assert "bob@example.com" in targeted[0].description
        assert targeted[0].severity.name == "CRITICAL"
        assert targeted[0].cwe_id == "CWE-89"

    @pytest.mark.asyncio
    async def test_no_targeted_attempts_when_injection_point_not_confirmed(self, mock_http_client):
        """If the generic primitives don't confirm injectability, the scanner
        must not go on to try per-account payloads (would be pointless load)."""
        from tests.conftest import MockResponse

        endpoint = Endpoint(url="http://app/login", method="POST", parameters={})
        seen_payloads = []

        async def never_vulnerable_post(url, **kwargs):
            data = kwargs.get("json", {})
            seen_payloads.append(data.get("email", ""))
            return MockResponse(status_code=401, text='{"error": "invalid"}')

        scanner = SQLiScanner(http=mock_http_client({}), ai_agent=None)
        scanner.http.post = never_vulnerable_post
        scanner._discovered_emails = {"alice@example.com"}

        findings = await scanner._test_login_injection([endpoint])

        assert findings == []
        assert not any(p.endswith("'--") and "@" in p for p in seen_payloads)

    @pytest.mark.asyncio
    async def test_targeted_findings_capped(self, mock_http_client):
        """MAX_TARGETED_FINDINGS (10) bounds how many per-account findings are
        reported even if more accounts were discovered / all are injectable."""
        from tests.conftest import MockResponse

        endpoint = Endpoint(url="http://app/login", method="POST", parameters={})
        emails = {f"user{i}@example.com" for i in range(15)}

        async def all_vulnerable_post(url, **kwargs):
            data = kwargs.get("json", {})
            value = data.get("email", "")
            if value == "' OR 1=1--" or value.endswith("'--"):
                return MockResponse(status_code=200, text='{"token": "abc123"}')
            return MockResponse(status_code=401, text='{"error": "invalid"}')

        scanner = SQLiScanner(http=mock_http_client({}), ai_agent=None)
        scanner.http.post = all_vulnerable_post
        scanner._discovered_emails = emails

        findings = await scanner._test_login_injection([endpoint])
        targeted = [f for f in findings if f.title != findings[0].title]

        # 1 generic finding + at most 10 targeted findings.
        assert len(findings) <= 11

    @pytest.mark.asyncio
    async def test_no_targeted_findings_when_no_accounts_discovered(self, mock_http_client):
        """Baseline: with an empty discovery set, only the generic finding is
        produced — the targeted phase contributes nothing."""
        from tests.conftest import MockResponse

        endpoint = Endpoint(url="http://app/login", method="POST", parameters={})

        async def auth_bypass_post(url, **kwargs):
            data = kwargs.get("json", {})
            if data.get("email") == "' OR 1=1--":
                return MockResponse(status_code=200, text='{"token": "abc123"}')
            return MockResponse(status_code=401, text='{"error": "invalid"}')

        scanner = SQLiScanner(http=mock_http_client({}), ai_agent=None)
        scanner.http.post = auth_bypass_post
        scanner._discovered_emails = set()

        findings = await scanner._test_login_injection([endpoint])

        assert len(findings) == 1


# ---------------------------------------------------------------------------
# scan() — login endpoints processed last so earlier-harvested accounts are
# available as targets.
# ---------------------------------------------------------------------------

class TestScanOrdersLoginEndpointLast:
    @pytest.mark.asyncio
    async def test_emails_harvested_from_earlier_endpoint_are_available_at_login(
        self, mock_http_client,
    ):
        from tests.conftest import MockResponse

        # A search endpoint whose response leaks an account, queued BEFORE the
        # login endpoint (the scanner must still process it first).
        search_item = {
            "queue_id": 1,
            "url": "http://app/search",
            "method": "GET",
            "payload": {"params": {"q": "test"}},
        }
        login_item = {
            "queue_id": 2,
            "url": "http://app/login",
            "method": "POST",
            "payload": {"type": "login_endpoint", "params": {}},
        }

        async def get(url, **kwargs):
            return MockResponse(text="1,gina@example.com,hash")

        async def post(url, **kwargs):
            data = kwargs.get("json", {})
            value = data.get("email", "")
            if value in ("' OR 1=1--", "gina@example.com'--"):
                return MockResponse(status_code=200, text='{"token": "abc123"}')
            return MockResponse(status_code=401, text='{"error": "invalid"}')

        scanner = SQLiScanner(http=mock_http_client({}), ai_agent=None)
        scanner.http.get = get
        scanner.http.post = post
        scanner.scan_state = FakeState([login_item, search_item])
        scanner.scan_id = "test"

        from diana.config import ScanConfig
        config = ScanConfig(target="http://app")

        findings = await scanner.scan(config)

        assert any("gina@example.com" in f.title for f in findings)
