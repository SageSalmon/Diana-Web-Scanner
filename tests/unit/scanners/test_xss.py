"""Tests for XSS scanner — reflection detection, param injection, DOM XSS sinks."""

from __future__ import annotations

import pytest

from diana.core.models import Endpoint, Payload, VulnType
from diana.scanners.xss import XSSScanner

from tests.conftest import MockResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scanner(mock_http_client, response_map=None, default_response=None):
    """Create an XSSScanner with mocked HTTP and no AI."""
    client = mock_http_client(response_map, default_response)
    scanner = XSSScanner(http=client, ai_agent=None)
    return scanner


# ---------------------------------------------------------------------------
# _test_payload — parameter injection and reflection detection
# ---------------------------------------------------------------------------

class TestPayloadReflectionDetection:
    """Tests for _test_payload — the core reflected XSS detection method."""

    @pytest.mark.asyncio
    async def test_detects_full_payload_reflected_unencoded(self, mock_http_client, sample_endpoint):
        """When the exact payload appears in the response body, report XSS."""
        payload_str = '<script>alert("diana")</script>'
        endpoint = sample_endpoint(url="http://app/search", parameters={"q": "test"})

        scanner = _make_scanner(mock_http_client, default_response=MockResponse(
            text=f'<html><body>Results for: {payload_str}</body></html>',
        ))

        payload = Payload(value=payload_str, vuln_type=VulnType.XSS_REFLECTED)
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is not None
        assert finding.vuln_type == VulnType.XSS_REFLECTED
        assert "q" in finding.title

    @pytest.mark.asyncio
    async def test_detects_canary_in_dangerous_html_context(self, mock_http_client, sample_endpoint):
        """When canary is reflected inside a script tag context, report XSS."""
        endpoint = sample_endpoint(url="http://app/search", parameters={"q": "test"})

        # Response has canary reflected inside a script block
        # The canary will be generated dynamically, so we match any diana* prefix
        scanner = _make_scanner(mock_http_client, default_response=MockResponse(
            text='<html><script>var x = "diana00000000";</script></html>',
        ))

        payload = Payload(value='<script>alert("diana")</script>', vuln_type=VulnType.XSS_REFLECTED)
        finding = await scanner._test_payload(endpoint, payload)

        # The canary replaces "diana" in the payload, so the response needs to contain
        # the exact canary. Since we can't predict the canary, test with a response that
        # will match any canary by using a mock that echoes the query param.
        # Instead, test the actual flow with a response builder:
        async def reflecting_get(url, **kwargs):
            # Extract the q param value and reflect it in a script context
            if "q=" in url:
                from urllib.parse import parse_qs, urlparse
                q_val = parse_qs(urlparse(url).query).get("q", [""])[0]
                return MockResponse(text=f'<html><script>var x = "{q_val}";</script></html>')
            return MockResponse(text="<html></html>")

        scanner.http.get = reflecting_get

        finding = await scanner._test_payload(endpoint, payload)
        assert finding is not None
        assert "dangerous context" in finding.description.lower() or "reflected" in finding.description.lower()

    @pytest.mark.asyncio
    async def test_detects_unencoded_html_chars_near_canary(self, mock_http_client, sample_endpoint):
        """When canary is reflected and HTML special chars survive, report XSS."""
        endpoint = sample_endpoint(url="http://app/page", parameters={"name": "test"})

        async def reflecting_get(url, **kwargs):
            if "name=" in url:
                from urllib.parse import parse_qs, urlparse
                val = parse_qs(urlparse(url).query).get("name", [""])[0]
                # Reflect with some chars intact — simulate partial encoding
                return MockResponse(text=f'<html><body><p class="{val}">hello</p></body></html>')
            return MockResponse(text="<html></html>")

        scanner = _make_scanner(mock_http_client)
        scanner.http.get = reflecting_get

        # Payload with quotes that should be caught as unencoded HTML chars
        payload = Payload(value='" onfocus=alert("diana") autofocus="', vuln_type=VulnType.XSS_REFLECTED)
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is not None

    @pytest.mark.asyncio
    async def test_no_finding_when_payload_is_fully_encoded(self, mock_http_client, sample_endpoint):
        """When the response properly encodes the payload, no finding should be reported."""
        endpoint = sample_endpoint(url="http://app/search", parameters={"q": "test"})

        async def encoding_get(url, **kwargs):
            if "q=" in url:
                from urllib.parse import parse_qs, urlparse
                val = parse_qs(urlparse(url).query).get("q", [""])[0]
                # Properly HTML-encode everything
                encoded = val.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
                return MockResponse(text=f'<html><body>Results for: {encoded}</body></html>')
            return MockResponse(text="<html></html>")

        scanner = _make_scanner(mock_http_client)
        scanner.http.get = encoding_get

        payload = Payload(value='<script>alert("diana")</script>', vuln_type=VulnType.XSS_REFLECTED)
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is None

    @pytest.mark.asyncio
    async def test_no_finding_when_canary_not_reflected(self, mock_http_client, sample_endpoint):
        """When the response doesn't contain the canary at all, no finding."""
        endpoint = sample_endpoint(url="http://app/search", parameters={"q": "test"})

        scanner = _make_scanner(mock_http_client, default_response=MockResponse(
            text='<html><body>No results found.</body></html>',
        ))

        payload = Payload(value='<script>alert("diana")</script>', vuln_type=VulnType.XSS_REFLECTED)
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is None

    @pytest.mark.asyncio
    async def test_no_finding_on_empty_response(self, mock_http_client, sample_endpoint):
        """Empty response body should not produce a finding."""
        endpoint = sample_endpoint(url="http://app/search", parameters={"q": "test"})

        scanner = _make_scanner(mock_http_client, default_response=MockResponse(text=""))

        payload = Payload(value='<script>alert("diana")</script>', vuln_type=VulnType.XSS_REFLECTED)
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is None

    @pytest.mark.asyncio
    async def test_handles_ai_generated_payload_without_diana_marker(self, mock_http_client, sample_endpoint):
        """AI-generated payloads that don't contain 'diana' should still work."""
        endpoint = sample_endpoint(url="http://app/search", parameters={"q": "test"})

        async def reflecting_get(url, **kwargs):
            if "q=" in url:
                from urllib.parse import parse_qs, urlparse
                val = parse_qs(urlparse(url).query).get("q", [""])[0]
                return MockResponse(text=f'<html><body>{val}</body></html>')
            return MockResponse(text="<html></html>")

        scanner = _make_scanner(mock_http_client)
        scanner.http.get = reflecting_get

        # AI-generated payload — no "diana" in it
        payload = Payload(value='<svg onload=alert(1)>', vuln_type=VulnType.XSS_REFLECTED)
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is not None

    @pytest.mark.asyncio
    async def test_get_params_actually_sent_to_server(self, mock_http_client, sample_endpoint):
        """Regression: GET params must be in the URL sent to the server."""
        endpoint = sample_endpoint(url="http://app/search", parameters={"q": "test"})

        requested_urls = []

        async def tracking_get(url, **kwargs):
            requested_urls.append(url)
            return MockResponse(text="<html></html>")

        scanner = _make_scanner(mock_http_client)
        scanner.http.get = tracking_get

        payload = Payload(value='<script>alert("diana")</script>', vuln_type=VulnType.XSS_REFLECTED)
        await scanner._test_payload(endpoint, payload)

        assert len(requested_urls) > 0
        # The URL must contain our injected param
        assert "q=" in requested_urls[0]
        # Should not just be the bare endpoint URL
        assert requested_urls[0] != "http://app/search"

    @pytest.mark.asyncio
    async def test_get_params_replace_existing_query_string(self, mock_http_client, sample_endpoint):
        """When endpoint URL already has a query string, it should be rebuilt with test params."""
        endpoint = sample_endpoint(url="http://app/search?q=original&page=1", parameters={"q": "test"})

        requested_urls = []

        async def tracking_get(url, **kwargs):
            requested_urls.append(url)
            return MockResponse(text="<html></html>")

        scanner = _make_scanner(mock_http_client)
        scanner.http.get = tracking_get

        payload = Payload(value='<script>alert("diana")</script>', vuln_type=VulnType.XSS_REFLECTED)
        await scanner._test_payload(endpoint, payload)

        assert len(requested_urls) > 0
        # Should NOT contain the original "q=original"
        assert "q=original" not in requested_urls[0]

    @pytest.mark.asyncio
    async def test_post_endpoint_sends_data(self, mock_http_client, sample_endpoint):
        """POST endpoints should send test params in the request body."""
        endpoint = sample_endpoint(url="http://app/feedback", method="POST", parameters={"comment": "hello"})

        post_calls = []

        async def tracking_post(url, **kwargs):
            post_calls.append({"url": url, "kwargs": kwargs})
            return MockResponse(text="<html></html>")

        scanner = _make_scanner(mock_http_client)
        scanner.http.post = tracking_post

        payload = Payload(value='<script>alert("diana")</script>', vuln_type=VulnType.XSS_REFLECTED)
        await scanner._test_payload(endpoint, payload)

        assert len(post_calls) > 0
        assert post_calls[0]["url"] == "http://app/feedback"

    @pytest.mark.asyncio
    async def test_no_finding_when_endpoint_has_no_parameters(self, mock_http_client):
        """Endpoint with no parameters should produce no findings."""
        endpoint = Endpoint(url="http://app/about", method="GET", parameters={})

        scanner = _make_scanner(mock_http_client, default_response=MockResponse(
            text='<html><script>alert(1)</script></html>',
        ))

        payload = Payload(value='<script>alert("diana")</script>', vuln_type=VulnType.XSS_REFLECTED)
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is None

    @pytest.mark.asyncio
    async def test_handles_http_exception_gracefully(self, mock_http_client, sample_endpoint):
        """HTTP errors should be skipped, not crash the scanner."""
        endpoint = sample_endpoint(url="http://app/search", parameters={"q": "test"})

        async def failing_get(url, **kwargs):
            raise ConnectionError("Connection refused")

        scanner = _make_scanner(mock_http_client)
        scanner.http.get = failing_get

        payload = Payload(value='<script>alert("diana")</script>', vuln_type=VulnType.XSS_REFLECTED)
        finding = await scanner._test_payload(endpoint, payload)

        assert finding is None  # Graceful skip, no crash


# ---------------------------------------------------------------------------
# Path-parameter injection — reflected XSS via RESTful path segments
# ---------------------------------------------------------------------------

class TestPathParameterInjection:
    """A param whose value is a path segment must be injected into the path,
    not only appended as an (ignored) query string. Generic to any REST app
    that reflects a path id/slug (e.g. /track-order/{id}, /product/{slug})."""

    def test_inject_into_path_replaces_matching_segment(self):
        out = XSSScanner._inject_into_path(
            "http://app/api/orders/1", "1", '<svg onload=alert(1)>'
        )
        # The '1' segment is replaced with the URL-encoded payload; the rest of
        # the path is preserved.
        assert out is not None
        assert out.startswith("http://app/api/orders/")
        assert "/orders/1" not in out
        assert "%3Csvg" in out  # '<' url-encoded into the path

    def test_inject_into_path_none_when_value_not_a_segment(self):
        # 'test' is a query value, not a path segment — nothing to inject.
        assert XSSScanner._inject_into_path("http://app/search", "test", "X") is None

    def test_inject_into_path_none_for_empty_value(self):
        assert XSSScanner._inject_into_path("http://app/x/1", "", "X") is None

    def test_inject_into_path_only_first_matching_segment(self):
        # Value appears twice; only the first segment is substituted so the URL
        # stays well-formed.
        out = XSSScanner._inject_into_path("http://app/1/1", "1", "P")
        assert out == "http://app/P/1"

    def test_injection_requests_includes_path_for_path_id_endpoint(self, sample_endpoint):
        ep = sample_endpoint(url="http://app/track-order/1", parameters={"id": "1"})
        scanner = XSSScanner(http=None, ai_agent=None)
        reqs = scanner._injection_requests(ep, "id", "PAYLOAD")
        locations = {loc for loc, _url, _data in reqs}
        assert locations == {"query", "path"}
        path_url = next(url for loc, url, _ in reqs if loc == "path")
        assert "track-order/PAYLOAD" in path_url

    def test_injection_requests_query_only_for_search_param(self, sample_endpoint):
        ep = sample_endpoint(url="http://app/search", parameters={"q": "test"})
        scanner = XSSScanner(http=None, ai_agent=None)
        reqs = scanner._injection_requests(ep, "q", "PAYLOAD")
        assert [loc for loc, _u, _d in reqs] == ["query"]

    def test_injection_requests_post_uses_body(self, sample_endpoint):
        ep = sample_endpoint(url="http://app/feedback", method="POST",
                             parameters={"comment": "hi"})
        scanner = XSSScanner(http=None, ai_agent=None)
        reqs = scanner._injection_requests(ep, "comment", "PAYLOAD")
        assert len(reqs) == 1
        loc, url, data = reqs[0]
        assert loc == "body" and url == "http://app/feedback"
        assert data == {"comment": "PAYLOAD"}

    @pytest.mark.asyncio
    async def test_detects_reflected_xss_via_path_segment(self, mock_http_client, sample_endpoint):
        """Payload injected into a path segment and reflected back is detected,
        and the finding records that it came from the path (not the query)."""
        ep = sample_endpoint(url="http://app/track-order/1", parameters={"id": "1"})

        async def reflecting_get(url, **kwargs):
            from urllib.parse import unquote, urlsplit
            last_seg = unquote(urlsplit(url).path.rsplit("/", 1)[-1])
            # Server echoes the path id verbatim into a JSON body.
            return MockResponse(text=f'{{"orderId":"{last_seg}","status":"ok"}}')

        scanner = _make_scanner(mock_http_client)
        scanner.http.get = reflecting_get

        payload = Payload(value='<iframe src="javascript:alert(`xss`)">',
                          vuln_type=VulnType.XSS_REFLECTED)
        finding = await scanner._test_payload(ep, payload)

        assert finding is not None
        assert "(path)" in finding.title

    @pytest.mark.asyncio
    async def test_canonical_payload_sent_verbatim(self, mock_http_client, sample_endpoint):
        """Canonical payloads (no marker) must not be mutated — the exact vector
        has to reach the server to exercise its output encoding."""
        ep = sample_endpoint(url="http://app/track-order/1", parameters={"id": "1"})
        seen = []

        async def tracking_get(url, **kwargs):
            from urllib.parse import unquote
            seen.append(unquote(url))
            return MockResponse(text="<html></html>")

        scanner = _make_scanner(mock_http_client)
        scanner.http.get = tracking_get

        payload = Payload(value='<iframe src="javascript:alert(`xss`)">',
                          vuln_type=VulnType.XSS_REFLECTED)
        await scanner._test_payload(ep, payload)

        # The exact payload appears verbatim in at least one request (path form).
        assert any('<iframe src="javascript:alert(`xss`)">' in u for u in seen)

    @pytest.mark.asyncio
    async def test_no_false_positive_from_surrounding_page_markup(self, mock_http_client, sample_endpoint):
        """Canary reflected but fully encoded, surrounded by the page's own
        markup, must NOT be reported (regression for the ±window bleed bug)."""
        ep = sample_endpoint(url="http://app/search", parameters={"q": "test"})

        async def encoding_get(url, **kwargs):
            from urllib.parse import parse_qs, urlparse
            val = parse_qs(urlparse(url).query).get("q", [""])[0]
            enc = (val.replace("&", "&amp;").replace("<", "&lt;")
                      .replace(">", "&gt;").replace('"', "&quot;"))
            # Reflection sits inside real page markup with plenty of raw '<'.
            return MockResponse(
                text=f'<html><body><div class="results">{enc}</div></body></html>'
            )

        scanner = _make_scanner(mock_http_client)
        scanner.http.get = encoding_get

        payload = Payload(value='<script>alert("diana")</script>',
                          vuln_type=VulnType.XSS_REFLECTED)
        finding = await scanner._test_payload(ep, payload)
        assert finding is None


# ---------------------------------------------------------------------------
# _test_dom_xss_sinks — DOM-based XSS detection via source/sink analysis
# ---------------------------------------------------------------------------

class TestDomXssSinkDetection:
    """Tests for _test_dom_xss_sinks — static source/sink analysis."""

    @pytest.mark.asyncio
    async def test_detects_innerhtml_with_location_hash(self, mock_http_client):
        """Page with location.hash flowing to innerHTML should be flagged."""
        page_with_dom_xss = """
        <html><body>
        <div id="output"></div>
        <script>
            var input = location.hash.substring(1);
            document.getElementById("output").innerHTML = input;
        </script>
        </body></html>
        """
        scanner = _make_scanner(mock_http_client, default_response=MockResponse(text=page_with_dom_xss))

        findings = await scanner._test_dom_xss_sinks(
            "http://app",
            [{"url": "http://app/page", "queue_id": 1}],
        )

        assert len(findings) >= 1
        assert findings[0].vuln_type == VulnType.XSS_DOM
        assert "location.hash" in findings[0].description or "location" in findings[0].evidence

    @pytest.mark.asyncio
    async def test_detects_document_write_with_document_url(self, mock_http_client):
        """Page with document.URL flowing to document.write should be flagged."""
        page = """
        <html><body>
        <script>
            var url = document.URL;
            document.write("<p>Current page: " + url + "</p>");
        </script>
        </body></html>
        """
        scanner = _make_scanner(mock_http_client, default_response=MockResponse(text=page))

        findings = await scanner._test_dom_xss_sinks("http://app", [])

        assert len(findings) >= 1
        assert findings[0].vuln_type == VulnType.XSS_DOM

    @pytest.mark.asyncio
    async def test_detects_eval_with_location_search(self, mock_http_client):
        """Page with location.search flowing to eval should be flagged."""
        page = """
        <html><body>
        <script>
            var params = location.search;
            eval(params.substring(1));
        </script>
        </body></html>
        """
        scanner = _make_scanner(mock_http_client, default_response=MockResponse(text=page))

        findings = await scanner._test_dom_xss_sinks("http://app", [])

        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_no_finding_when_no_sources_present(self, mock_http_client):
        """Page with sinks but no sources should not be flagged."""
        page = """
        <html><body>
        <script>
            var data = "safe static string";
            document.getElementById("out").innerHTML = data;
        </script>
        </body></html>
        """
        scanner = _make_scanner(mock_http_client, default_response=MockResponse(text=page))

        findings = await scanner._test_dom_xss_sinks("http://app", [])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_finding_when_no_sinks_present(self, mock_http_client):
        """Page with sources but no dangerous sinks should not be flagged."""
        page = """
        <html><body>
        <script>
            var hash = location.hash;
            console.log("Hash is: " + hash);
        </script>
        </body></html>
        """
        scanner = _make_scanner(mock_http_client, default_response=MockResponse(text=page))

        findings = await scanner._test_dom_xss_sinks("http://app", [])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_finding_on_plain_html_page(self, mock_http_client):
        """Static HTML page with no JavaScript should produce no findings."""
        page = "<html><body><h1>Welcome</h1><p>No scripts here.</p></body></html>"
        scanner = _make_scanner(mock_http_client, default_response=MockResponse(text=page))

        findings = await scanner._test_dom_xss_sinks("http://app", [])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_finding_on_empty_response(self, mock_http_client):
        """Empty response should produce no findings."""
        scanner = _make_scanner(mock_http_client, default_response=MockResponse(text=""))

        findings = await scanner._test_dom_xss_sinks("http://app", [])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_handles_http_error_gracefully(self, mock_http_client):
        """HTTP errors during DOM sink scanning should not crash."""
        async def failing_get(url, **kwargs):
            raise ConnectionError("Connection refused")

        scanner = _make_scanner(mock_http_client)
        scanner.http.get = failing_get

        findings = await scanner._test_dom_xss_sinks("http://app", [])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_deduplicates_urls_from_work_items(self, mock_http_client):
        """Multiple work items with the same base URL should only be checked once."""
        request_count = []

        async def counting_get(url, **kwargs):
            request_count.append(url)
            return MockResponse(text="<html><body>clean</body></html>")

        scanner = _make_scanner(mock_http_client)
        scanner.http.get = counting_get

        # Same base URL repeated in work items with different query strings
        work_items = [
            {"url": "http://app/page?q=1", "queue_id": 1},
            {"url": "http://app/page?q=2", "queue_id": 2},
            {"url": "http://app/page?q=3", "queue_id": 3},
        ]

        await scanner._test_dom_xss_sinks("http://app", work_items)

        # Should have checked http://app (base) and http://app/page (deduped) = 2 unique URLs
        unique_urls = set(request_count)
        assert len(unique_urls) <= 2
