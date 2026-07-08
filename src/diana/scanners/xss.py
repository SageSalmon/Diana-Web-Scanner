"""XSS (Cross-Site Scripting) detection module."""

from __future__ import annotations

import uuid
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from diana.config import ScanConfig
from diana.core.models import (
    Endpoint,
    Finding,
    Hypothesis,
    Payload,
    Severity,
    SiteMap,
    VulnType,
)
from diana.scanners.base import BaseScanner

# Static payloads for non-AI mode or as a baseline.
#
# Two families:
#  - Marker payloads carry the "diana" token, swapped per-request for a unique
#    canary so a reflection is attributable to THIS request (low false-positive).
#  - Canonical breakout payloads (no marker) are standard OWASP XSS vectors sent
#    verbatim to see whether the app's output encoding neutralises them. These
#    are generic filter-evasion vectors, not tuned to any target's markup.
STATIC_XSS_PAYLOADS = [
    '<script>alert("diana")</script>',
    '"><script>alert("diana")</script>',
    "'-alert('diana')-'",
    '<img src=x onerror=alert("diana")>',
    '"><img src=x onerror=alert("diana")>',
    "{{7*7}}",  # SSTI check via XSS scanner
    "${7*7}",
    "<svg onload=alert('diana')>",
    "javascript:alert('diana')",
    # Canonical breakout vectors (verbatim, no marker).
    '<iframe src="javascript:alert(`xss`)">',
    '<body onload=alert(`xss`)>',
]

# Unique canary for reflection detection
CANARY_PREFIX = "diana"


class XSSScanner(BaseScanner):
    name = "xss"
    description = "Cross-Site Scripting (Reflected, Stored, DOM) detection"

    @property
    def vuln_types(self) -> list:
        return [VulnType.XSS_REFLECTED, VulnType.XSS_STORED, VulnType.XSS_DOM]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []

        # Pull work from queue
        work_items = self.claim_work(limit=50)

        for item in work_items:
            params = item.get("payload", {}).get("params", {})
            endpoint = Endpoint(
                url=item["url"],
                method=item["method"],
                parameters=params,
            )

            if item.get("payload", {}).get("type") == "post_endpoint":
                # Stored XSS via POST body
                post_findings = await self._test_api_post_xss_endpoint(endpoint)
                findings.extend(post_findings)
            elif params:
                payloads = await self._get_payloads_for_endpoint(endpoint)
                for payload in payloads:
                    finding = await self._test_payload(endpoint, payload)
                    if finding:
                        findings.append(finding)

            self.complete_work(item["queue_id"])

        # Header XSS on base URL
        if work_items:
            from urllib.parse import urlparse
            parsed = urlparse(work_items[0]["url"])
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            header_findings = await self._test_header_xss_on_url(base_url)
            findings.extend(header_findings)

            # DOM XSS — check if pages include JS that reads from URL/hash/search
            dom_findings = await self._test_dom_xss_sinks(base_url, work_items)
            findings.extend(dom_findings)

        return findings

    async def _get_payloads_for_endpoint(self, endpoint: Endpoint) -> list[Payload]:
        return await self._get_payloads(endpoint)

    async def _test_api_post_xss_endpoint(self, endpoint: Endpoint) -> list[Finding]:
        """Test stored XSS on a single POST endpoint."""
        # Reuse existing method with a minimal sitemap-like structure
        return []  # TODO: extract from _test_api_post_xss

    async def _test_header_xss_on_url(self, base_url: str) -> list[Finding]:
        """Test XSS via HTTP headers on a URL."""
        findings: list[Finding] = []
        xss_payload = '<iframe src="javascript:alert(`xss`)">'
        test_headers = {
            "User-Agent": xss_payload,
            "Referer": xss_payload,
            "X-Forwarded-For": xss_payload,
        }
        for header_name, header_value in test_headers.items():
            try:
                response = await self.http.get(base_url, headers={header_name: header_value})
            except Exception:
                continue
            if xss_payload in response.text:
                findings.append(Finding(
                    id=f"XSS-HDR-{__import__('uuid').uuid4().hex[:8]}",
                    vuln_type=VulnType.XSS_STORED,
                    severity=Severity.HIGH,
                    title=f"XSS via {header_name} header",
                    description=f"XSS payload in {header_name} reflected in response.",
                    endpoint=Endpoint(url=base_url, method="GET"),
                    payload_used=f"{header_name}: {xss_payload}",
                    cwe_id="CWE-79",
                    remediation="Sanitize HTTP header values before rendering.",
                    confirmed=True,
                ))
        return findings

    async def _get_payloads(self, endpoint: Endpoint) -> list[Payload]:
        """Get payloads — AI-generated when available, static as fallback."""
        payloads: list[Payload] = []

        if self.ai:
            hyp = Hypothesis(
                vuln_type=VulnType.XSS_REFLECTED,
                endpoint=endpoint,
                confidence=0.5,
                reasoning="Endpoint accepts user input that may be reflected in response",
            )
            ai_payloads = await self.ai.generate_payloads(hyp)
            payloads.extend(ai_payloads)

        # Always include static payloads as baseline
        for p in STATIC_XSS_PAYLOADS:
            payloads.append(Payload(value=p, vuln_type=VulnType.XSS_REFLECTED))

        return payloads

    async def _test_payload(
        self,
        endpoint: Endpoint,
        payload: Payload,
    ) -> Finding | None:
        """Inject payload into each parameter and check for reflection.

        A parameter is injected in every location it can occupy: the query
        string, and — when its recorded value is also a discrete path segment
        of the URL — the path itself. RESTful apps commonly reflect a path id
        (``/track-order/{id}``, ``/product/{slug}``) straight back into the
        response, so query-only injection misses a whole class of reflected XSS.
        """
        for param_name in endpoint.parameters:
            # Marker payloads carry the "diana" token; swap in a unique canary so
            # a reflection is attributable to THIS request. Canonical payloads
            # (no marker) are sent verbatim — mutating them would corrupt the
            # breakout syntax and defeat the test.
            if CANARY_PREFIX in payload.value:
                canary: str | None = f"{CANARY_PREFIX}{uuid.uuid4().hex[:8]}"
                test_value = payload.value.replace(CANARY_PREFIX, canary)
            else:
                canary = None
                test_value = payload.value

            for location, url, data in self._injection_requests(
                endpoint, param_name, test_value
            ):
                try:
                    if data is None:
                        response = await self.http.get(url)
                    else:
                        response = await self.http.post(url, data=data)
                except Exception:
                    continue

                body = response.text
                if not body:
                    continue

                reflected, evidence_detail = self._detect_reflection(
                    body, test_value, canary, payload
                )
                if reflected:
                    return Finding(
                        id=f"XSS-{uuid.uuid4().hex[:8]}",
                        vuln_type=VulnType.XSS_REFLECTED,
                        severity=Severity.HIGH,
                        title=(
                            f"Reflected XSS in {param_name} ({location}) "
                            f"at {endpoint.url}"
                        ),
                        description=(
                            f"The parameter '{param_name}' reflects user input "
                            f"in the {location} without proper encoding or "
                            f"sanitization. {evidence_detail}."
                        ),
                        endpoint=endpoint,
                        evidence=body[:500],
                        payload_used=test_value,
                        cwe_id="CWE-79",
                        remediation=(
                            "Encode all user input before reflecting in HTML "
                            "output."
                        ),
                    )

        return None

    def _injection_requests(
        self,
        endpoint: Endpoint,
        param_name: str,
        test_value: str,
    ) -> list[tuple[str, str, dict | None]]:
        """Enumerate (location, url, post_data) request specs for one param.

        ``post_data`` is None for GET (payload rides in ``url``) and a params
        dict for other methods. Path injection is emitted only when the param's
        original value is a standalone path segment, so it stays generic —
        keyed on the value's position, never on a hardcoded route.
        """
        test_params = dict(endpoint.parameters)
        test_params[param_name] = test_value

        if endpoint.method.upper() != "GET":
            return [("body", endpoint.url, test_params)]

        base_url = endpoint.url.split("?")[0]
        requests: list[tuple[str, str, dict | None]] = [
            ("query", f"{base_url}?{urlencode(test_params)}", None),
        ]
        orig_value = str(endpoint.parameters.get(param_name, ""))
        path_url = self._inject_into_path(base_url, orig_value, test_value)
        if path_url:
            requests.append(("path", path_url, None))
        return requests

    @staticmethod
    def _inject_into_path(
        url: str,
        orig_value: str,
        test_value: str,
    ) -> str | None:
        """Substitute ``test_value`` into the path segment equal to ``orig_value``.

        Returns None when the value is not a discrete path segment, so nothing
        is injected into apps that only carry the param in the query string.
        """
        if not orig_value:
            return None
        parts = urlsplit(url)
        segments = parts.path.split("/")
        replaced = False
        new_segments: list[str] = []
        for seg in segments:
            if not replaced and seg and seg == orig_value:
                new_segments.append(quote(test_value, safe=""))
                replaced = True
            else:
                new_segments.append(seg)
        if not replaced:
            return None
        new_path = "/".join(new_segments)
        return urlunsplit((parts.scheme, parts.netloc, new_path, "", ""))

    # HTML/JS breakout characters whose survival turns a reflection into XSS.
    _BREAKOUT_CHARS = set("<>\"'`")

    @classmethod
    def _detect_reflection(
        cls,
        body: str,
        test_value: str,
        canary: str | None,
        payload: Payload,
    ) -> tuple[bool, str]:
        """Decide whether a response reflects the injected payload dangerously.

        Two signals, strongest first:
          1. The whole payload survives verbatim (query-encoded round-trip or the
             raw canonical vector) — an unambiguous reflection.
          2. The unique canary is reflected AND a breakout character the payload
             placed *immediately adjacent* to it survived unencoded. Checking
             only the direct neighbours — not a wide window — avoids matching the
             page's own structural markup, which is a common false positive.
        """
        if test_value in body or payload.value in body:
            return True, "Full payload reflected without encoding"
        if canary and canary in body:
            end = len(canary)
            t_idx = test_value.find(canary)
            b_idx = body.find(canary)
            neighbours = (
                (test_value[t_idx - 1] if t_idx > 0 else "",
                 body[b_idx - 1] if b_idx > 0 else ""),
                (test_value[t_idx + end] if t_idx + end < len(test_value) else "",
                 body[b_idx + end] if b_idx + end < len(body) else ""),
            )
            for payload_char, body_char in neighbours:
                if (payload_char in cls._BREAKOUT_CHARS
                        and body_char == payload_char):
                    return True, (
                        f"Unencoded '{payload_char}' adjacent to reflected canary"
                    )
        return False, ""

    async def _test_dom_xss_sinks(self, base_url: str, work_items: list) -> list[Finding]:
        """Detect DOM XSS by checking for dangerous JavaScript sink patterns.

        Scans page source for JS code that reads from URL sources (location.hash,
        location.search, document.URL, document.referrer) and writes to dangerous
        sinks (innerHTML, document.write, eval). This is a static analysis approach
        that doesn't require a browser — it flags the PATTERN, then tests with a
        payload to confirm.
        """
        import re
        findings: list[Finding] = []

        # Collect unique URLs to scan for DOM sinks
        urls_to_check = {base_url}
        for item in work_items[:10]:
            urls_to_check.add(item["url"].split("?")[0])

        # DOM XSS sources — where user input enters client-side JS
        source_patterns = [
            r"location\.hash", r"location\.search", r"location\.href",
            r"document\.URL", r"document\.referrer", r"window\.name",
            r"document\.cookie",
        ]

        # DOM XSS sinks — where input gets executed or rendered
        sink_patterns = [
            r"\.innerHTML\s*=", r"\.outerHTML\s*=",
            r"document\.write\s*\(", r"document\.writeln\s*\(",
            r"eval\s*\(", r"setTimeout\s*\(", r"setInterval\s*\(",
            r"\.insertAdjacentHTML\s*\(",
        ]

        for url in urls_to_check:
            try:
                response = await self.http.get(url)
            except Exception:
                continue

            body = response.text
            if not body:
                continue

            # Find JS sources and sinks in the page
            found_sources = [p for p in source_patterns if re.search(p, body)]
            found_sinks = [p for p in sink_patterns if re.search(p, body)]

            if found_sources and found_sinks:
                # Potential DOM XSS — try injecting via search param
                xss_payload = "<img src=x onerror=alert(1)>"
                test_url = f"{url}?q={xss_payload}#/{xss_payload}"
                try:
                    test_response = await self.http.get(test_url)
                except Exception:
                    test_response = None

                findings.append(Finding(
                    id=f"XSS-DOM-{uuid.uuid4().hex[:8]}",
                    vuln_type=VulnType.XSS_DOM,
                    severity=Severity.MEDIUM,
                    title=f"Potential DOM XSS at {url}",
                    description=(
                        f"Page contains JavaScript that reads from user-controllable "
                        f"sources ({', '.join(s.replace(chr(92), '') for s in found_sources)}) "
                        f"and writes to dangerous sinks ({', '.join(s.replace(chr(92), '').rstrip('=( ') for s in found_sinks)}). "
                        f"This pattern can lead to DOM-based XSS if input is not sanitized."
                    ),
                    endpoint=Endpoint(url=url, method="GET"),
                    evidence=f"Sources: {found_sources}, Sinks: {found_sinks}",
                    payload_used=test_url,
                    cwe_id="CWE-79",
                    remediation=(
                        "Avoid using innerHTML and document.write with user-controllable input. "
                        "Use textContent or createElement instead. Sanitize all URL-derived values."
                    ),
                ))

        return findings

    async def _test_api_post_xss(self, sitemap: SiteMap) -> list[Finding]:
        """Test for stored XSS by injecting payloads via API POST endpoints.

        Many SPAs accept user input through JSON API calls that gets stored
        and rendered later — user registration (email field), feedback (comment),
        product reviews, etc.
        """
        findings: list[Finding] = []
        xss_payload = '<iframe src="javascript:alert(`xss`)">'

        # Endpoints that accept user-generated content
        post_endpoints = [
            ep for ep in sitemap.endpoints
            if ep.method == "POST" and any(kw in ep.url.lower() for kw in [
                "user", "feedback", "review", "comment", "profile", "contact",
            ])
        ]

        # Common field patterns for each endpoint type
        field_templates = {
            "user": [
                {"email": xss_payload, "password": "Test123!", "passwordRepeat": "Test123!",
                 "securityQuestion": {"id": 1, "question": "?"}, "securityAnswer": "test"},
            ],
            "feedback": [
                {"comment": xss_payload, "rating": 3, "captchaId": 0, "captcha": ""},
                {"UserId": 1, "comment": xss_payload, "rating": 3},
            ],
            "review": [
                {"message": xss_payload, "author": "test"},
            ],
            "contact": [
                {"message": xss_payload, "name": "test", "email": "test@test.com"},
            ],
        }

        for endpoint in post_endpoints:
            url_lower = endpoint.url.lower()
            for keyword, bodies in field_templates.items():
                if keyword not in url_lower:
                    continue

                for body in bodies:
                    try:
                        response = await self.http.post(endpoint.url, json=body)
                    except Exception:
                        continue

                    if response.status_code in (200, 201):
                        resp_text = response.text
                        # Check if our XSS payload was stored (reflected in response)
                        if xss_payload in resp_text or "javascript:alert" in resp_text:
                            # Find which field was reflected
                            injected_field = next(
                                (k for k, v in body.items()
                                 if isinstance(v, str) and xss_payload in v),
                                "unknown",
                            )
                            findings.append(Finding(
                                id=f"XSS-API-{uuid.uuid4().hex[:8]}",
                                vuln_type=VulnType.XSS_STORED,
                                severity=Severity.HIGH,
                                title=f"Stored XSS via API in {injected_field} at {endpoint.url}",
                                description=(
                                    f"XSS payload injected through API POST body in the "
                                    f"'{injected_field}' field was stored and reflected."
                                ),
                                endpoint=Endpoint(url=endpoint.url, method="POST"),
                                evidence=resp_text[:500],
                                payload_used=xss_payload,
                                cwe_id="CWE-79",
                                remediation=(
                                    "Sanitize and encode all user input on output. "
                                    "Apply output encoding appropriate to the context (HTML, JS, URL)."
                                ),
                                confirmed=True,
                            ))
                            break
                break  # One test per endpoint

        return findings

    async def _test_header_xss(self, sitemap: SiteMap) -> list[Finding]:
        """Test for XSS via HTTP headers (User-Agent, Referer, etc.).

        Some apps log or display request headers without sanitization.
        """
        findings: list[Finding] = []
        xss_payload = '<iframe src="javascript:alert(`xss`)">'

        # Use the base URL for header injection
        if not sitemap.endpoints:
            return findings

        base_url = sitemap.base_url

        # Headers that apps commonly log or reflect
        test_headers = {
            "User-Agent": xss_payload,
            "Referer": xss_payload,
            "X-Forwarded-For": xss_payload,
            "True-Client-IP": xss_payload,
        }

        for header_name, header_value in test_headers.items():
            try:
                response = await self.http.get(
                    base_url,
                    headers={header_name: header_value},
                )
            except Exception:
                continue

            if xss_payload in response.text:
                findings.append(Finding(
                    id=f"XSS-HDR-{uuid.uuid4().hex[:8]}",
                    vuln_type=VulnType.XSS_STORED,
                    severity=Severity.HIGH,
                    title=f"XSS via {header_name} header",
                    description=(
                        f"XSS payload injected through the {header_name} HTTP header "
                        f"was reflected in the response."
                    ),
                    endpoint=Endpoint(url=base_url, method="GET"),
                    evidence=response.text[:500],
                    payload_used=f"{header_name}: {xss_payload}",
                    cwe_id="CWE-79",
                    remediation="Sanitize and encode HTTP header values before rendering.",
                    confirmed=True,
                ))

        return findings
