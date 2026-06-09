"""SSRF (Server-Side Request Forgery) detection module."""

from __future__ import annotations

import uuid
from urllib.parse import urlencode

from diana.config import ScanConfig
from diana.core.models import (
    Endpoint,
    Finding,
    Payload,
    Severity,
    VulnType,
)
from diana.scanners.base import BaseScanner

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://metadata.google.internal/",
    "http://169.254.169.254/metadata/v1/",  # Azure/DO
    "http://0177.0.0.1",  # Octal
    "http://0x7f.0x0.0x0.0x1",  # Hex
    "http://2130706433",  # Decimal
]

SSRF_INDICATORS = [
    "ami-id",
    "instance-id",
    "instance-type",
    "local-ipv4",
    "security-credentials",
    "computeMetadata",
    "root:x:0:0",
    "connection refused",
    "<!doctype html>",  # Internal page returned
]

# Parameters likely to accept URLs
URL_PARAM_NAMES = [
    "url", "uri", "link", "href", "src", "source", "redirect",
    "return", "next", "dest", "destination", "target", "path",
    "page", "feed", "host", "site", "callback", "webhook",
    "proxy", "fetch", "load", "file", "document", "image",
]


class SSRFScanner(BaseScanner):
    name = "ssrf"
    description = "Server-Side Request Forgery detection"

    @property
    def vuln_types(self) -> list:
        return [VulnType.SSRF]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []

        work_items = self.claim_work(limit=30)
        if not work_items:
            return findings

        # Build endpoints from work items (queue already filtered for URL params)
        testable = []
        for item in work_items:
            params = item.get("payload", {}) or {}
            ep = Endpoint(
                url=item["url"],
                method=item.get("method", "GET"),
                parameters=params.get("parameters", {}),
            )
            testable.append(ep)

        for endpoint in testable:
            payloads = await self._get_payloads(endpoint)

            for payload in payloads:
                finding = await self._test_payload(endpoint, payload)
                if finding:
                    findings.append(finding)

        for item in work_items:
            self.complete_work(item["queue_id"])

        return findings

    async def _get_payloads(
        self, endpoint: Endpoint,
    ) -> list[Payload]:
        payloads: list[Payload] = []

        if self.ai:
            hyp = Hypothesis(
                vuln_type=VulnType.SSRF,
                endpoint=endpoint,
                confidence=0.5,
                reasoning="Endpoint has URL-accepting parameters",
            )
            ai_payloads = await self.ai.generate_payloads(hyp)
            payloads.extend(ai_payloads)

        for p in SSRF_PAYLOADS:
            payloads.append(Payload(value=p, vuln_type=VulnType.SSRF))

        return payloads

    async def _test_payload(
        self, endpoint: Endpoint, payload: Payload
    ) -> Finding | None:
        url_params = [
            name for name in endpoint.parameters
            if name.lower() in URL_PARAM_NAMES
        ]
        if not url_params:
            url_params = list(endpoint.parameters.keys())

        for param_name in url_params:
            test_params = dict(endpoint.parameters)
            test_params[param_name] = payload.value

            try:
                if endpoint.method.upper() == "GET":
                    url = f"{endpoint.url}?{urlencode(test_params)}"
                    response = await self.http.get(url)
                else:
                    response = await self.http.post(endpoint.url, data=test_params)
            except Exception:
                continue

            response_lower = response.text.lower()
            for indicator in SSRF_INDICATORS:
                if indicator.lower() in response_lower:
                    return Finding(
                        id=f"SSRF-{uuid.uuid4().hex[:8]}",
                        vuln_type=VulnType.SSRF,
                        severity=Severity.CRITICAL,
                        title=f"SSRF in {param_name} at {endpoint.url}",
                        description=(
                            f"The parameter '{param_name}' is vulnerable to SSRF. "
                            f"Internal resources are accessible via this endpoint."
                        ),
                        endpoint=endpoint,
                        evidence=response.text[:500],
                        payload_used=payload.value,
                        cwe_id="CWE-918",
                        remediation=(
                            "Validate and whitelist allowed URLs/domains. "
                            "Block access to internal/cloud metadata endpoints. "
                            "Use a dedicated egress proxy for outbound requests."
                        ),
                    )

        return None
