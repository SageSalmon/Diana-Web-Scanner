"""Broken authentication and IDOR detection module."""

from __future__ import annotations

import uuid
from urllib.parse import urlencode, urlparse

from diana.config import ScanConfig
from diana.core.models import (
    Endpoint,
    Finding,
    Severity,
    VulnType,
)
from diana.scanners.base import BaseScanner

# Common IDOR parameter names
IDOR_PARAMS = [
    "id", "user_id", "uid", "account", "account_id", "profile",
    "order", "order_id", "doc", "document_id", "file_id", "record",
    "invoice", "invoice_id", "customer_id", "org_id", "project_id",
]


class AuthScanner(BaseScanner):
    name = "auth"
    description = "Broken authentication and IDOR detection"

    @property
    def vuln_types(self) -> list:
        return [VulnType.BROKEN_AUTH, VulnType.IDOR, VulnType.OPEN_REDIRECT, VulnType.PATH_TRAVERSAL]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []

        work_items = self.claim_work(limit=50)
        if not work_items:
            return findings

        # Build endpoints from work items
        endpoints = []
        for item in work_items:
            params = item.get("payload", {}) or {}
            ep = Endpoint(
                url=item["url"],
                method=item.get("method", "GET"),
                parameters=params.get("parameters", {}),
            )
            endpoints.append(ep)

        # IDOR checks
        idor_findings = await self._check_idor(endpoints)
        findings.extend(idor_findings)

        # Path traversal checks
        traversal_findings = await self._check_path_traversal(endpoints)
        findings.extend(traversal_findings)

        # Open redirect checks
        redirect_findings = await self._check_open_redirect(endpoints)
        findings.extend(redirect_findings)

        for item in work_items:
            self.complete_work(item["queue_id"])

        return findings

    async def _check_idor(self, endpoints: list[Endpoint]) -> list[Finding]:
        """Check for IDOR by manipulating ID parameters."""
        findings: list[Finding] = []

        for endpoint in endpoints:
            idor_params = [
                name for name in endpoint.parameters
                if name.lower() in IDOR_PARAMS
            ]
            if not idor_params:
                continue

            # Get baseline response
            try:
                baseline = await self.http.get(endpoint.url)
            except Exception:
                continue

            for param_name in idor_params:
                original_value = endpoint.parameters.get(param_name, "1")

                # Try adjacent IDs
                for test_value in self._generate_idor_values(original_value):
                    test_params = dict(endpoint.parameters)
                    test_params[param_name] = test_value

                    try:
                        url = f"{endpoint.url}?{urlencode(test_params)}"
                        response = await self.http.get(url)
                    except Exception:
                        continue

                    # If we get a 200 with different content, potential IDOR
                    if (
                        response.status_code == 200
                        and response.text != baseline.text
                        and len(response.text) > 50
                    ):
                        findings.append(Finding(
                            id=f"IDOR-{uuid.uuid4().hex[:8]}",
                            vuln_type=VulnType.IDOR,
                            severity=Severity.HIGH,
                            title=f"Potential IDOR in {param_name} at {endpoint.url}",
                            description=(
                                f"Changing '{param_name}' from {original_value} to {test_value} "
                                f"returned different data, suggesting broken access control."
                            ),
                            endpoint=endpoint,
                            payload_used=test_value,
                            cwe_id="CWE-639",
                            remediation=(
                                "Implement server-side authorization checks. "
                                "Verify the authenticated user has access to the requested resource."
                            ),
                        ))
                        break  # One finding per parameter

        return findings

    async def _check_path_traversal(self, endpoints: list[Endpoint]) -> list[Finding]:
        findings: list[Finding] = []

        file_params = ["file", "path", "page", "template", "include", "doc", "folder", "dir"]
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]

        for endpoint in endpoints:
            target_params = [
                name for name in endpoint.parameters
                if name.lower() in file_params
            ]
            if not target_params:
                continue

            for param_name in target_params:
                for payload in traversal_payloads:
                    test_params = dict(endpoint.parameters)
                    test_params[param_name] = payload

                    try:
                        url = f"{endpoint.url}?{urlencode(test_params)}"
                        response = await self.http.get(url)
                    except Exception:
                        continue

                    if "root:" in response.text or "[extensions]" in response.text:
                        findings.append(Finding(
                            id=f"TRAV-{uuid.uuid4().hex[:8]}",
                            vuln_type=VulnType.PATH_TRAVERSAL,
                            severity=Severity.CRITICAL,
                            title=f"Path Traversal in {param_name} at {endpoint.url}",
                            description=f"The parameter '{param_name}' allows file path traversal.",
                            endpoint=endpoint,
                            evidence=response.text[:300],
                            payload_used=payload,
                            cwe_id="CWE-22",
                            remediation="Validate and sanitize file paths. Use a whitelist of allowed files.",
                        ))
                        break

        return findings

    async def _check_open_redirect(self, endpoints: list[Endpoint]) -> list[Finding]:
        findings: list[Finding] = []

        redirect_params = ["redirect", "return", "next", "url", "dest", "destination", "continue", "return_to"]
        evil_urls = ["https://evil.com", "//evil.com", "/\\evil.com"]

        for endpoint in endpoints:
            target_params = [
                name for name in endpoint.parameters
                if name.lower() in redirect_params
            ]
            if not target_params:
                continue

            for param_name in target_params:
                for evil_url in evil_urls:
                    test_params = dict(endpoint.parameters)
                    test_params[param_name] = evil_url

                    try:
                        url = f"{endpoint.url}?{urlencode(test_params)}"
                        response = await self.http.get(url, follow_redirects=False)
                    except Exception:
                        continue

                    location = response.headers.get("location", "")
                    if "evil.com" in location:
                        findings.append(Finding(
                            id=f"REDIR-{uuid.uuid4().hex[:8]}",
                            vuln_type=VulnType.OPEN_REDIRECT,
                            severity=Severity.MEDIUM,
                            title=f"Open Redirect in {param_name} at {endpoint.url}",
                            description=f"The parameter '{param_name}' allows redirecting to external sites.",
                            endpoint=endpoint,
                            evidence=f"Location: {location}",
                            payload_used=evil_url,
                            cwe_id="CWE-601",
                            remediation="Validate redirect URLs against a whitelist of allowed destinations.",
                        ))
                        break

        return findings

    @staticmethod
    def _generate_idor_values(original: str) -> list[str]:
        try:
            n = int(original)
            return [str(n + 1), str(n - 1), str(n + 100), "0"]
        except ValueError:
            return ["1", "2", "admin", "test"]
