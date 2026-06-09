"""Security headers analysis module."""

from __future__ import annotations

import uuid

from diana.config import ScanConfig
from diana.core.models import (
    Endpoint,
    Finding,
    Hypothesis,
    Severity,
    SiteMap,
    VulnType,
)
from diana.scanners.base import BaseScanner

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "severity": Severity.MEDIUM,
        "title": "Missing Strict-Transport-Security (HSTS)",
        "description": "HSTS header is not set, allowing potential protocol downgrade attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        "cwe": "CWE-319",
    },
    "content-security-policy": {
        "severity": Severity.MEDIUM,
        "title": "Missing Content-Security-Policy (CSP)",
        "description": "CSP header is not set, increasing XSS attack surface.",
        "remediation": "Implement a Content-Security-Policy header with a restrictive policy.",
        "cwe": "CWE-693",
    },
    "x-content-type-options": {
        "severity": Severity.LOW,
        "title": "Missing X-Content-Type-Options",
        "description": "Browser MIME-sniffing is not disabled.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        "cwe": "CWE-693",
    },
    "x-frame-options": {
        "severity": Severity.MEDIUM,
        "title": "Missing X-Frame-Options",
        "description": "Page can be embedded in iframes, enabling clickjacking.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
        "cwe": "CWE-1021",
    },
    "referrer-policy": {
        "severity": Severity.LOW,
        "title": "Missing Referrer-Policy",
        "description": "Referrer information may leak to third-party sites.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
        "cwe": "CWE-200",
    },
    "permissions-policy": {
        "severity": Severity.LOW,
        "title": "Missing Permissions-Policy",
        "description": "Browser features (camera, microphone, geolocation) not restricted.",
        "remediation": "Add a Permissions-Policy header to restrict browser feature access.",
        "cwe": "CWE-693",
    },
}

INSECURE_HEADERS = {
    "server": {
        "severity": Severity.INFO,
        "title": "Server Version Disclosed",
        "description": "Server header reveals version information.",
        "remediation": "Remove or generalize the Server header.",
        "cwe": "CWE-200",
    },
    "x-powered-by": {
        "severity": Severity.INFO,
        "title": "X-Powered-By Header Present",
        "description": "Technology stack information disclosed.",
        "remediation": "Remove the X-Powered-By header.",
        "cwe": "CWE-200",
    },
    "x-aspnet-version": {
        "severity": Severity.INFO,
        "title": "ASP.NET Version Disclosed",
        "description": "ASP.NET version disclosed in headers.",
        "remediation": "Remove the X-AspNet-Version header.",
        "cwe": "CWE-200",
    },
}


class HeadersScanner(BaseScanner):
    name = "headers"
    description = "Security headers analysis"

    @property
    def vuln_types(self) -> list:
        return [VulnType.SECURITY_HEADERS, VulnType.CORS_MISCONFIGURATION, VulnType.INFO_DISCLOSURE]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []

        # Pull work from queue
        work_items = self.claim_work(limit=5)
        if not work_items:
            return findings

        item = work_items[0]
        try:
            response = await self.http.get(item["url"])
        except Exception:
            self.complete_work(item["queue_id"])
            return findings

        base_endpoint = Endpoint(url=item["url"])

        headers = {k.lower(): v for k, v in response.headers.items()}

        # Check for missing security headers
        for header_name, info in REQUIRED_HEADERS.items():
            if header_name not in headers:
                findings.append(Finding(
                    id=f"HDR-{uuid.uuid4().hex[:8]}",
                    vuln_type=VulnType.SECURITY_HEADERS,
                    severity=info["severity"],
                    title=info["title"],
                    description=info["description"],
                    endpoint=base_endpoint,
                    remediation=info["remediation"],
                    cwe_id=info["cwe"],
                    confirmed=True,
                ))

        # Check for information-leaking headers
        for header_name, info in INSECURE_HEADERS.items():
            if header_name in headers:
                findings.append(Finding(
                    id=f"HDR-{uuid.uuid4().hex[:8]}",
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    severity=info["severity"],
                    title=info["title"],
                    description=f"{info['description']} Value: {headers[header_name]}",
                    endpoint=base_endpoint,
                    evidence=f"{header_name}: {headers[header_name]}",
                    remediation=info["remediation"],
                    cwe_id=info["cwe"],
                    confirmed=True,
                ))

        # CORS check
        cors_finding = await self._check_cors(base_endpoint, headers)
        if cors_finding:
            findings.append(cors_finding)

        # Cookie security check
        cookie_findings = self._check_cookies(response, base_endpoint)
        findings.extend(cookie_findings)

        for w in work_items:
            self.complete_work(w["queue_id"])

        return findings

    async def _check_cors(self, endpoint: Endpoint, headers: dict) -> Finding | None:
        """Check for CORS misconfiguration."""
        try:
            response = await self.http.get(
                endpoint.url,
                headers={"Origin": "https://evil.com"},
            )
        except Exception:
            return None

        acao = response.headers.get("access-control-allow-origin", "")
        if acao == "*" or acao == "https://evil.com":
            return Finding(
                id=f"CORS-{uuid.uuid4().hex[:8]}",
                vuln_type=VulnType.CORS_MISCONFIGURATION,
                severity=Severity.HIGH if "credentials" in response.headers.get(
                    "access-control-allow-credentials", ""
                ).lower() else Severity.MEDIUM,
                title="Permissive CORS Configuration",
                description=f"CORS allows requests from arbitrary origins. ACAO: {acao}",
                endpoint=endpoint,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                cwe_id="CWE-942",
                remediation="Restrict CORS to trusted origins only.",
                confirmed=True,
            )
        return None

    def _check_cookies(self, response, endpoint: Endpoint) -> list[Finding]:
        findings = []
        for cookie_header in response.headers.get_list("set-cookie"):
            cookie_lower = cookie_header.lower()
            name = cookie_header.split("=")[0].strip()

            issues = []
            if "secure" not in cookie_lower:
                issues.append("missing Secure flag")
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite attribute")

            if issues:
                findings.append(Finding(
                    id=f"COOKIE-{uuid.uuid4().hex[:8]}",
                    vuln_type=VulnType.SECURITY_HEADERS,
                    severity=Severity.LOW,
                    title=f"Insecure Cookie: {name}",
                    description=f"Cookie '{name}' has: {', '.join(issues)}",
                    endpoint=endpoint,
                    evidence=cookie_header,
                    cwe_id="CWE-614",
                    remediation="Set Secure, HttpOnly, and SameSite attributes on all cookies.",
                    confirmed=True,
                ))
        return findings
