"""Information disclosure detection module."""

from __future__ import annotations

import re
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

# Patterns indicating information disclosure
DISCLOSURE_PATTERNS = [
    {
        "name": "Stack Trace",
        "patterns": [
            r"Traceback \(most recent call last\)",
            r"at [\w.]+\([\w.]+:\d+\)",
            r"Exception in thread",
            r"System\.Web\.HttpException",
            r"PHP (?:Fatal|Warning|Notice) error",
        ],
        "severity": Severity.MEDIUM,
        "cwe": "CWE-209",
    },
    {
        "name": "Database Error",
        "patterns": [
            r"SQLSTATE\[",
            r"mysql_fetch",
            r"pg_query",
            r"ORA-\d{5}",
        ],
        "severity": Severity.MEDIUM,
        "cwe": "CWE-209",
    },
    {
        "name": "Debug Information",
        "patterns": [
            r"DEBUG\s*=\s*True",
            r"DJANGO_SETTINGS_MODULE",
            r"phpinfo\(\)",
            r"Werkzeug Debugger",
            r"Laravel.*APP_DEBUG",
        ],
        "severity": Severity.HIGH,
        "cwe": "CWE-215",
    },
    {
        "name": "Internal Path Disclosure",
        "patterns": [
            r"/home/[\w/]+\.py",
            r"/var/www/[\w/]+",
            r"C:\\(?:Users|inetpub|Program Files)\\[\w\\]+",
            r"/usr/local/[\w/]+",
        ],
        "severity": Severity.LOW,
        "cwe": "CWE-200",
    },
    {
        "name": "API Key / Secret",
        "patterns": [
            r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[\w-]{20,}",
            r"(?:secret|token|password)\s*[:=]\s*['\"]?[\w-]{8,}",
            r"AKIA[0-9A-Z]{16}",  # AWS Access Key
            r"sk-[a-zA-Z0-9]{20,}",  # Various API keys
        ],
        "severity": Severity.CRITICAL,
        "cwe": "CWE-312",
    },
    {
        "name": "Email Address",
        "patterns": [
            r"[\w.+-]+@[\w-]+\.[\w.-]+",
        ],
        "severity": Severity.INFO,
        "cwe": "CWE-200",
    },
    {
        "name": "Private IP Address",
        "patterns": [
            r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}",
        ],
        "severity": Severity.LOW,
        "cwe": "CWE-200",
    },
]

# Common debug/info endpoints to probe
DEBUG_ENDPOINTS = [
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/debug",
    "/debug/pprof",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/elmah.axd",
    "/trace.axd",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/api/swagger.json",
    "/swagger-ui.html",
    "/graphql",
    "/.well-known/openid-configuration",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/wp-config.php.bak",
    "/.DS_Store",
    "/backup.sql",
    "/dump.sql",
]


class InfoDisclosureScanner(BaseScanner):
    name = "info_disclosure"
    description = "Information disclosure, debug endpoints, and exposed secrets"

    @property
    def vuln_types(self) -> list:
        return [VulnType.INFO_DISCLOSURE, VulnType.DEBUG_ENDPOINT]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []

        # Pull work from queue — each item is an endpoint to check
        work_items = self.claim_work(limit=50)

        for item in work_items:
            endpoint = Endpoint(url=item["url"], method=item["method"])
            page_findings = await self._check_page(endpoint)
            findings.extend(page_findings)
            self.complete_work(item["queue_id"])

        # Probe for debug/info endpoints using base URL from first item
        if work_items:
            from urllib.parse import urlparse
            parsed = urlparse(work_items[0]["url"])
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            for debug_path in DEBUG_ENDPOINTS:
                finding = await self._probe_endpoint(base_url, debug_path)
                if finding:
                    findings.append(finding)

        return findings

    async def _check_page(self, endpoint: Endpoint) -> list[Finding]:
        findings: list[Finding] = []

        try:
            response = await self.http.get(endpoint.url)
        except Exception:
            return findings

        body = response.text

        for disclosure in DISCLOSURE_PATTERNS:
            for pattern in disclosure["patterns"]:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    findings.append(Finding(
                        id=f"INFO-{uuid.uuid4().hex[:8]}",
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        severity=disclosure["severity"],
                        title=f"{disclosure['name']} at {endpoint.url}",
                        description=f"{disclosure['name']} detected in page response.",
                        endpoint=endpoint,
                        evidence=match.group(0)[:200],
                        cwe_id=disclosure["cwe"],
                        remediation="Remove sensitive information from production responses.",
                        confirmed=True,
                    ))
                    break  # One finding per category per page

        return findings

    async def _probe_endpoint(self, base_url: str, path: str) -> Finding | None:
        url = f"{base_url}{path}"

        try:
            response = await self.http.get(url)
        except Exception:
            return None

        if response.status_code == 200:
            # Check if it's a real response (not a custom 404)
            content_type = response.headers.get("content-type", "")
            body = response.text

            if len(body) < 10:
                return None

            # .git/HEAD check
            if path == "/.git/HEAD" and body.startswith("ref:"):
                return Finding(
                    id=f"DEBUG-{uuid.uuid4().hex[:8]}",
                    vuln_type=VulnType.DEBUG_ENDPOINT,
                    severity=Severity.CRITICAL,
                    title=f"Git Repository Exposed at {url}",
                    description="The .git directory is publicly accessible, exposing source code.",
                    endpoint=Endpoint(url=url),
                    evidence=body[:200],
                    cwe_id="CWE-538",
                    remediation="Block access to .git directories in web server configuration.",
                    confirmed=True,
                )

            # .env check
            if path == "/.env" and "=" in body and any(
                k in body.upper() for k in ["DATABASE", "SECRET", "KEY", "PASSWORD", "TOKEN"]
            ):
                return Finding(
                    id=f"DEBUG-{uuid.uuid4().hex[:8]}",
                    vuln_type=VulnType.DEBUG_ENDPOINT,
                    severity=Severity.CRITICAL,
                    title=f"Environment File Exposed at {url}",
                    description="The .env file is publicly accessible, exposing credentials.",
                    endpoint=Endpoint(url=url),
                    evidence="[REDACTED — credentials detected]",
                    cwe_id="CWE-312",
                    remediation="Block access to .env files. Move secrets to a secrets manager.",
                    confirmed=True,
                )

            # Generic debug endpoint
            if path in ("/debug", "/actuator", "/actuator/env", "/phpinfo.php"):
                return Finding(
                    id=f"DEBUG-{uuid.uuid4().hex[:8]}",
                    vuln_type=VulnType.DEBUG_ENDPOINT,
                    severity=Severity.HIGH,
                    title=f"Debug Endpoint Exposed: {path}",
                    description=f"Debug endpoint {path} is accessible in production.",
                    endpoint=Endpoint(url=url),
                    evidence=body[:300],
                    cwe_id="CWE-215",
                    remediation="Disable debug endpoints in production.",
                    confirmed=True,
                )

        return None
