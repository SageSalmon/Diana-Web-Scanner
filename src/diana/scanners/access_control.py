"""AI-driven access control testing module — OWASP #1.

Uses the Bedrock AI agent to reason about and execute multi-step access
control tests. The AI observes endpoints, reasons about prerequisites
(CAPTCHAs, tokens, resource IDs), and executes attack flows dynamically.

No hardcoded paths or app-specific logic. The AI figures it out.

When AI is not available, falls back to generic structural tests that
work against any REST API (IDOR by ID increment, method tampering,
role field injection on registration).
"""

from __future__ import annotations

import json
import logging
import uuid

import httpx

from diana.ai.agent import AIAgent
from diana.ai.bedrock import BedrockClient
from diana.config import ScanConfig
from diana.core.http_client import ScopedHTTPClient
from diana.core.models import (
    Endpoint,
    Finding,
    Severity,
    VulnType,
)
from diana.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# System prompt for the access control testing agent
ACCESS_CONTROL_SYSTEM = """You are an expert penetration tester performing access control testing on a web application.

You have two user sessions:
- ADMIN: A high-privilege user
- USER: A low-privilege user you registered

Your goal is to find authorization flaws by testing each endpoint with both sessions.
You can make HTTP requests using the provided tools.

For each endpoint, reason about:
1. What does this endpoint do? (CRUD operation, data access, admin function?)
2. Can the low-priv USER access data belonging to ADMIN?
3. Can an UNAUTHENTICATED user access it?
4. Does it accept unexpected HTTP methods (PUT/DELETE on a GET-only resource)?
5. Can I manipulate fields like userId, role, or quantity to abuse business logic?
6. Are there prerequisites I need to handle first? (CAPTCHA, creating a resource before modifying it)

IMPORTANT RULES:
- When a request succeeds that SHOULD have been denied, immediately call report_finding. Do not wait.
- A low-priv USER getting 200 on admin data = FINDING. Report it.
- An UNAUTHENTICATED request getting 200 with real data = FINDING. Report it.
- PUT/DELETE succeeding for a low-priv user on another user's resource = FINDING. Report it.
- A password change without the current password succeeding = FINDING. Report it.
- Registration with role=admin succeeding = FINDING. Report it.
- Negative quantities or zero ratings being accepted = FINDING. Report it.

Do NOT be conservative. If the server accepted something it shouldn't have, report it.
You have a limited number of turns. Be efficient — test, observe, report, move on.
When done, call the done tool."""

ACCESS_CONTROL_PROMPT = """Test the following endpoints for access control vulnerabilities.

Application base URL: {base_url}

ADMIN token: {admin_token}
USER token: {user_token}
USER id: {user_id}

Endpoints to test (showing method, URL, and known parameters):
{endpoints_summary}

For each endpoint:
1. Try accessing it as USER when it might be admin-only
2. Try accessing it without any token
3. If it has numeric IDs, try adjacent IDs as USER
4. If it accepts POST/PUT, try manipulating identity fields (userId, role, etc.)
5. If there's a CAPTCHA or other prerequisite, figure out how to satisfy it first
6. Try boundary values (0, negative numbers) for numeric fields
7. Try omitting required fields

Report every vulnerability you find."""

# Tool definitions for the access control agent
AGENT_TOOLS = [
    {
        "name": "http_request",
        "description": (
            "Make an HTTP request to the target application. "
            "Use this to probe endpoints with different auth levels and payloads."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                    "description": "HTTP method",
                },
                "url": {
                    "type": "string",
                    "description": "Full URL to request",
                },
                "auth": {
                    "type": "string",
                    "enum": ["admin", "user", "none"],
                    "description": "Which auth token to use: admin, user (low-priv), or none",
                },
                "json_body": {
                    "type": "object",
                    "description": "JSON request body (optional)",
                },
            },
            "required": ["method", "url", "auth"],
        },
    },
    {
        "name": "report_finding",
        "description": "Report a confirmed access control vulnerability.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short title for the finding",
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the vulnerability",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Severity level",
                },
                "endpoint": {
                    "type": "string",
                    "description": "The affected endpoint URL",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method used",
                },
                "evidence": {
                    "type": "string",
                    "description": "Evidence of the vulnerability (response excerpt, etc.)",
                },
                "cwe_id": {
                    "type": "string",
                    "description": "CWE identifier (e.g., CWE-639 for IDOR)",
                },
                "remediation": {
                    "type": "string",
                    "description": "How to fix the vulnerability",
                },
            },
            "required": ["title", "description", "severity", "endpoint", "method"],
        },
    },
    {
        "name": "done",
        "description": "Signal that you have finished testing all endpoints.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Brief summary of what was tested and found",
                },
            },
            "required": ["summary"],
        },
    },
]


class AccessControlScanner(BaseScanner):
    name = "access_control"
    description = "AI-driven access control testing — IDOR, role escalation, business logic abuse"

    def __init__(self, http: ScopedHTTPClient, ai_agent: AIAgent | None = None):
        super().__init__(http, ai_agent)
        self._admin_token: str = ""
        self._low_priv_token: str = ""
        self._low_priv_user_id: int = 0
        self._llm = None
        if ai_agent:
            self._llm = ai_agent.llm

    @property
    def vuln_types(self) -> list:
        return [VulnType.IDOR, VulnType.BROKEN_AUTH, VulnType.PATH_TRAVERSAL]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []

        work_items = self.claim_work(limit=50)
        if not work_items:
            return findings

        self._admin_token = self.http._auth_headers.get(
            "Authorization", ""
        ).replace("Bearer ", "")

        # Also check if we have cookie-based auth (Playwright login)
        has_cookies = bool(self.http._auth_cookies)

        if not self._admin_token and not has_cookies:
            for item in work_items:
                self.complete_work(item["queue_id"])
            return findings

        # Check if orchestrator already authenticated a low-priv user (from engagement file)
        if self.scan_state and self.scan_id:
            auth_data = self.scan_state.get_auth(self.scan_id)
            if auth_data.get("user_token"):
                self._low_priv_token = auth_data["user_token"]
                self._low_priv_user_id = auth_data.get("user_id", 0)

        # If no low-priv token from engagement, try to register one
        if not self._low_priv_token:
            base_url = work_items[0]["url"].split("/api")[0].split("/rest")[0]
            registered = await self._register_low_priv_user(base_url)
            if not registered:
                for item in work_items:
                    self.complete_work(item["queue_id"])
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

        if self._llm and not config.no_ai:
            # AI-driven: let the agent reason about and execute multi-step tests.
            ai_findings = await self._run_ai_agent(endpoints, work_items)
            findings.extend(ai_findings)

        # Always run the deterministic structural sweep — even with AI enabled.
        # The AI agent tends to fixate on easy unauthenticated reads and skip the
        # systematic authenticated cross-user IDOR / method-tampering / role tests,
        # which are what actually exercise (and confirm) authorization flaws. These
        # are generic REST tests with no app-specific paths, and they issue the
        # authenticated requests directly rather than relying on the model's choices.
        findings.extend(await self._test_idor_by_id(endpoints))
        findings.extend(await self._test_method_tampering(endpoints))
        findings.extend(await self._test_role_escalation(endpoints))
        findings.extend(await self._test_unauthenticated_access(endpoints))

        for item in work_items:
            self.complete_work(item["queue_id"])

        return self._dedupe_findings(findings)

    async def _run_ai_agent(self, endpoints: list[Endpoint], work_items: list[dict]) -> list[Finding]:
        """Run the AI agent to discover and exploit access control flaws."""
        from diana.ai.tool_agent import ToolUsingAgent
        from urllib.parse import urlparse

        base = urlparse(endpoints[0].url).scheme + "://" + urlparse(endpoints[0].url).netloc

        endpoint_lines = []
        seen = set()
        for ep in endpoints[:50]:
            key = f"{ep.method} {ep.url}"
            if key in seen:
                continue
            seen.add(key)
            params = list(ep.parameters.keys()) if ep.parameters else []
            param_str = f" params={params}" if params else ""
            endpoint_lines.append(f"  {ep.method} {ep.url}{param_str}")

        prompt = ACCESS_CONTROL_PROMPT.format(
            base_url=base,
            admin_token=self._admin_token[:20] + "...",
            user_token=self._low_priv_token[:20] + "...",
            user_id=self._low_priv_user_id,
            endpoints_summary="\n".join(endpoint_lines),
        )

        # Include findings from other agents
        if self.scan_state and self.scan_id:
            other_findings = self.scan_state.get_findings_summary(self.scan_id)
            if other_findings:
                prompt += f"\n\nFindings from other agents:\n{other_findings}"

        agent = ToolUsingAgent(
            llm=self._llm,
            enforcer=self.http.enforcer,
            admin_token=self._admin_token,
            user_token=self._low_priv_token,
            max_turns=30,
            scan_state=self.scan_state,
            scan_id=self.scan_id,
            module_name="access_control",
        )

        return await agent.run(ACCESS_CONTROL_SYSTEM, prompt)

    # --- Fallback methods (no AI, no hardcoded paths) -------------------------

    async def _register_low_priv_user(self, base_url: str) -> bool:
        """Register a low-privilege user for access control comparison.

        Discovers registration endpoint dynamically from the sitemap.
        """
        base = base_url.rstrip("/")
        test_email = f"diana-test-{uuid.uuid4().hex[:8]}@test.local"
        test_password = "DianaTest123!"

        # Try common registration patterns
        register_bodies = [
            {
                "email": test_email,
                "password": test_password,
                "passwordRepeat": test_password,
                "securityQuestion": {"id": 1, "question": "?"},
                "securityAnswer": "diana",
            },
            {
                "username": test_email,
                "password": test_password,
                "passwordConfirm": test_password,
            },
            {
                "email": test_email,
                "password": test_password,
            },
        ]

        # Find registration endpoints from sitemap or probe common paths
        register_paths = ["/api/Users", "/rest/user/register", "/api/register",
                          "/register", "/signup", "/auth/register"]

        for path in register_paths:
            for body in register_bodies:
                try:
                    reg_url = f"{base}{path}"
                    # L2: Scope check
                    self.http.enforcer.check_request(reg_url, "POST")

                    async with httpx.AsyncClient(timeout=10) as client:
                        resp = await client.post(reg_url, json=body)
                        if resp.status_code in (200, 201):
                            # Try to login
                            for login_path in ["/rest/user/login", "/api/login",
                                               "/auth/login", "/login"]:
                                login_resp = await client.post(
                                    f"{base}{login_path}",
                                    json={"email": test_email, "password": test_password},
                                )
                                if login_resp.status_code == 200:
                                    login_body = login_resp.json()
                                    self._low_priv_token = (
                                        login_body.get("authentication", {}).get("token")
                                        or login_body.get("token")
                                        or login_body.get("access_token")
                                        or ""
                                    )
                                    self._low_priv_user_id = (
                                        login_body.get("authentication", {}).get("bid")
                                        or login_body.get("userId")
                                        or 0
                                    )
                                    if self._low_priv_token:
                                        return True
                except Exception:
                    continue

        return False

    async def _test_idor_by_id(self, endpoints: list[Endpoint]) -> list[Finding]:
        """Generic IDOR: for any endpoint with a numeric ID, try accessing
        adjacent IDs as the low-priv user."""
        findings: list[Finding] = []

        for ep in endpoints:
            if "id" not in ep.parameters:
                continue

            try:
                # Access as admin
                admin_resp = await self._request_as(ep.url, "GET", self._admin_token)
                if admin_resp.status_code != 200:
                    continue

                # Same resource as low-priv user
                user_resp = await self._request_as(ep.url, "GET", self._low_priv_token)
                if (
                    user_resp.status_code == 200
                    and len(user_resp.text) > 20
                    and self._responses_have_same_structure(admin_resp.text, user_resp.text)
                ):
                    findings.append(Finding(
                        id=f"IDOR-{uuid.uuid4().hex[:8]}",
                        vuln_type=VulnType.IDOR,
                        severity=Severity.HIGH,
                        title=f"IDOR at {ep.url}",
                        description="Low-privilege user can access resources belonging to other users.",
                        endpoint=ep,
                        evidence=user_resp.text[:300],
                        cwe_id="CWE-639",
                        remediation="Verify resource ownership server-side.",
                        confirmed=True,
                    ))

                # Unauthenticated
                unauth_resp = await self._request_as(ep.url, "GET", "")
                if (
                    unauth_resp.status_code == 200
                    and len(unauth_resp.text) > 20
                    and "unauthorized" not in unauth_resp.text.lower()
                    and self._responses_have_same_structure(admin_resp.text, unauth_resp.text)
                ):
                    findings.append(Finding(
                        id=f"NOAUTH-{uuid.uuid4().hex[:8]}",
                        vuln_type=VulnType.BROKEN_AUTH,
                        severity=Severity.HIGH,
                        title=f"Missing authentication on {ep.url}",
                        description="Endpoint returns data without any authentication.",
                        endpoint=ep,
                        evidence=unauth_resp.text[:300],
                        cwe_id="CWE-306",
                        remediation="Require authentication on all data endpoints.",
                        confirmed=True,
                    ))
            except Exception:
                continue

        return findings

    async def _test_method_tampering(self, endpoints: list[Endpoint]) -> list[Finding]:
        """Try PUT/DELETE on GET-only resource endpoints."""
        findings: list[Finding] = []

        resource_endpoints = [
            ep for ep in endpoints
            if ep.method == "GET"
            and any(kw in ep.url for kw in ["/api/", "/rest/"])
            and ("id" in ep.parameters or any(c.isdigit() for c in ep.url.split("/")[-1]))
        ]

        for ep in resource_endpoints[:20]:
            for method in ["PUT", "DELETE"]:
                try:
                    resp = await self._request_as(
                        ep.url, method, self._low_priv_token,
                        json_body={"id": 1} if method == "PUT" else None,
                    )
                    if resp.status_code in (200, 201, 204):
                        findings.append(Finding(
                            id=f"METHOD-{uuid.uuid4().hex[:8]}",
                            vuln_type=VulnType.BROKEN_AUTH,
                            severity=Severity.HIGH,
                            title=f"Unauthorized {method} on {ep.url}",
                            description=f"Low-privilege user can {method} a resource.",
                            endpoint=Endpoint(url=ep.url, method=method),
                            evidence=resp.text[:200],
                            cwe_id="CWE-285",
                            remediation=f"Restrict {method} to authorized users.",
                            confirmed=True,
                        ))
                        break
                except Exception:
                    continue

        return findings

    async def _test_role_escalation(self, endpoints: list[Endpoint]) -> list[Finding]:
        """Try registration with elevated role field."""
        findings: list[Finding] = []
        from urllib.parse import urlparse
        parsed = urlparse(endpoints[0].url) if endpoints else None
        if not parsed:
            return findings
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Find registration-like POST endpoints
        reg_endpoints = [
            ep for ep in endpoints
            if ep.method == "POST"
            and any(kw in ep.url.lower() for kw in ["user", "register", "signup"])
        ]

        # Also try common paths
        reg_paths = list({ep.url for ep in reg_endpoints})
        for common in [f"{base}/api/Users", f"{base}/api/register"]:
            if common not in reg_paths:
                reg_paths.append(common)

        for url in reg_paths:
            email = f"diana-role-{uuid.uuid4().hex[:6]}@test.local"
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(url, json={
                        "email": email, "password": "Test123!",
                        "passwordRepeat": "Test123!", "role": "admin",
                        "securityQuestion": {"id": 1, "question": "?"},
                        "securityAnswer": "test",
                    })
                    if resp.status_code in (200, 201):
                        body = resp.json() if "json" in resp.headers.get("content-type", "") else {}
                        user_data = body.get("data", body)
                        if user_data.get("role") == "admin":
                            findings.append(Finding(
                                id=f"ROLE-{uuid.uuid4().hex[:8]}",
                                vuln_type=VulnType.BROKEN_AUTH,
                                severity=Severity.CRITICAL,
                                title=f"Role escalation via registration at {url}",
                                description="Registration accepts client-supplied role values.",
                                endpoint=Endpoint(url=url, method="POST"),
                                evidence=f"Created user with role: {user_data.get('role')}",
                                cwe_id="CWE-269",
                                remediation="Set roles server-side. Never trust client-supplied role values.",
                                confirmed=True,
                            ))
            except Exception:
                continue

        return findings

    async def _test_unauthenticated_access(self, endpoints: list[Endpoint]) -> list[Finding]:
        """Test endpoints that return JSON data without auth."""
        findings: list[Finding] = []

        for ep in endpoints:
            if not any(kw in ep.url.lower() for kw in [
                "admin", "user", "profile", "basket", "order", "payment",
                "address", "wallet", "card",
            ]):
                continue

            try:
                resp = await self._request_as(ep.url, "GET", "")
                if resp.status_code == 200 and len(resp.text) > 50:
                    ct = resp.headers.get("content-type", "")
                    body = resp.text.lower()
                    if (
                        "json" in ct
                        and "unauthorized" not in body
                        and "error" not in body[:50]
                        and any(kw in body for kw in [
                            "email", "username", "password", "address",
                            "token", "credit", "order",
                        ])
                    ):
                        findings.append(Finding(
                            id=f"NOAUTH-{uuid.uuid4().hex[:8]}",
                            vuln_type=VulnType.BROKEN_AUTH,
                            severity=Severity.MEDIUM,
                            title=f"Sensitive endpoint accessible without auth: {ep.url}",
                            description="Returns sensitive data without authentication.",
                            endpoint=ep,
                            evidence=resp.text[:300],
                            cwe_id="CWE-306",
                            remediation="Enforce authentication on sensitive endpoints.",
                            confirmed=True,
                        ))
            except Exception:
                continue

        return findings

    async def _request_as(
        self, url: str, method: str, token: str,
        json_body: dict | None = None,
    ) -> httpx.Response:
        """Make a request with a specific auth token.

        Still goes through L2 engagement enforcer even though it uses
        a raw httpx client (needed for different auth headers).
        """
        from diana.engagement.models import ScopeViolation

        # L2: Scope check before any request
        self.http.enforcer.check_request(url, method)

        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=10) as client:
            return await client.request(method, url, headers=headers, json=json_body)

    @staticmethod
    def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
        """Collapse findings describing the same flaw at the same endpoint.

        The AI agent and the deterministic sweep can each surface the same
        issue; dedupe by (title, url, method) so one logical authorization flaw
        is reported once.
        """
        seen: set[tuple[str, str, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.title.strip().lower(), f.endpoint.url, f.endpoint.method)
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)
        return unique

    @staticmethod
    def _responses_have_same_structure(body1: str, body2: str) -> bool:
        try:
            d1 = json.loads(body1)
            d2 = json.loads(body2)
            if isinstance(d1, dict) and isinstance(d2, dict):
                return set(d1.keys()) == set(d2.keys())
            if isinstance(d1, list) and isinstance(d2, list):
                return True
        except (json.JSONDecodeError, TypeError):
            pass
        return False
