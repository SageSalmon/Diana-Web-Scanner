"""AI-driven SQL injection agent.

Gives the AI HTTP tools and lets it reason about injection attacks:
- Error-based, UNION-based, blind SQLi
- Login bypass for specific user accounts
- NoSQL injection ($gt, $ne, $where)
- Data extraction and schema enumeration
"""

from __future__ import annotations

from diana.ai.bedrock import BedrockClient
from diana.ai.tool_agent import ToolUsingAgent
from diana.config import ScanConfig
from diana.core.http_client import ScopedHTTPClient
from diana.core.models import Finding
from diana.scanners.base import BaseScanner


SQLI_SYSTEM = """You are an expert penetration tester specializing in injection attacks.

You are testing a web application for SQL injection, NoSQL injection, and other injection flaws.
You have HTTP request tools to probe endpoints.

Your approach:
1. For each endpoint with parameters, try injection payloads in each parameter
2. Start with simple error-triggering payloads (' " ;) and observe error messages
3. If errors reveal a database type, craft targeted payloads (UNION for SQLite/MySQL/PostgreSQL, $gt/$ne for MongoDB)
4. For login endpoints, try authentication bypass: ' OR 1=1--, admin'--, etc.
5. If you find UNION works, enumerate columns and extract data (users, passwords, schema)
6. For search/query endpoints, try both SQL and NoSQL payloads
7. Check for time-based blind injection with SLEEP/WAITFOR/pg_sleep

IMPORTANT RULES:
- When you get a database error message in the response, that's a FINDING. Report it.
- When a login bypass returns a token/session, that's a CRITICAL FINDING. Report it.
- When UNION SELECT returns data from other tables, that's a CRITICAL FINDING. Report it.
- When NoSQL operators ($gt, $ne) change the response, that's a FINDING. Report it.
- Set vuln_type to: sql_injection, sql_injection_blind, or command_injection
- Be efficient. Test, observe, report, move on."""


SQLI_PROMPT = """Test the following endpoints for injection vulnerabilities.

Application base URL: {base_url}
ADMIN token: {admin_token}
USER token: {user_token}

Endpoints with parameters (focus on these):
{param_endpoints}

Login/auth endpoints (try auth bypass):
{login_endpoints}

Technology stack: {tech_stack}

Test each parameterized endpoint for SQL injection, NoSQL injection, and command injection.
For login endpoints, try authentication bypass payloads.
Report every vulnerability you find."""


class SQLiAgent(BaseScanner):
    name = "sqli_agent"
    description = "AI-driven injection testing — SQLi, NoSQL, command injection"

    @property
    def vuln_types(self) -> list:
        from diana.core.models import VulnType
        return [VulnType.SQLI, VulnType.SQLI_BLIND, VulnType.COMMAND_INJECTION, VulnType.SSTI]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        if config.no_ai or not self.ai:
            return []

        work_items = self.claim_work(limit=30)
        if not work_items:
            return []

        admin_token = self.http._auth_headers.get("Authorization", "").replace("Bearer ", "")

        from urllib.parse import urlparse
        parsed = urlparse(work_items[0]["url"])
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Build endpoint descriptions from work items
        param_eps = []
        login_eps = []
        seen = set()
        for item in work_items:
            key = f"{item.get('method', 'GET')} {item['url']}"
            if key in seen:
                continue
            seen.add(key)
            payload = item.get("payload", {}) or {}
            params = payload.get("parameters", {})
            if params:
                param_eps.append(f"  {item.get('method', 'GET')} {item['url']} params={list(params.keys())}")
            if any(kw in item["url"].lower() for kw in ["login", "auth", "signin"]):
                login_eps.append(f"  {item.get('method', 'GET')} {item['url']}")

        if not param_eps and not login_eps:
            for item in work_items:
                self.complete_work(item["queue_id"])
            return []

        other_findings = ""
        if self.scan_state and self.scan_id:
            other_findings = self.scan_state.get_findings_summary(self.scan_id)

        tech = "unknown"
        first_payload = work_items[0].get("payload", {}) or {}
        if first_payload.get("tech_stack"):
            tech = first_payload["tech_stack"]

        prompt = SQLI_PROMPT.format(
            base_url=base,
            admin_token=admin_token[:20] + "..." if admin_token else "none",
            user_token="none",
            param_endpoints="\n".join(param_eps) or "none found",
            login_endpoints="\n".join(login_eps) or "none found",
            tech_stack=tech,
        )
        if other_findings:
            prompt += f"\n\nFindings from other agents:\n{other_findings}"

        agent = ToolUsingAgent(
            llm=self.ai.llm,
            enforcer=self.http.enforcer,
            admin_token=admin_token,
            max_turns=25,
            scan_state=self.scan_state,
            scan_id=self.scan_id,
            module_name="sqli_agent",
        )

        results = await agent.run(SQLI_SYSTEM, prompt)

        for item in work_items:
            self.complete_work(item["queue_id"])

        return results
