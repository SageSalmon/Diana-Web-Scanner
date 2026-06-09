"""AI-driven XSS testing agent.

Gives the AI HTTP tools and lets it reason about XSS attacks:
- Reflected XSS via URL parameters and search fields
- Stored XSS via API POST bodies (user registration, feedback, reviews)
- Filter bypass (server-side and client-side)
- HTTP header injection (User-Agent, Referer)
- Context-aware payload crafting based on where input is reflected
"""

from __future__ import annotations

from diana.ai.bedrock import BedrockClient
from diana.ai.tool_agent import ToolUsingAgent
from diana.config import ScanConfig
from diana.core.http_client import ScopedHTTPClient
from diana.core.models import Finding
from diana.scanners.base import BaseScanner


XSS_SYSTEM = """You are an expert penetration tester specializing in Cross-Site Scripting (XSS).

You are testing a web application for XSS vulnerabilities using HTTP request tools.

Your approach:
1. For each endpoint with parameters, inject XSS payloads and check if they're reflected
2. Start with a canary string (e.g., "diana12345") to test reflection, then escalate to real payloads
3. Try payloads in URL parameters (reflected XSS), POST bodies (stored XSS), and HTTP headers
4. Standard payloads to try:
   - <script>alert('xss')</script>
   - <iframe src="javascript:alert(`xss`)">
   - <img src=x onerror=alert('xss')>
   - <svg onload=alert('xss')>
5. If basic payloads are filtered, try bypasses:
   - Case variation: <ScRiPt>
   - Encoding: &#x3C;script&#x3E;
   - Event handlers: " onfocus=alert('xss') autofocus="
   - Template syntax: {{constructor.constructor('alert(1)')()}}
6. For stored XSS, POST the payload to an endpoint (user registration email, feedback comment, review)
   then GET the endpoint to check if it's persisted and reflected
7. For header XSS, inject payloads in User-Agent, Referer, X-Forwarded-For headers

IMPORTANT RULES:
- When your payload appears UNENCODED in the response HTML, that's a FINDING. Report it.
- When <script>, <iframe>, or event handlers appear in the response body, that's a FINDING.
- If a canary string is reflected but XSS payload is stripped, note what was filtered and try bypass.
- Set vuln_type to: xss_reflected, xss_stored, or xss_dom
- For stored XSS, make sure to verify by reading back the stored data.
- Be efficient. Don't try 20 payloads on the same parameter — try 3-4, observe, adapt."""


XSS_PROMPT = """Test the following endpoints for Cross-Site Scripting vulnerabilities.

Application base URL: {base_url}
ADMIN token: {admin_token}
USER token: {user_token}

Endpoints with parameters (test for reflected XSS):
{param_endpoints}

POST endpoints (test for stored XSS via body fields):
{post_endpoints}

Technology stack: {tech_stack}
WAF detected: {waf}

For each endpoint:
1. First send a canary to see if input is reflected
2. If reflected, try XSS payloads
3. For POST endpoints, try XSS in common fields (email, comment, message, name)
4. Try header injection on the base URL
Report every vulnerability you find."""


class XSSAgent(BaseScanner):
    name = "xss_agent"
    description = "AI-driven XSS testing — reflected, stored, filter bypass, header injection"

    @property
    def vuln_types(self) -> list:
        from diana.core.models import VulnType
        return [VulnType.XSS_REFLECTED, VulnType.XSS_STORED, VulnType.XSS_DOM]

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

        param_eps = []
        post_eps = []
        seen = set()
        for item in work_items:
            method = item.get("method", "GET")
            key = f"{method} {item['url']}"
            if key in seen:
                continue
            seen.add(key)

            payload = item.get("payload", {}) or {}
            params = payload.get("parameters", {})
            if params:
                param_eps.append(f"  {method} {item['url']} params={list(params.keys())}")

            if method == "POST":
                post_eps.append(f"  POST {item['url']}")

        if not param_eps and not post_eps:
            for item in work_items:
                self.complete_work(item["queue_id"])
            return []

        tech = "unknown"
        waf = "none detected"
        first_payload = work_items[0].get("payload", {}) or {}
        if first_payload.get("tech_stack"):
            tech = first_payload["tech_stack"]
        if first_payload.get("waf"):
            waf = first_payload["waf"]

        prompt = XSS_PROMPT.format(
            base_url=base,
            admin_token=admin_token[:20] + "..." if admin_token else "none",
            user_token="none",
            param_endpoints="\n".join(param_eps[:30]) or "none found",
            post_endpoints="\n".join(post_eps[:20]) or "none found",
            tech_stack=tech,
            waf=waf,
        )

        # Include findings from other agents
        if self.scan_state and self.scan_id:
            other_findings = self.scan_state.get_findings_summary(self.scan_id)
            if other_findings:
                prompt += f"\n\nFindings from other agents:\n{other_findings}"

        agent = ToolUsingAgent(
            llm=self.ai.llm,
            enforcer=self.http.enforcer,
            admin_token=admin_token,
            max_turns=25,
            scan_state=self.scan_state,
            scan_id=self.scan_id,
            module_name="xss_agent",
        )

        results = await agent.run(XSS_SYSTEM, prompt)

        for item in work_items:
            self.complete_work(item["queue_id"])

        return results
