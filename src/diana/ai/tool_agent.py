"""LangChain-powered tool-using agent for AI-driven scanner modules.

Uses LangGraph's create_react_agent with LangChain tools. Each scanner
module defines its tools and prompt — this module provides the shared
agent execution loop with engagement scope enforcement.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import httpx
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool as langchain_tool, StructuredTool
from langgraph.prebuilt import create_react_agent

from diana.ai.prompts import _scope_block
from diana.core.models import Endpoint, Finding, Severity, VulnType
from diana.engagement.enforcer import EngagementEnforcer

logger = logging.getLogger(__name__)

VULN_TYPE_MAP = {
    "sql_injection": VulnType.SQLI,
    "sql_injection_blind": VulnType.SQLI_BLIND,
    "xss_reflected": VulnType.XSS_REFLECTED,
    "xss_stored": VulnType.XSS_STORED,
    "xss_dom": VulnType.XSS_DOM,
    "idor": VulnType.IDOR,
    "broken_auth": VulnType.BROKEN_AUTH,
    "ssrf": VulnType.SSRF,
    "path_traversal": VulnType.PATH_TRAVERSAL,
    "info_disclosure": VulnType.INFO_DISCLOSURE,
    "open_redirect": VulnType.OPEN_REDIRECT,
    "command_injection": VulnType.COMMAND_INJECTION,
    "ssti": VulnType.SSTI,
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class ToolUsingAgent:
    """LangChain-powered tool-using agent.

    Creates a LangGraph ReAct agent with HTTP request and finding
    reporting tools. Engagement scope is enforced on every HTTP call.
    """

    def __init__(
        self,
        llm: BaseChatModel,
        enforcer: EngagementEnforcer,
        admin_token: str = "",
        user_token: str = "",
        max_turns: int = 30,
        scan_state=None,
        scan_id: str = "",
        module_name: str = "",
    ):
        self.llm = llm
        self.enforcer = enforcer
        self.admin_token = admin_token
        self.user_token = user_token
        self.max_turns = max_turns
        self.scan_state = scan_state  # ScanState DB manager
        self.scan_id = scan_id
        self.module_name = module_name
        self._findings: list[Finding] = []
        self._seen_requests: set[str] = set()
        self._reported_keys: set[str] = set()

    async def run(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> list[Finding]:
        """Run the LangGraph ReAct agent and return discovered findings."""
        self._findings = []
        self._seen_requests = set()
        self._reported_keys = set()

        # Build tools with closure over self for state access
        tools = self._build_tools()

        # Inject engagement scope into system prompt (L1)
        system_with_scope = (
            system_prompt + "\n\n" + _scope_block(self.enforcer.config)
        )

        # Create LangGraph ReAct agent
        agent = create_react_agent(
            self.llm,
            tools,
            prompt=SystemMessage(content=system_with_scope),
        )

        # Run the agent
        try:
            result = await agent.ainvoke(
                {"messages": [HumanMessage(content=user_prompt)]},
                config={"recursion_limit": self.max_turns * 5},
            )
        except Exception as e:
            logger.warning("Agent execution failed: %s", e)

        return self._findings

    def _build_tools(self) -> list[StructuredTool]:
        """Build LangChain tools with access to agent state."""
        agent = self  # Capture in closure

        @langchain_tool
        def http_request(
            method: str,
            url: str,
            auth: str = "none",
            json_body: dict | None = None,
            headers: dict | None = None,
        ) -> str:
            """Make an HTTP request to the target application.

            Args:
                method: HTTP method (GET, POST, PUT, PATCH, DELETE)
                url: Full URL to request
                auth: Which auth token to use: "admin", "user", or "none"
                json_body: Optional JSON request body
                headers: Optional additional HTTP headers
            """
            import asyncio

            # Dedup
            request_key = f"{method}|{url}|{auth}|{json.dumps(json_body, sort_keys=True) if json_body else ''}"
            if request_key in agent._seen_requests:
                if agent.scan_state and agent.scan_id:
                    agent.scan_state.increment_module_metrics(
                        agent.scan_id, agent.module_name, cache_hits=1)
                return "DUPLICATE: You already made this exact request. Try something different."
            agent._seen_requests.add(request_key)

            print(f"  AI agent: {method} {url} (auth={auth})")

            # L2: Engagement scope check
            from diana.engagement.models import ScopeViolation
            try:
                agent.enforcer.check_request(url, method)
            except ScopeViolation as e:
                print(f"  AI agent: BLOCKED {url} — {e}")
                return f"BLOCKED by engagement scope: {e}"

            # Resolve auth
            token = ""
            if auth == "admin":
                token = agent.admin_token
            elif auth == "user":
                token = agent.user_token

            # Execute request (sync wrapper for tool compatibility)
            try:
                req_headers: dict[str, str] = {}
                if token:
                    req_headers["Authorization"] = f"Bearer {token}"
                if headers:
                    req_headers.update(headers)

                # Use synchronous httpx since LangChain tools are sync
                with httpx.Client(timeout=10) as client:
                    resp = client.request(
                        method, url, headers=req_headers, json=json_body,
                    )

                body_preview = resp.text[:500] if resp.text else "(empty)"
                if agent.scan_state and agent.scan_id:
                    agent.scan_state.increment_module_metrics(
                        agent.scan_id, agent.module_name,
                        http_requests=1,
                        http_request_bytes=len(resp.content) if resp.content else 0)
                return (
                    f"Status: {resp.status_code}\n"
                    f"Content-Type: {resp.headers.get('content-type', 'unknown')}\n"
                    f"Body: {body_preview}"
                )
            except Exception as e:
                return f"Error: {e}"

        @langchain_tool
        def report_finding(
            title: str,
            description: str,
            severity: str,
            endpoint: str,
            method: str,
            evidence: str = "",
            cwe_id: str = "CWE-284",
            vuln_type: str = "idor",
            remediation: str = "Implement proper security controls.",
            payload_used: str = "",
        ) -> str:
            """Report a confirmed vulnerability. Call this IMMEDIATELY when you observe a security flaw.

            Args:
                title: Short title for the finding
                description: Detailed description of the vulnerability
                severity: Severity level (critical, high, medium, low)
                endpoint: The affected endpoint URL
                method: HTTP method used
                evidence: Evidence of the vulnerability (response excerpt)
                cwe_id: CWE identifier (e.g., CWE-639 for IDOR)
                vuln_type: Type (sql_injection, xss_reflected, idor, info_disclosure, etc.)
                remediation: How to fix the vulnerability
                payload_used: The payload that triggered the vulnerability
            """
            # Collapse repeat reports of the same flaw — the model often calls
            # report_finding many times for one issue, flooding results and the DB.
            dedup_key = f"{title.strip().lower()}|{endpoint}|{method.upper()}"
            if dedup_key in agent._reported_keys:
                return "Duplicate finding ignored — already reported. Move on to a new test."
            agent._reported_keys.add(dedup_key)

            print(f"  AI agent: FINDING - {title}")

            finding = Finding(
                id=f"AI-{uuid.uuid4().hex[:8]}",
                vuln_type=VULN_TYPE_MAP.get(vuln_type, VulnType.IDOR),
                severity=SEVERITY_MAP.get(severity, Severity.HIGH),
                title=title,
                description=description,
                endpoint=Endpoint(url=endpoint, method=method),
                evidence=evidence[:500],
                payload_used=payload_used,
                cwe_id=cwe_id,
                remediation=remediation,
                confirmed=True,
            )
            agent._findings.append(finding)

            # Track finding in module metrics
            if agent.scan_state and agent.scan_id:
                agent.scan_state.increment_module_metrics(
                    agent.scan_id, agent.module_name, findings_reported=1)

            # Also write to shared DB so other agents can see it
            if agent.scan_state and agent.scan_id:
                agent.scan_state.store_finding(agent.scan_id, agent.module_name, {
                    "id": finding.id,
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "endpoint_url": endpoint,
                    "endpoint_method": method,
                    "evidence": evidence[:2000],
                    "payload_used": payload_used,
                    "cwe_id": cwe_id,
                    "remediation": remediation,
                })

            return "Finding recorded."

        return [http_request, report_finding]
