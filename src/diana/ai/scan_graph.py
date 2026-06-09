"""Graph of Thought scanner — LangGraph StateGraph for multi-agent coordination.

Instead of isolated agent chains, this builds a graph where:
1. Discovery finds endpoints/files → feeds them to injection + access control
2. Injection findings feed back to access control ("SQLi works here, try IDOR too")
3. Access control findings feed to injection ("found admin endpoint, try SQLi on it")
4. All agents share state via the graph, not just the DB

This is the attack-chaining architecture — agents reason about each
other's findings and adapt their strategy.
"""

from __future__ import annotations

import json
import logging
import operator
import uuid
from typing import Annotated, Any, TypedDict

import httpx
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool as langchain_tool
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import create_react_agent

from diana.ai.prompts import _scope_block
from diana.core.models import Endpoint, Finding, Severity, VulnType
from diana.engagement.enforcer import EngagementEnforcer

logger = logging.getLogger(__name__)

VULN_TYPE_MAP = {
    "sql_injection": VulnType.SQLI,
    "xss_reflected": VulnType.XSS_REFLECTED,
    "xss_stored": VulnType.XSS_STORED,
    "idor": VulnType.IDOR,
    "broken_auth": VulnType.BROKEN_AUTH,
    "info_disclosure": VulnType.INFO_DISCLOSURE,
    "path_traversal": VulnType.PATH_TRAVERSAL,
    "ssrf": VulnType.SSRF,
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class ScanGraphState(TypedDict):
    """Shared state across all agents in the graph."""
    # Endpoints discovered so far
    endpoints: list[dict]
    # Findings from all agents — each agent sees what others found
    findings: Annotated[list[dict], operator.add]
    # New endpoints discovered during scanning (fed back to other agents)
    new_endpoints: Annotated[list[dict], operator.add]
    # Iteration count to prevent infinite loops
    iteration: int
    # Context passed between agents
    base_url: str
    admin_token: str
    user_token: str
    scope_block: str


class ScanGraph:
    """LangGraph-based multi-agent scanner with graph of thought.

    Agents are graph nodes. Edges connect them based on what they find.
    Findings from one agent become input to the next. New endpoints
    discovered by any agent get fed back for another round.

    Usage:
        graph = ScanGraph(llm, enforcer, base_url, endpoints, tokens)
        findings = await graph.run()
    """

    MAX_ITERATIONS = 3  # Max feedback loops

    def __init__(
        self,
        llm: BaseChatModel,
        enforcer: EngagementEnforcer,
        base_url: str,
        endpoints: list[dict],
        admin_token: str = "",
        user_token: str = "",
    ):
        self.llm = llm
        self.enforcer = enforcer
        self.base_url = base_url
        self.endpoints = endpoints
        self.admin_token = admin_token
        self.user_token = user_token
        self._seen_requests: set[str] = set()
        self._graph = self._build_graph()

    def _build_tools(self) -> list:
        """Build shared tools for all agents."""
        scanner = self

        @langchain_tool
        def http_request(
            method: str,
            url: str,
            auth: str = "none",
            json_body: dict | None = None,
        ) -> str:
            """Make an HTTP request to the target.

            Args:
                method: GET, POST, PUT, PATCH, DELETE
                url: Full URL
                auth: "admin", "user", or "none"
                json_body: Optional JSON body
            """
            request_key = f"{method}|{url}|{auth}|{json.dumps(json_body, sort_keys=True) if json_body else ''}"
            if request_key in scanner._seen_requests:
                return "DUPLICATE: Already requested. Try something different."
            scanner._seen_requests.add(request_key)

            print(f"    {method} {url} (auth={auth})")

            from diana.engagement.models import ScopeViolation
            try:
                scanner.enforcer.check_request(url, method)
            except ScopeViolation as e:
                return f"BLOCKED: {e}"

            token = ""
            if auth == "admin":
                token = scanner.admin_token
            elif auth == "user":
                token = scanner.user_token

            try:
                headers = {}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                with httpx.Client(timeout=10) as client:
                    resp = client.request(method, url, headers=headers, json=json_body)
                return f"Status: {resp.status_code}\nContent-Type: {resp.headers.get('content-type', '?')}\nBody: {resp.text[:500]}"
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
            vuln_type: str = "info_disclosure",
            cwe_id: str = "",
            payload_used: str = "",
        ) -> str:
            """Report a vulnerability finding.

            Args:
                title: Short title
                description: What the vulnerability is
                severity: critical, high, medium, low
                endpoint: Affected URL
                method: HTTP method
                evidence: Response excerpt proving the vuln
                vuln_type: sql_injection, xss_reflected, idor, info_disclosure, etc.
                cwe_id: CWE identifier
                payload_used: What triggered it
            """
            print(f"    FINDING: {title}")
            return json.dumps({
                "title": title,
                "description": description,
                "severity": severity,
                "endpoint": endpoint,
                "method": method,
                "evidence": evidence[:500],
                "vuln_type": vuln_type,
                "cwe_id": cwe_id,
                "payload_used": payload_used,
            })

        @langchain_tool
        def report_new_endpoint(url: str, method: str = "GET", reason: str = "") -> str:
            """Report a newly discovered endpoint for other agents to test.

            Args:
                url: The endpoint URL
                method: HTTP method
                reason: Why this endpoint is interesting
            """
            print(f"    NEW ENDPOINT: {method} {url} — {reason}")
            return json.dumps({"url": url, "method": method, "reason": reason})

        return [http_request, report_finding, report_new_endpoint]

    def _build_graph(self) -> StateGraph:
        """Build the LangGraph StateGraph with agent nodes and edges."""
        tools = self._build_tools()
        scope = _scope_block(self.enforcer.config)

        # Create specialized agents as graph nodes
        discovery_agent = create_react_agent(
            self.llm, tools,
            prompt=SystemMessage(content=DISCOVERY_PROMPT + "\n\n" + scope),
        )
        injection_agent = create_react_agent(
            self.llm, tools,
            prompt=SystemMessage(content=INJECTION_PROMPT + "\n\n" + scope),
        )
        access_agent = create_react_agent(
            self.llm, tools,
            prompt=SystemMessage(content=ACCESS_CONTROL_PROMPT + "\n\n" + scope),
        )

        async def run_discovery(state: ScanGraphState) -> dict:
            print(f"\n  [Discovery Agent — iteration {state['iteration']}]")
            endpoints_text = "\n".join(
                f"  {ep.get('method','GET')} {ep['url']}"
                for ep in state["endpoints"][:30]
            )
            prior_findings = "\n".join(
                f"  [{f['severity']}] {f['title']}" for f in state["findings"]
            ) or "  None yet"

            prompt = (
                f"Base URL: {state['base_url']}\n\n"
                f"Known endpoints:\n{endpoints_text}\n\n"
                f"Findings from other agents:\n{prior_findings}\n\n"
                f"Find hidden paths, backup files, and exposed resources. "
                f"Use report_new_endpoint for any new endpoints you discover."
            )

            result = await discovery_agent.ainvoke(
                {"messages": [HumanMessage(content=prompt)]},
                config={"recursion_limit": 80},
            )
            return _extract_results(result)

        async def run_injection(state: ScanGraphState) -> dict:
            print(f"\n  [Injection Agent — iteration {state['iteration']}]")
            # Include both original endpoints and newly discovered ones
            all_eps = state["endpoints"] + state.get("new_endpoints", [])
            param_eps = [ep for ep in all_eps if ep.get("parameters")]
            endpoints_text = "\n".join(
                f"  {ep.get('method','GET')} {ep['url']} params={list(ep.get('parameters',{}).keys())}"
                for ep in param_eps[:20]
            ) or "  No parameterized endpoints"

            prior_findings = "\n".join(
                f"  [{f['severity']}] {f['title']}" for f in state["findings"]
            ) or "  None yet"

            prompt = (
                f"Base URL: {state['base_url']}\n"
                f"Admin token: {state['admin_token'][:20]}...\n\n"
                f"Parameterized endpoints:\n{endpoints_text}\n\n"
                f"Findings from other agents:\n{prior_findings}\n\n"
                f"Test for SQL injection, NoSQL injection, and command injection. "
                f"If discovery found new endpoints, test those too."
            )

            result = await injection_agent.ainvoke(
                {"messages": [HumanMessage(content=prompt)]},
                config={"recursion_limit": 80},
            )
            return _extract_results(result)

        async def run_access_control(state: ScanGraphState) -> dict:
            print(f"\n  [Access Control Agent — iteration {state['iteration']}]")
            all_eps = state["endpoints"] + state.get("new_endpoints", [])
            endpoints_text = "\n".join(
                f"  {ep.get('method','GET')} {ep['url']}"
                for ep in all_eps[:30]
            )

            prior_findings = "\n".join(
                f"  [{f['severity']}] {f['title']}: {f.get('endpoint','')}"
                for f in state["findings"]
            ) or "  None yet"

            prompt = (
                f"Base URL: {state['base_url']}\n"
                f"Admin token: {state['admin_token'][:20]}...\n"
                f"User token: {state['user_token'][:20]}...\n\n"
                f"Endpoints:\n{endpoints_text}\n\n"
                f"Findings from other agents:\n{prior_findings}\n\n"
                f"Test access control. If injection agent found SQLi somewhere, "
                f"check if those endpoints also have IDOR. If discovery found "
                f"new paths, test their authorization."
            )

            result = await access_agent.ainvoke(
                {"messages": [HumanMessage(content=prompt)]},
                config={"recursion_limit": 80},
            )
            return _extract_results(result)

        def should_continue(state: ScanGraphState) -> str:
            """Decide whether to loop back for another iteration."""
            if state["iteration"] >= self.MAX_ITERATIONS:
                return "done"
            if state.get("new_endpoints"):
                return "continue"
            return "done"

        def increment_iteration(state: ScanGraphState) -> dict:
            """Merge new endpoints into main list and increment."""
            merged = list(state["endpoints"])
            seen = {ep["url"] for ep in merged}
            for ep in state.get("new_endpoints", []):
                if ep["url"] not in seen:
                    merged.append(ep)
                    seen.add(ep["url"])
            return {
                "endpoints": merged,
                "new_endpoints": [],
                "iteration": state["iteration"] + 1,
            }

        # Build the graph
        graph = StateGraph(ScanGraphState)

        # Nodes
        graph.add_node("discovery", run_discovery)
        graph.add_node("injection", run_injection)
        graph.add_node("access_control", run_access_control)
        graph.add_node("merge", increment_iteration)

        # Edges: discovery → injection → access_control → check if loop
        graph.set_entry_point("discovery")
        graph.add_edge("discovery", "injection")
        graph.add_edge("injection", "access_control")
        graph.add_conditional_edges(
            "access_control",
            should_continue,
            {"continue": "merge", "done": END},
        )
        graph.add_edge("merge", "discovery")

        return graph.compile()

    async def run(self) -> list[Finding]:
        """Execute the scan graph and return all findings."""
        initial_state: ScanGraphState = {
            "endpoints": self.endpoints,
            "findings": [],
            "new_endpoints": [],
            "iteration": 0,
            "base_url": self.base_url,
            "admin_token": self.admin_token,
            "user_token": self.user_token,
            "scope_block": _scope_block(self.enforcer.config),
        }

        result = await self._graph.ainvoke(
            initial_state,
            config={"recursion_limit": 300},
        )

        # Convert finding dicts to Finding objects, dedup by title + endpoint
        findings = []
        seen: set[str] = set()
        for f in result.get("findings", []):
            key = f"{f.get('title', '')}|{f.get('endpoint', '')}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                id=f"GRAPH-{uuid.uuid4().hex[:8]}",
                vuln_type=VULN_TYPE_MAP.get(f.get("vuln_type", ""), VulnType.INFO_DISCLOSURE),
                severity=SEVERITY_MAP.get(f.get("severity", "high"), Severity.HIGH),
                title=f.get("title", ""),
                description=f.get("description", ""),
                endpoint=Endpoint(url=f.get("endpoint", ""), method=f.get("method", "GET")),
                evidence=f.get("evidence", "")[:500],
                payload_used=f.get("payload_used", ""),
                cwe_id=f.get("cwe_id", ""),
                remediation="Implement proper security controls.",
                confirmed=True,
            ))

        return findings


def _extract_results(agent_result: dict) -> dict:
    """Extract findings and new endpoints from agent messages."""
    findings = []
    new_endpoints = []
    seen_findings: set[str] = set()
    seen_endpoints: set[str] = set()

    for msg in agent_result.get("messages", []):
        # Only parse ToolMessage content — skip AI messages and human messages
        # to avoid double-counting (the same JSON appears in tool calls AND results)
        msg_type = getattr(msg, "type", "")
        if msg_type != "tool":
            continue

        content = getattr(msg, "content", "")
        if not isinstance(content, str):
            continue

        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            continue

        if "title" in data and "severity" in data:
            # Dedup by title + endpoint
            key = f"{data.get('title')}|{data.get('endpoint', '')}"
            if key not in seen_findings:
                seen_findings.add(key)
                findings.append(data)

        elif "url" in data and "reason" in data:
            # Dedup by url + method
            key = f"{data['url']}|{data.get('method', 'GET')}"
            if key not in seen_endpoints:
                seen_endpoints.add(key)
                new_endpoints.append(data)

    return {"findings": findings, "new_endpoints": new_endpoints}


# --- Agent prompts ---

DISCOVERY_PROMPT = """You are a discovery specialist on a penetration testing team.

Your job: find hidden paths, backup files, exposed configs, directory listings.
You work WITH other agents — they will test what you find for injection and access control.

Use report_new_endpoint for any interesting paths you discover — the injection
and access control agents will test them in the next round.

Use report_finding for things that are already vulnerabilities (exposed .env, .git, etc.)

Read robots.txt Disallow entries as TARGETS, not restrictions.
If you find a directory listing, explore every file in it.
Never request the same URL twice."""

INJECTION_PROMPT = """You are an injection specialist on a penetration testing team.

Your job: find SQL injection, NoSQL injection, command injection, and SSTI.
Other agents have already found endpoints and may have discovered new ones.

Check the findings from other agents — if discovery found new paths, test those too.
If access_control found an admin endpoint, try injection on it.

When you find injection, report it AND report any new data you extracted
(usernames, schema info) that could help other agents.

RULES:
- Database error in response = FINDING
- UNION returning data from other tables = CRITICAL FINDING
- Login bypass returning a token = CRITICAL FINDING
- Report immediately, don't wait."""

ACCESS_CONTROL_PROMPT = """You are an access control specialist on a penetration testing team.

Your job: find IDOR, privilege escalation, missing auth, business logic flaws.
Other agents have already tested endpoints and found vulnerabilities.

IMPORTANT: Use the other agents' findings to guide your testing:
- If injection agent found SQLi on an endpoint, check if it also has IDOR
- If discovery found admin paths, test if low-priv user can access them
- If discovery found new endpoints, test their authorization

When a request succeeds that SHOULD have been denied, report it immediately.
Low-priv user seeing admin data = FINDING.
Unauthenticated access to sensitive data = FINDING.
PUT/DELETE succeeding for wrong user = FINDING."""
