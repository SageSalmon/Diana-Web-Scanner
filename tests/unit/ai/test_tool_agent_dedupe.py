"""Tests for ToolUsingAgent.report_finding de-duplication.

The model frequently calls report_finding many times for one issue, flooding
results and the DB (observed ~25x for a single endpoint). report_finding now
collapses repeats by (title, endpoint, method) and tells the model to move on.
"""

from types import SimpleNamespace

from diana.ai.tool_agent import ToolUsingAgent


def _agent() -> ToolUsingAgent:
    # llm/enforcer are unused by report_finding; scan_state stays None so no DB.
    return ToolUsingAgent(llm=None, enforcer=SimpleNamespace(config=None))


def _report_tool(agent: ToolUsingAgent):
    tools = agent._build_tools()
    return next(t for t in tools if t.name == "report_finding")


def test_repeat_reports_are_deduped():
    agent = _agent()
    report = _report_tool(agent)
    args = dict(
        title="IDOR on /api/Users/2",
        description="cross-user read",
        severity="high",
        endpoint="http://t/api/Users/2",
        method="GET",
    )

    first = report.func(**args)
    second = report.func(**args)

    assert "recorded" in first.lower()
    assert "duplicate" in second.lower()
    assert len(agent._findings) == 1


def test_distinct_findings_are_kept():
    agent = _agent()
    report = _report_tool(agent)

    report.func(title="IDOR", description="d", severity="high",
                endpoint="http://t/api/Users/2", method="GET")
    report.func(title="IDOR", description="d", severity="high",
                endpoint="http://t/api/Baskets/2", method="GET")
    report.func(title="IDOR", description="d", severity="high",
                endpoint="http://t/api/Users/2", method="PUT")

    assert len(agent._findings) == 3
