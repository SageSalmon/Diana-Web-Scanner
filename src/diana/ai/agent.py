"""AI Agent — ReAct loop for vulnerability analysis powered by Bedrock."""

from __future__ import annotations

import json
import logging
from typing import Any

from diana.ai.bedrock import BedrockClient
from diana.ai.prompts import (
    FINDING_VALIDATION,
    PAYLOAD_GENERATION,
    SURFACE_ANALYSIS,
    system_prompt,
)
from diana.core.models import (
    Endpoint,
    Finding,
    Hypothesis,
    Payload,
    Severity,
    SiteMap,
    VulnType,
)
from diana.engagement.enforcer import EngagementEnforcer

logger = logging.getLogger(__name__)


class AIAgent:
    """ReAct agent that reasons about attack surfaces and validates findings."""

    def __init__(self, bedrock: BedrockClient, enforcer: EngagementEnforcer, llm=None):
        self.bedrock = bedrock
        self.enforcer = enforcer
        self.llm = llm  # LangChain LLM for agent modules
        self._system = system_prompt(enforcer.config)

    async def analyze_surface(self, sitemap: SiteMap) -> list[Hypothesis]:
        """Analyze the crawled sitemap and generate vulnerability hypotheses."""
        sitemap_summary = self._summarize_sitemap(sitemap)
        tech_stack = self._summarize_tech_stack(sitemap)
        forms_summary = self._summarize_forms(sitemap)

        prompt = SURFACE_ANALYSIS.format(
            sitemap_summary=sitemap_summary,
            tech_stack=tech_stack,
            forms_summary=forms_summary,
        )

        try:
            result = self.bedrock.invoke_json(prompt, system=self._system)
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("AI surface analysis failed: %s", e)
            return []

        hypotheses: list[Hypothesis] = []
        items = result if isinstance(result, list) else result.get("hypotheses", [])

        for item in items:
            try:
                vuln_type = VulnType(item.get("vuln_type", ""))
                hypotheses.append(Hypothesis(
                    vuln_type=vuln_type,
                    endpoint=Endpoint(
                        url=item.get("endpoint_url", ""),
                        method=item.get("endpoint_method", "GET"),
                    ),
                    confidence=float(item.get("confidence", 0.5)),
                    reasoning=item.get("reasoning", ""),
                ))
            except (ValueError, KeyError):
                continue

        # Sort by confidence descending
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses

    async def generate_payloads(
        self,
        hypothesis: Hypothesis,
        tech_stack: str = "",
        waf_info: str = "none detected",
    ) -> list[Payload]:
        """Generate context-aware payloads for a hypothesis."""
        prompt = PAYLOAD_GENERATION.format(
            vuln_type=hypothesis.vuln_type.value,
            endpoint_url=hypothesis.endpoint.url,
            endpoint_method=hypothesis.endpoint.method,
            tech_stack=tech_stack,
            param_context=json.dumps(hypothesis.endpoint.parameters),
            reasoning=hypothesis.reasoning,
            waf_info=waf_info,
        )

        try:
            result = self.bedrock.invoke_json(prompt, system=self._system)
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("AI payload generation failed: %s", e)
            return []

        payloads: list[Payload] = []
        items = result if isinstance(result, list) else result.get("payloads", [])

        for item in items:
            payload = Payload(
                value=item.get("value", ""),
                vuln_type=hypothesis.vuln_type,
                encoding=item.get("encoding", "none"),
                context=item.get("context", ""),
            )
            # L2 check: ensure payload isn't destructive if not allowed
            try:
                self.enforcer.check_destructive(payload.value)
                payloads.append(payload)
            except Exception:
                logger.info("Blocked destructive payload: %s", payload.value[:50])

        return payloads

    async def validate_finding(self, finding: Finding) -> bool:
        """Use AI to validate whether a finding is a true or false positive."""
        prompt = FINDING_VALIDATION.format(
            vuln_type=finding.vuln_type.value,
            endpoint_url=finding.endpoint.url,
            payload=finding.payload_used,
            request_summary=f"{finding.endpoint.method} {finding.endpoint.url}",
            response_status="200",
            response_excerpt=finding.evidence[:2000] if finding.evidence else "N/A",
            baseline_excerpt="N/A",
        )

        try:
            result = self.bedrock.invoke_json(prompt, system=self._system)
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("AI validation failed: %s — defaulting to confirmed", e)
            return True

        confirmed = result.get("confirmed", True)
        finding.ai_analysis = result.get("analysis", "")
        finding.remediation = result.get("remediation", finding.remediation)

        severity_str = result.get("severity", "")
        if severity_str:
            try:
                finding.severity = Severity(severity_str.lower())
            except ValueError:
                pass

        return confirmed

    def _summarize_sitemap(self, sitemap: SiteMap) -> str:
        endpoints = sitemap.endpoints[:50]
        lines = [f"Base URL: {sitemap.base_url}", f"Total endpoints: {len(sitemap.endpoints)}"]
        for ep in endpoints:
            params = ", ".join(ep.parameters.keys()) if ep.parameters else "none"
            lines.append(f"  {ep.method} {ep.url} [params: {params}]")
        return "\n".join(lines)

    def _summarize_tech_stack(self, sitemap: SiteMap) -> str:
        ts = sitemap.tech_stack
        parts = []
        if ts.server:
            parts.append(f"Server: {ts.server}")
        if ts.frameworks:
            parts.append(f"Frameworks: {', '.join(ts.frameworks)}")
        if ts.waf:
            parts.append(f"WAF: {ts.waf}")
        return " | ".join(parts) if parts else "Unknown"

    def _summarize_forms(self, sitemap: SiteMap) -> str:
        if not sitemap.forms:
            return "No forms found."
        lines = []
        for form in sitemap.forms[:20]:
            field_names = [f.name for f in form.fields]
            lines.append(f"  {form.method} {form.action} — fields: {', '.join(field_names)}")
        return "\n".join(lines)
