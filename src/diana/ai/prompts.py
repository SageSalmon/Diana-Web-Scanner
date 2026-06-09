"""Prompt templates for Diana AI operations.

Every prompt includes engagement scope as immutable context (L1 enforcement).
"""

from __future__ import annotations

from diana.engagement.models import EngagementConfig


def _scope_block(engagement: EngagementConfig) -> str:
    """Generate the scope constraint block injected into every prompt."""
    domains = engagement.get_whitelisted_domains()
    deny_list = engagement.scope.deny_list

    return (
        "<scope_constraints>\n"
        "YOU MUST ONLY reason about, suggest, or generate payloads for targets "
        "within the following engagement scope. Any target outside this scope is "
        "STRICTLY FORBIDDEN. Do not reference, suggest scanning, or generate "
        "payloads for any domain, IP, or path not listed here.\n\n"
        f"Engagement ID: {engagement.engagement.id}\n"
        f"Client: {engagement.engagement.client}\n"
        f"Allowed Targets:\n"
        + "\n".join(f"  - {d}" for d in domains)
        + "\n\nDeny List (NEVER touch):\n"
        + "\n".join(f"  - {d}" for d in deny_list)
        + "\n\nDestructive payloads allowed: "
        + str(engagement.restrictions.destructive_payloads)
        + "\n</scope_constraints>"
    )


SYSTEM_BASE = (
    "You are Diana, an AI-powered web vulnerability scanner. You are an expert "
    "in web application security, OWASP Top 10, CWE classifications, and "
    "penetration testing methodologies. You think like a skilled pentester — "
    "methodical, creative, and thorough.\n\n"
    "You MUST adhere to the engagement scope constraints provided. Never suggest "
    "scanning or testing anything outside the defined scope."
)


def system_prompt(engagement: EngagementConfig) -> str:
    return f"{SYSTEM_BASE}\n\n{_scope_block(engagement)}"


SURFACE_ANALYSIS = """Analyze the following web application attack surface and generate vulnerability hypotheses.

For each hypothesis, provide:
- vuln_type: The vulnerability type (xss_reflected, sql_injection, ssrf, etc.)
- endpoint_url: The specific endpoint to test
- endpoint_method: HTTP method
- confidence: 0.0-1.0 confidence that this vulnerability exists
- reasoning: Why you believe this vulnerability may exist

Application sitemap summary:
{sitemap_summary}

Technology stack:
{tech_stack}

Forms discovered:
{forms_summary}

Respond as a JSON array of hypothesis objects."""


PAYLOAD_GENERATION = """Generate context-aware test payloads for the following vulnerability hypothesis.

Hypothesis:
- Type: {vuln_type}
- Endpoint: {endpoint_url} ({endpoint_method})
- Technology stack: {tech_stack}
- Parameter context: {param_context}
- Reasoning: {reasoning}

Generate payloads that:
1. Are appropriate for the detected technology stack
2. Include encoding variations if a WAF is detected ({waf_info})
3. Are NON-DESTRUCTIVE (detection only, no data modification)
4. Include both basic and advanced payloads

Respond as a JSON array of payload objects with fields: value, encoding, context."""


FINDING_VALIDATION = """Analyze this potential vulnerability finding and determine if it is a TRUE POSITIVE or FALSE POSITIVE.

Vulnerability type: {vuln_type}
Endpoint: {endpoint_url}
Payload sent: {payload}
Request: {request_summary}
Response status: {response_status}
Response body (relevant excerpt):
{response_excerpt}

Baseline response (without payload):
{baseline_excerpt}

Analyze:
1. Was the payload reflected/executed in the response?
2. Is there evidence of actual exploitation vs. safe handling?
3. Could this be a false positive? Why?
4. What is the actual security impact?

Respond as JSON: {{"confirmed": bool, "confidence": float, "analysis": str, "severity": str, "remediation": str}}"""


REPORT_NARRATIVE = """Write a professional penetration test finding narrative for the following vulnerability.

Finding:
- Type: {vuln_type}
- Severity: {severity}
- Endpoint: {endpoint_url}
- Evidence: {evidence}
- CWE: {cwe_id}

Write:
1. A clear title
2. A description explaining the vulnerability to both technical and non-technical audiences
3. The security impact / risk
4. Step-by-step remediation recommendations
5. References (OWASP, CWE)

Use professional pentest report language."""


SCAN_CONFIGURATOR = """Analyze the following initial reconnaissance data from a web application and generate a scan configuration.

Target: {target_url}

Pages discovered (sample):
{pages_summary}

Forms found:
{forms_summary}

Headers observed:
{headers_summary}

Cookies:
{cookies_summary}

JavaScript frameworks detected:
{js_frameworks}

Identify and configure:
1. **Authentication flow**: Is there a login form? What type (form POST, OAuth, SAML)?
2. **Logout detection**: What patterns indicate session loss?
3. **Crawl traps**: Any calendar widgets, infinite pagination, search facets to exclude?
4. **Session management**: Session cookies, CSRF tokens, JWT patterns?
5. **Form fill strategy**: For each form, what type of data should each field receive?
6. **WAF detection**: Any WAF signatures in headers or responses?

Respond as JSON with sections: auth_config, logout_detection, crawl_exclusions, session_config, form_strategies, waf_info."""


SESSION_CHECK = """Analyze this HTTP response and determine if the session is still authenticated.

Expected authenticated behavior: {auth_indicators}

Current response:
- Status: {status_code}
- Headers: {response_headers}
- Body excerpt: {body_excerpt}

Previous authenticated response (baseline):
- Status: {baseline_status}
- Body excerpt: {baseline_excerpt}

Is the session still authenticated? Respond as JSON: {{"authenticated": bool, "confidence": float, "reason": str}}"""
