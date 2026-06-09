"""Core data models for scan operations."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    PENDING = "pending"
    CONFIGURING = "configuring"
    CRAWLING = "crawling"
    ANALYZING = "analyzing"
    TESTING = "testing"
    VALIDATING = "validating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    PAUSED = "paused"
    FAILED = "failed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnType(str, Enum):
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SQLI = "sql_injection"
    SQLI_BLIND = "sql_injection_blind"
    COMMAND_INJECTION = "command_injection"
    SSTI = "server_side_template_injection"
    SSRF = "server_side_request_forgery"
    IDOR = "insecure_direct_object_reference"
    BROKEN_AUTH = "broken_authentication"
    PATH_TRAVERSAL = "path_traversal"
    SECURITY_HEADERS = "missing_security_headers"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    INFO_DISCLOSURE = "information_disclosure"
    WEAK_CRYPTO = "weak_cryptography"
    OPEN_REDIRECT = "open_redirect"
    DEBUG_ENDPOINT = "debug_endpoint_exposed"


class Endpoint(BaseModel):
    url: str
    method: str = "GET"
    parameters: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    content_type: str = ""
    requires_auth: bool = False


class Form(BaseModel):
    action: str
    method: str = "POST"
    fields: list[FormField] = Field(default_factory=list)
    page_url: str = ""


class FormField(BaseModel):
    name: str
    field_type: str = "text"
    required: bool = False
    value: str = ""
    options: list[str] = Field(default_factory=list)


# Fix forward reference
Form.model_rebuild()


class TechStack(BaseModel):
    server: str = ""
    frameworks: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    cms: str = ""
    js_libraries: list[str] = Field(default_factory=list)
    waf: str = ""
    cdn: str = ""


class SiteMap(BaseModel):
    base_url: str
    endpoints: list[Endpoint] = Field(default_factory=list)
    forms: list[Form] = Field(default_factory=list)
    tech_stack: TechStack = Field(default_factory=TechStack)
    static_files: list[str] = Field(default_factory=list)
    external_links: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    vuln_type: VulnType
    endpoint: Endpoint
    confidence: float = 0.0
    reasoning: str = ""


class Payload(BaseModel):
    value: str
    vuln_type: VulnType
    encoding: str = "none"
    context: str = ""
    is_destructive: bool = False


class TestResult(BaseModel):
    endpoint: Endpoint
    payload: Payload
    request_url: str
    request_method: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    response_time_ms: float = 0.0
    error: str = ""


class Finding(BaseModel):
    id: str = ""
    vuln_type: VulnType
    severity: Severity
    title: str
    description: str
    endpoint: Endpoint
    evidence: str = ""
    payload_used: str = ""
    remediation: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    confirmed: bool = False
    false_positive: bool = False
    ai_analysis: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanResult(BaseModel):
    scan_id: str
    target: str
    engagement_id: str
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    sitemap: SiteMap | None = None
    findings: list[Finding] = Field(default_factory=list)
    hypotheses_generated: int = 0
    payloads_tested: int = 0
    false_positives_rejected: int = 0
    duration_seconds: float = 0.0
    ai_model_used: str = ""
    modules_run: list[str] = Field(default_factory=list)

    @property
    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            if f.confirmed and not f.false_positive:
                result[f.severity].append(f)
        return result
