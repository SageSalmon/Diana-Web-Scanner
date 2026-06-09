"""Report generator — produces HTML, JSON, and SARIF reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from diana.ai.bedrock import BedrockClient
from diana.ai.prompts import REPORT_NARRATIVE
from diana.config import ReportingConfig
from diana.core.models import Finding, ScanResult, Severity


class ReportGenerator:
    """Generates scan reports with optional AI-written narratives."""

    def __init__(self, bedrock: BedrockClient | None = None):
        self.bedrock = bedrock

    async def generate(self, result: ScanResult, config: ReportingConfig) -> Path:
        output_dir = Path(config.output)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_name = f"scan_{result.scan_id}_{timestamp}"

        # Enrich findings with AI narratives if available
        if self.bedrock:
            for finding in result.findings:
                if not finding.ai_analysis:
                    finding.ai_analysis = await self._generate_narrative(finding)

        if config.format == "json":
            path = output_dir / f"{base_name}.json"
            self._write_json(result, path)
        elif config.format == "sarif":
            path = output_dir / f"{base_name}.sarif"
            self._write_sarif(result, path)
        else:
            path = output_dir / f"{base_name}.html"
            self._write_html(result, path)

        return path

    async def _generate_narrative(self, finding: Finding) -> str:
        if not self.bedrock:
            return ""
        try:
            prompt = REPORT_NARRATIVE.format(
                vuln_type=finding.vuln_type.value,
                severity=finding.severity.value,
                endpoint_url=finding.endpoint.url,
                evidence=finding.evidence[:500],
                cwe_id=finding.cwe_id,
            )
            return self.bedrock.invoke(prompt)
        except Exception:
            return ""

    def _write_json(self, result: ScanResult, path: Path) -> None:
        data = result.model_dump(mode="json")
        path.write_text(json.dumps(data, indent=2, default=str))

    def _write_sarif(self, result: ScanResult, path: Path) -> None:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Diana",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/diana-scanner/diana",
                    }
                },
                "results": [
                    self._finding_to_sarif(f) for f in result.findings
                ],
            }],
        }
        path.write_text(json.dumps(sarif, indent=2))

    def _finding_to_sarif(self, finding: Finding) -> dict:
        severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }
        return {
            "ruleId": finding.cwe_id or finding.vuln_type.value,
            "level": severity_map.get(finding.severity, "warning"),
            "message": {"text": finding.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.endpoint.url}
                }
            }],
        }

    def _write_html(self, result: ScanResult, path: Path) -> None:
        severity_colors = {
            Severity.CRITICAL: "#dc3545",
            Severity.HIGH: "#fd7e14",
            Severity.MEDIUM: "#ffc107",
            Severity.LOW: "#17a2b8",
            Severity.INFO: "#6c757d",
        }

        findings_html = ""
        for finding in sorted(result.findings, key=lambda f: list(Severity).index(f.severity)):
            color = severity_colors.get(finding.severity, "#6c757d")
            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="severity" style="background-color: {color}">{finding.severity.value.upper()}</span>
                    <span class="title">{finding.title}</span>
                </div>
                <table>
                    <tr><td><strong>Type</strong></td><td>{finding.vuln_type.value}</td></tr>
                    <tr><td><strong>Endpoint</strong></td><td>{finding.endpoint.url}</td></tr>
                    <tr><td><strong>CWE</strong></td><td>{finding.cwe_id}</td></tr>
                    <tr><td><strong>Description</strong></td><td>{finding.description}</td></tr>
                    <tr><td><strong>Evidence</strong></td><td><code>{finding.evidence[:200]}</code></td></tr>
                    <tr><td><strong>Remediation</strong></td><td>{finding.remediation}</td></tr>
                </table>
                {"<div class='ai-analysis'><strong>AI Analysis:</strong><br>" + finding.ai_analysis + "</div>" if finding.ai_analysis else ""}
            </div>
            """

        by_severity = result.findings_by_severity
        summary_rows = ""
        for sev in Severity:
            count = len(by_severity[sev])
            color = severity_colors[sev]
            bar = "█" * count
            summary_rows += f"<tr><td><span style='color:{color}'>{sev.value.upper()}</span></td><td>{count}</td><td style='color:{color}'>{bar}</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Diana Scan Report — {result.scan_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; }}
        h1, h2 {{ color: #58a6ff; }}
        .summary {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; margin: 20px 0; }}
        .finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin: 10px 0; }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }}
        .severity {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .title {{ font-size: 16px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; }}
        td {{ padding: 6px; border-bottom: 1px solid #30363d; vertical-align: top; }}
        td:first-child {{ width: 120px; color: #8b949e; }}
        code {{ background: #1f2428; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
        .ai-analysis {{ margin-top: 10px; padding: 10px; background: #1c2333; border-left: 3px solid #58a6ff; }}
        .meta {{ color: #8b949e; font-size: 14px; }}
    </style>
</head>
<body>
    <h1>Diana Scan Report</h1>
    <div class="meta">
        Scan ID: {result.scan_id} |
        Target: {result.target} |
        Engagement: {result.engagement_id} |
        Duration: {result.duration_seconds:.1f}s |
        AI Model: {result.ai_model_used}
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <table>
            <tr><th>Severity</th><th>Count</th><th></th></tr>
            {summary_rows}
        </table>
        <p>
            Hypotheses generated: {result.hypotheses_generated} |
            Payloads tested: {result.payloads_tested} |
            False positives rejected: {result.false_positives_rejected}
        </p>
    </div>

    <h2>Findings ({len(result.findings)})</h2>
    {findings_html if findings_html else "<p>No vulnerabilities found.</p>"}

    <div class="meta" style="margin-top: 40px;">
        Generated by Diana v0.1.0 — AI-Enabled Web Vulnerability Scanner
    </div>
</body>
</html>"""

        path.write_text(html)
