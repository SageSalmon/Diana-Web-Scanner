"""AI-driven discovery agent.

Gives the AI HTTP tools and lets it reason about what hidden paths,
files, and endpoints might exist based on:
- What's already been discovered (tech stack, known paths, JS routes)
- Common patterns for the detected framework
- Breadcrumbs in responses (links, comments, error messages)
- Standard pentest discovery patterns
"""

from __future__ import annotations

from diana.ai.bedrock import BedrockClient
from diana.ai.tool_agent import ToolUsingAgent
from diana.config import ScanConfig
from diana.core.http_client import ScopedHTTPClient
from diana.core.models import Finding
from diana.scanners.base import BaseScanner


DISCOVERY_SYSTEM = """You are an expert penetration tester performing reconnaissance and discovery.

You are probing a web application to find hidden paths, exposed files, debug endpoints,
backup files, and sensitive information that wasn't found by the automated crawler.

You are a SECURITY TESTER, not a well-behaved crawler. You do NOT obey robots.txt
restrictions — you READ robots.txt to find paths the site owner wants hidden, then
you probe ALL of those paths. Attackers don't follow robots.txt and neither do you.

Your approach:
1. Read robots.txt — every Disallow path is a TARGET to investigate, not a restriction
2. Look at what's already been discovered (endpoints, tech stack, static files)
3. Based on the technology stack, probe framework-specific paths
4. Look for directory listings, backup files, config files, version control artifacts
5. Probe common paths: /ftp, /backup, /admin, /debug, /console, /metrics, /logs
6. If you find a directory listing, explore EVERY file in it
7. Probe for backup extensions (.bak, .old, .orig, .swp, ~) on discovered files
8. Look for API documentation (swagger, openapi, graphql playground)
9. Check for exposed environment files, Docker configs, CI/CD artifacts
10. Follow breadcrumbs — if a response mentions a path or file, probe it
11. Never request the same URL twice — if you already probed it, move on

IMPORTANT RULES:
- When you find a file that shouldn't be public (backups, configs, .git, .env), that's a FINDING.
- When you find a directory listing, that's a FINDING.
- When you find API documentation that reveals internal endpoints, that's a FINDING.
- When you find debug/monitoring endpoints (metrics, actuator, phpinfo), that's a FINDING.
- When you find version control artifacts (.git/HEAD, .svn/entries), that's a CRITICAL FINDING.
- Set vuln_type to: info_disclosure
- A 200 response with HTML that looks like a SPA shell (same content for every path) is NOT a finding — the app just serves its SPA for unknown routes.
- Be creative but efficient. Follow the evidence."""


DISCOVERY_PROMPT = """Discover hidden paths, files, and endpoints on this web application.

Application base URL: {base_url}

Technology stack detected:
  Server: {server}
  Frameworks: {frameworks}
  WAF: {waf}

Already discovered paths:
{known_paths}

Static files found:
{static_files}

SPA routes extracted from JavaScript:
{spa_routes}

Based on what's already known, probe for:
1. Framework-specific paths based on the detected tech stack
2. Parent directories of known files (if /ftp/legal.md exists, try /ftp/)
3. Backup extensions on config files (.bak, .old)
4. Admin panels, debug endpoints, monitoring
5. Any paths referenced in discovered content

The SPA serves the same HTML shell for any unknown client-side route — don't
report those as findings. Only report paths that return DIFFERENT content
(JSON data, file downloads, directory listings, config files, etc.)

Report every real discovery."""


class DiscoveryAgent(BaseScanner):
    name = "discovery_agent"
    description = "AI-driven path and file discovery — finds hidden endpoints, backups, configs"

    @property
    def vuln_types(self) -> list:
        from diana.core.models import VulnType
        return [VulnType.INFO_DISCLOSURE, VulnType.DEBUG_ENDPOINT]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        if config.no_ai or not self.ai:
            return []

        work_items = self.claim_work(limit=1)
        if not work_items:
            return []

        admin_token = self.http._auth_headers.get("Authorization", "").replace("Bearer ", "")

        from urllib.parse import urlparse
        parsed = urlparse(work_items[0]["url"])
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Build context from work item payload
        payload = work_items[0].get("payload", {}) or {}
        known_paths = payload.get("known_paths", [])[:40]
        static = payload.get("static_files", [])[:20]
        spa_routes = payload.get("spa_routes", [])[:20]

        server = payload.get("server", "unknown")
        frameworks = payload.get("frameworks", "unknown")
        waf = payload.get("waf", "none")

        prompt = DISCOVERY_PROMPT.format(
            base_url=base,
            server=server,
            frameworks=frameworks,
            waf=waf,
            known_paths="\n".join(f"  {p}" for p in known_paths) or "  (none)",
            static_files="\n".join(f"  {s}" for s in static) or "  (none)",
            spa_routes="\n".join(f"  {r}" for r in spa_routes) or "  (none)",
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
            max_turns=20,
            scan_state=self.scan_state,
            scan_id=self.scan_id,
            module_name="discovery_agent",
        )

        results = await agent.run(DISCOVERY_SYSTEM, prompt)

        for item in work_items:
            self.complete_work(item["queue_id"])

        return results
