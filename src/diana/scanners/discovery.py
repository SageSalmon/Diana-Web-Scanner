"""Directory and file discovery module.

Finds hidden paths, backup files, and exposed directories using:
1. Wordlist-driven brute force (standard pentest wordlist, not app-specific)
2. Parent path inference (discovered /ftp/legal.md → probe /ftp/)
3. Backup extension probing (discovered /config.js → probe /config.js.bak)
4. Technology-aware paths (detected Express → probe Express-specific paths)
"""

from __future__ import annotations

import uuid
from urllib.parse import urlparse

from diana.ai.agent import AIAgent
from diana.config import ScanConfig
from diana.core.http_client import ScopedHTTPClient
from diana.core.models import (
    Endpoint,
    Finding,
    Severity,
    VulnType,
)
from diana.scanners.base import BaseScanner

# Generic wordlist — curated from common pentest wordlists (SecLists, dirb, dirbuster).
# These paths are found across web apps regardless of framework or language.
# Organized by category for clarity but flattened during scanning.
COMMON_DIRECTORIES = [
    # Version control
    ".git/HEAD", ".git/config", ".svn/entries", ".hg/store",
    # Environment / config
    ".env", ".env.local", ".env.production", ".env.backup",
    "config.json", "config.yaml", "config.yml", "config.xml",
    "settings.json", "settings.yaml",
    # Backups
    "backup", "backups", "bak", "old", "archive",
    "dump.sql", "backup.sql", "db.sql", "database.sql",
    "backup.tar.gz", "backup.zip", "site.zip",
    # Admin panels
    "admin", "administrator", "admin-panel", "manage", "management",
    "dashboard", "portal", "console",
    # Uploads / user content
    "upload", "uploads", "files", "documents", "media",
    "ftp", "public", "private", "tmp", "temp",
    # API docs
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "swagger-ui.html", "api-docs", "graphql", "graphiql",
    # Monitoring / debug
    "metrics", "prometheus", "health", "healthz", "ready", "readyz",
    "status", "server-status", "server-info",
    "debug", "debug/pprof", "trace",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    # Logs
    "logs", "log", "access.log", "error.log",
    # Common framework files
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "humans.txt", "security.txt", ".well-known/security.txt",
    # Package manager artifacts
    "package.json", "composer.json", "Gemfile", "requirements.txt",
    "package-lock.json", "yarn.lock",
    # CI/CD
    ".github", ".gitlab-ci.yml", "Jenkinsfile", "Dockerfile",
    ".dockerenv",
    # IDE / editor artifacts
    ".idea", ".vscode", ".DS_Store", "Thumbs.db",
    # Common web files
    "favicon.ico", "manifest.json",
    "wp-config.php", "wp-login.php", "wp-admin",
    "web.config", "Web.config",
    "phpinfo.php", "info.php", "test.php",
    "elmah.axd", "trace.axd",
]

# Technology-specific paths — only probed if the tech stack is detected
TECH_SPECIFIC_PATHS: dict[str, list[str]] = {
    "Express": [
        "node_modules", ".npmrc",
        "encryptionkeys", "package.json",
    ],
    "Django": [
        "admin", "static", "media",
        "__debug__", "api/schema",
    ],
    "Rails": [
        "rails/info/properties", "rails/mailers",
        "assets", "system",
    ],
    "Spring": [
        "actuator", "actuator/env", "actuator/health", "actuator/beans",
        "actuator/configprops", "actuator/mappings",
        "h2-console", "swagger-ui.html",
    ],
    "Laravel": [
        "telescope", "horizon",
        "storage", "storage/logs/laravel.log",
    ],
    "ASP.NET": [
        "elmah.axd", "trace.axd",
        "web.config", "bin",
    ],
}

# Backup extensions to try on every discovered file
BACKUP_EXTENSIONS = [
    ".bak", ".old", ".orig", ".save", ".swp", ".tmp",
    ".backup", ".copy", "~",
    ".1", ".2",
]


class DiscoveryScanner(BaseScanner):
    name = "discovery"
    description = "Directory and file discovery — wordlist brute force, path inference, backup probing"

    @property
    def vuln_types(self) -> list:
        return [VulnType.INFO_DISCLOSURE, VulnType.DEBUG_ENDPOINT]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []

        work_items = self.claim_work(limit=1)
        if not work_items:
            return findings

        # The work item provides the base URL
        parsed = urlparse(work_items[0]["url"])
        base = f"{parsed.scheme}://{parsed.netloc}"
        payload = work_items[0].get("payload", {}) or {}
        probed: set[str] = set()

        # Capture a 404 baseline — SPAs return 200 with the same shell for any path
        self._404_baseline = ""
        self._404_length = 0
        try:
            resp = await self.http.get(f"{base}/diana-nonexistent-{uuid.uuid4().hex[:8]}")
            self._404_baseline = resp.text
            self._404_length = len(resp.text)
        except Exception:
            pass

        # 1. Wordlist-driven directory brute force
        wordlist_findings = await self._probe_wordlist(base, probed)
        findings.extend(wordlist_findings)

        # 2. Technology-specific paths (from payload if available)
        tech_stack = payload.get("tech_stack", {})
        tech_findings = await self._probe_tech_specific(base, tech_stack, probed)
        findings.extend(tech_findings)

        # 3. Parent path inference from known paths in payload
        known_paths = payload.get("known_paths", [])
        static_files = payload.get("static_files", [])
        parent_findings = await self._probe_parent_paths(base, known_paths, static_files, probed)
        findings.extend(parent_findings)

        # 4. Backup extension probing on known file paths
        backup_findings = await self._probe_backup_extensions(base, known_paths, static_files, probed)
        findings.extend(backup_findings)

        for item in work_items:
            self.complete_work(item["queue_id"])

        return findings

    async def _probe_wordlist(self, base: str, probed: set[str]) -> list[Finding]:
        """Brute force common paths from the generic wordlist."""
        findings: list[Finding] = []

        for path in COMMON_DIRECTORIES:
            url = f"{base}/{path}"
            if url in probed:
                continue
            probed.add(url)

            finding = await self._check_path(url, path)
            if finding:
                findings.append(finding)

        return findings

    async def _probe_tech_specific(
        self, base: str, tech_stack: dict, probed: set[str]
    ) -> list[Finding]:
        """Probe paths specific to detected technologies."""
        findings: list[Finding] = []

        detected = set()
        frameworks = tech_stack.get("frameworks", []) if isinstance(tech_stack, dict) else []
        server = tech_stack.get("server", "") if isinstance(tech_stack, dict) else ""

        for fw in frameworks:
            for tech_name in TECH_SPECIFIC_PATHS:
                if tech_name.lower() in fw.lower():
                    detected.add(tech_name)

        if server:
            for tech_name in TECH_SPECIFIC_PATHS:
                if tech_name.lower() in server.lower():
                    detected.add(tech_name)

        for tech_name in detected:
            for path in TECH_SPECIFIC_PATHS[tech_name]:
                url = f"{base}/{path}"
                if url in probed:
                    continue
                probed.add(url)

                finding = await self._check_path(url, path, tech_context=tech_name)
                if finding:
                    findings.append(finding)

        return findings

    async def _probe_parent_paths(
        self, base: str, known_paths: list[str], static_files: list[str], probed: set[str]
    ) -> list[Finding]:
        """Infer parent directories from discovered paths and probe them.

        If crawler found /ftp/legal.md, probe /ftp/ for directory listing.
        If crawler found /api/Users, probe /api/ for API root.
        """
        findings: list[Finding] = []
        parents: set[str] = set()

        all_paths = set()
        for p in known_paths:
            parsed = urlparse(p)
            all_paths.add(parsed.path)
        for sf in static_files:
            parsed = urlparse(sf)
            all_paths.add(parsed.path)

        for path in all_paths:
            segments = path.strip("/").split("/")
            # Build parent paths: /a/b/c → /a/b/, /a/
            for i in range(1, len(segments)):
                parent = "/" + "/".join(segments[:i]) + "/"
                parents.add(parent)

        for parent_path in parents:
            url = f"{base}{parent_path}"
            if url in probed:
                continue
            probed.add(url)

            try:
                resp = await self.http.get(url)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    # Detect directory listing
                    if self._is_directory_listing(body):
                        findings.append(Finding(
                            id=f"DIRLIST-{uuid.uuid4().hex[:8]}",
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            severity=Severity.MEDIUM,
                            title=f"Directory listing enabled at {parent_path}",
                            description=(
                                f"Directory listing is enabled, exposing file names "
                                f"and structure to anyone who requests the path."
                            ),
                            endpoint=Endpoint(url=url),
                            evidence=resp.text[:500],
                            cwe_id="CWE-548",
                            remediation="Disable directory listing in web server configuration.",
                            confirmed=True,
                        ))
            except Exception:
                continue

        return findings

    async def _probe_backup_extensions(
        self, base: str, known_paths: list[str], static_files: list[str], probed: set[str]
    ) -> list[Finding]:
        """Try backup extensions on every discovered file path.

        If /config.js exists, try /config.js.bak, /config.js.old, etc.
        """
        findings: list[Finding] = []

        # Collect file paths (not directories)
        file_paths: set[str] = set()
        for p in known_paths:
            parsed = urlparse(p)
            path = parsed.path
            if "." in path.split("/")[-1]:  # Has a file extension
                file_paths.add(path)
        for sf in static_files:
            parsed = urlparse(sf)
            if "." in parsed.path.split("/")[-1]:
                file_paths.add(parsed.path)

        for file_path in file_paths:
            for ext in BACKUP_EXTENSIONS:
                backup_url = f"{base}{file_path}{ext}"
                if backup_url in probed:
                    continue
                probed.add(backup_url)

                try:
                    resp = await self.http.get(backup_url)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        # Skip SPA shell responses
                        if self._is_spa_shell(resp.text):
                            continue
                        content_type = resp.headers.get("content-type", "")
                        if "html" not in content_type or self._looks_like_real_content(resp.text):
                            findings.append(Finding(
                                id=f"BACKUP-{uuid.uuid4().hex[:8]}",
                                vuln_type=VulnType.INFO_DISCLOSURE,
                                severity=Severity.HIGH,
                                title=f"Backup file found: {file_path}{ext}",
                                description=(
                                    f"A backup copy of {file_path} is publicly accessible. "
                                    f"Backup files may contain source code, credentials, or "
                                    f"configuration details."
                                ),
                                endpoint=Endpoint(url=backup_url),
                                evidence=resp.text[:300],
                                cwe_id="CWE-530",
                                remediation="Remove backup files from production web servers.",
                                confirmed=True,
                            ))
                except Exception:
                    continue

        return findings

    async def _check_path(
        self, url: str, path: str, tech_context: str = ""
    ) -> Finding | None:
        """Probe a single path and classify the response."""
        try:
            resp = await self.http.get(url)
        except Exception:
            return None

        if resp.status_code != 200:
            return None

        body = resp.text
        content_type = resp.headers.get("content-type", "")

        # Skip empty responses and likely custom 404 pages
        if len(body) < 10:
            return None

        # SPA detection: if the response body is the same as the 404 baseline,
        # this is just the SPA shell being served for an unknown route — not a real find
        if self._404_baseline and self._is_spa_shell(body):
            return None

        # Classify the finding
        if path == ".git/HEAD" and body.strip().startswith("ref:"):
            return self._make_finding(
                url, path, Severity.CRITICAL,
                "Git repository exposed",
                "The .git directory is publicly accessible, exposing full source code history.",
                body, "CWE-538",
            )

        if path == ".env" and "=" in body and any(
            k in body.upper() for k in ["DATABASE", "SECRET", "KEY", "PASSWORD", "TOKEN", "API"]
        ):
            return self._make_finding(
                url, path, Severity.CRITICAL,
                "Environment file exposed",
                "The .env file is publicly accessible, potentially exposing credentials and secrets.",
                "[REDACTED - credentials detected]", "CWE-312",
            )

        if path in (".svn/entries", ".hg/store") and len(body) > 20:
            return self._make_finding(
                url, path, Severity.CRITICAL,
                f"Version control directory exposed ({path})",
                "Version control metadata is publicly accessible.",
                body[:200], "CWE-538",
            )

        if path.endswith((".sql", ".dump")) and any(
            k in body.upper() for k in ["CREATE TABLE", "INSERT INTO", "DROP TABLE"]
        ):
            return self._make_finding(
                url, path, Severity.CRITICAL,
                f"Database dump exposed: {path}",
                "A database dump file is publicly accessible.",
                body[:200], "CWE-312",
            )

        if path in ("package.json", "composer.json", "Gemfile", "requirements.txt"):
            return self._make_finding(
                url, path, Severity.LOW,
                f"Dependency manifest exposed: {path}",
                "Application dependency information is publicly accessible, aiding attacker reconnaissance.",
                body[:300], "CWE-200",
            )

        if path in ("swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml", "swagger-ui.html", "api-docs"):
            return self._make_finding(
                url, path, Severity.MEDIUM,
                f"API documentation exposed: {path}",
                "API documentation is publicly accessible, revealing endpoint structure and parameters.",
                body[:300], "CWE-200",
            )

        if path in ("robots.txt",) and any(
            k in body.lower() for k in ["disallow", "admin", "private", "secret"]
        ):
            return self._make_finding(
                url, path, Severity.INFO,
                "robots.txt reveals hidden paths",
                "The robots.txt file discloses paths the site owner wants hidden from crawlers.",
                body[:500], "CWE-200",
            )

        if self._is_directory_listing(body):
            return self._make_finding(
                url, path, Severity.MEDIUM,
                f"Directory listing at /{path}",
                "Directory listing is enabled, exposing file names and structure.",
                body[:500], "CWE-548",
            )

        # Generic interesting response — only for non-HTML (avoid SPA false positives)
        if "html" not in content_type and "json" in content_type:
            context = f" (tech: {tech_context})" if tech_context else ""
            return self._make_finding(
                url, path, Severity.INFO,
                f"Accessible endpoint: /{path}{context}",
                f"Endpoint returns data and may expose internal information.",
                body[:300], "CWE-200",
            )

        return None

    def _make_finding(
        self, url: str, path: str, severity: Severity,
        title: str, description: str, evidence: str, cwe: str,
    ) -> Finding:
        return Finding(
            id=f"DISC-{uuid.uuid4().hex[:8]}",
            vuln_type=VulnType.INFO_DISCLOSURE if severity != Severity.CRITICAL
                else VulnType.DEBUG_ENDPOINT,
            severity=severity,
            title=title,
            description=description,
            endpoint=Endpoint(url=url),
            evidence=evidence,
            cwe_id=cwe,
            remediation="Remove or restrict access to this resource in production.",
            confirmed=True,
        )

    def _is_spa_shell(self, body: str) -> bool:
        """Detect if a response is just the SPA shell (same as a 404 response).

        SPAs return the same HTML shell for any route — the client-side JS
        handles routing. If this response body is essentially the same as
        what we got for a known-nonexistent path, it's not a real find.
        """
        if not self._404_baseline:
            return False
        # Same length within 5% tolerance
        if abs(len(body) - self._404_length) < self._404_length * 0.05:
            # Quick content check — same first 200 chars
            if body[:200] == self._404_baseline[:200]:
                return True
        return False

    @staticmethod
    def _is_directory_listing(body: str) -> bool:
        """Detect common directory listing patterns."""
        indicators = [
            "index of /", "directory listing", "<pre>", "parent directory",
            "[dir]", "[to parent directory]", "last modified",
        ]
        body_lower = body.lower()
        return sum(1 for i in indicators if i in body_lower) >= 2

    @staticmethod
    def _looks_like_real_content(body: str) -> bool:
        """Heuristic: does this look like real file content vs a custom 404 page?"""
        # Custom 404 pages typically have these
        not_found_patterns = ["not found", "page not found", "404", "does not exist"]
        body_lower = body.lower()
        if any(p in body_lower for p in not_found_patterns):
            return False
        return True
