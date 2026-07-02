"""Sensitive-data / content-exposure module.

Finds files a web app never meant to serve. Three generic, framework-agnostic
techniques, all driven by what the crawl actually discovered (no hard-coded
target paths or filenames):

1. **Directory listing** — request the parent directories of discovered URLs
   (plus a small generic wordlist of common file-store directory names) and
   detect an open index (Apache/nginx autoindex, ``serve-index``, or a JSON
   file array). An open listing both is a finding and reveals more files to
   fetch.

2. **Backup / source exposure** — for every discovered static file, probe
   common editor/backup suffixes (``.bak``, ``~``, ``.old`` …). A backup of a
   served file usually leaks source or secrets.

3. **Extension-filter bypass (poison null byte)** — when a path is blocked
   (403/406/415) or is a backup the server refuses by extension, retry with a
   trailing null byte plus an allowed-looking extension (``%00.md`` /
   ``%2500.md``). Servers that allowlist by suffix but read the raw path are
   fooled into serving the real file.

Soft-404 aware: single-page apps answer unknown routes with 200 + the SPA
shell, so every candidate is compared against a learned "not found" baseline
and only materially different, real responses are reported.
"""

from __future__ import annotations

import re
import uuid
from urllib.parse import urljoin, urlparse

from diana.config import ScanConfig
from diana.core.models import Endpoint, Finding, Severity, VulnType
from diana.scanners.base import BaseScanner

# Keep runtime/cost bounded on large sitemaps.
MAX_DIRS = 40
MAX_FILES = 60
MAX_REQUESTS = 500

# Bytes of the response body compared to recognize a repeated soft-404 shell.
HEAD_LEN = 200

# Generic names for directories that commonly hold static, uploaded, or backup
# content across web apps. Not target-specific — these are conventional names,
# the same way "/admin" or "/api" are conventional.
COMMON_DIRS = [
    "ftp", "files", "file", "uploads", "upload", "backup", "backups",
    "static", "assets", "download", "downloads", "logs", "log", "support",
    "data", "public", "private", "docs", "documents", "media", "archive",
]

# Editor/backup suffixes appended to a served file's full name.
BACKUP_SUFFIXES = [".bak", "~", ".old", ".orig", ".save", ".swp", ".copy",
                   ".1", ".tmp", ".backup"]

# Extensions a suffix-allowlist typically permits — used as the null-byte tail.
ALLOWED_TAILS = [".md", ".pdf", ".txt"]

# Markers of an open directory index.
_LISTING_MARKERS = [
    re.compile(r"<title>\s*Index of", re.I),
    re.compile(r"Directory listing for", re.I),
    re.compile(r"\[To Parent Directory\]", re.I),  # IIS
    re.compile(r'<a[^>]+href="[^"]+"[^>]*>.*?</a>.*?<a[^>]+href=', re.I | re.S),
]

# File extensions worth treating as "static content" for backup probing.
_STATIC_EXT = re.compile(
    r"\.(md|pdf|txt|json|xml|yml|yaml|conf|cfg|ini|sql|log|bak|zip|tar|gz|"
    r"kdbx|pem|key|env|js|css|csv|xls|xlsx|doc|docx|gg)$",
    re.I,
)


class SensitiveDataExposureScanner(BaseScanner):
    name = "sensitive_data_exposure"
    description = "Directory listings, backup/source files, and extension-filter bypass"

    def __init__(self, http, ai_agent=None):
        super().__init__(http, ai_agent)
        self._requests_sent = 0
        # Learned soft-404 fingerprints. SPAs answer every unknown route with a
        # byte-identical shell, so the opening bytes of the body are a reliable
        # discriminator — far less lossy than comparing body lengths.
        self._notfound_heads: list[str] = []

    @property
    def vuln_types(self) -> list:
        return [VulnType.INFO_DISCLOSURE]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        work = self.claim_work(limit=1000)
        if not work:
            return findings

        parsed = urlparse(work[0]["url"])
        base = f"{parsed.scheme}://{parsed.netloc}"

        await self._learn_not_found(base)

        seen: set[str] = set()
        discovered_files: set[str] = set()
        candidate_dirs = self._candidate_dirs(base, [w["url"] for w in work])

        # 1) Directory listings — and harvest the files they reveal.
        for dir_url in list(candidate_dirs)[:MAX_DIRS]:
            if self._requests_sent >= MAX_REQUESTS:
                break
            listing, listed = await self._check_listing(dir_url, seen)
            if listing:
                findings.append(listing)
            for f in listed:
                discovered_files.add(f)

        # Seed backup probing with static files seen during the crawl too.
        for w in work:
            if _STATIC_EXT.search(urlparse(w["url"]).path):
                discovered_files.add(w["url"])
            self.complete_work(w["queue_id"])

        # 2) + 3) Backup suffixes and null-byte bypass on each known file.
        for file_url in list(discovered_files)[:MAX_FILES]:
            if self._requests_sent >= MAX_REQUESTS:
                break
            findings.extend(await self._probe_backups(file_url, seen))
            findings.extend(await self._probe_null_byte(file_url, seen))

        print(
            f"  sensitive_data_exposure: {len(candidate_dirs)} dirs, "
            f"{len(discovered_files)} files, {self._requests_sent} probes, "
            f"{len(findings)} findings"
        )
        return findings

    # -- candidate derivation --------------------------------------------------

    def _candidate_dirs(self, base: str, urls: list[str]) -> set[str]:
        """Parent directories of discovered URLs + generic common dir names."""
        dirs: set[str] = set()
        for u in urls:
            path = urlparse(u).path
            parts = [p for p in path.split("/") if p]
            # Every ancestor directory of the discovered path.
            for i in range(len(parts)):
                anc = "/".join(parts[:i])
                dirs.add(f"{base}/{anc}/".replace("//", "/").replace(":/", "://"))
        for name in COMMON_DIRS:
            dirs.add(f"{base}/{name}/")
        dirs.discard(f"{base}/")  # the app root is not an interesting "listing"
        return dirs

    # -- soft-404 learning -----------------------------------------------------

    async def _learn_not_found(self, base: str) -> None:
        """Fetch a couple of certainly-missing paths to learn the app's soft-404
        response (SPAs return 200 + the shell for anything unknown)."""
        for probe in (f"{base}/diana-{uuid.uuid4().hex}",
                      f"{base}/diana-{uuid.uuid4().hex}/nope.md"):
            resp = await self._get(probe)
            if resp is not None:
                self._notfound_heads.append(resp.text[:HEAD_LEN])

    def _looks_like_not_found(self, resp) -> bool:
        if resp is None:
            return True
        if resp.status_code in (404, 400, 401, 403, 406, 415):
            return True
        # Same opening bytes as a known soft-404 (the SPA shell).
        head = resp.text[:HEAD_LEN]
        return any(head == known for known in self._notfound_heads)

    # -- techniques ------------------------------------------------------------

    async def _check_listing(self, dir_url: str, seen: set[str]):
        resp = await self._get(dir_url)
        if resp is None or resp.status_code != 200:
            return None, []
        body = resp.text
        if self._looks_like_not_found(resp):
            return None, []
        if not any(m.search(body) for m in _LISTING_MARKERS):
            return None, []

        listed = self._parse_listed_files(dir_url, body)
        finding = None
        if dir_url not in seen:
            seen.add(dir_url)
            finding = Finding(
                id=f"SDE-{uuid.uuid4().hex[:8]}",
                vuln_type=VulnType.INFO_DISCLOSURE,
                severity=Severity.MEDIUM,
                title=f"Open directory listing at {dir_url}",
                description=(
                    f"{dir_url} returns a browsable directory index, exposing "
                    f"the names ({len(listed)} found) and contents of files that "
                    f"were not meant to be enumerable."
                ),
                endpoint=Endpoint(url=dir_url),
                evidence=body[:300],
                cwe_id="CWE-548",
                remediation="Disable automatic directory indexing on the web server.",
                confirmed=True,
            )
        return finding, listed

    def _parse_listed_files(self, dir_url: str, body: str) -> list[str]:
        files: list[str] = []
        for href in re.findall(r'href="([^"]+)"', body, re.I):
            if href in ("../", "/", ".", "..") or href.startswith("?"):
                continue
            files.append(urljoin(dir_url, href))
        # Some Node servers emit a JSON array of names instead of HTML.
        for name in re.findall(r'"([^"/]+\.[a-z0-9]{1,6})"', body, re.I):
            files.append(urljoin(dir_url, name))
        return files

    async def _probe_backups(self, file_url: str, seen: set[str]) -> list[Finding]:
        findings: list[Finding] = []
        for suffix in BACKUP_SUFFIXES:
            if self._requests_sent >= MAX_REQUESTS:
                break
            candidate = file_url + suffix
            resp = await self._get(candidate)
            if resp is not None and resp.status_code == 200 \
                    and not self._looks_like_not_found(resp) \
                    and candidate not in seen:
                seen.add(candidate)
                findings.append(self._finding(
                    candidate, Severity.HIGH, "Backup/source file exposed",
                    f"A backup copy of a served file is publicly retrievable at "
                    f"{candidate}. Backups often contain source code, credentials, "
                    f"or data absent from the live file.",
                    resp, "CWE-530",
                    "Remove backup files from web roots; deny access by extension.",
                ))
        return findings

    async def _probe_null_byte(self, file_url: str, seen: set[str]) -> list[Finding]:
        """If the file is blocked by an extension allowlist, a poison null byte
        followed by an allowed extension can bypass the filter."""
        base_resp = await self._get(file_url)
        blocked = base_resp is None or base_resp.status_code in (403, 406, 415)
        if not blocked:
            return []
        findings: list[Finding] = []
        for enc in ("%00", "%2500"):
            for tail in ALLOWED_TAILS:
                if self._requests_sent >= MAX_REQUESTS:
                    break
                candidate = f"{file_url}{enc}{tail}"
                resp = await self._get(candidate)
                if resp is not None and resp.status_code == 200 \
                        and not self._looks_like_not_found(resp) \
                        and candidate not in seen:
                    seen.add(candidate)
                    findings.append(self._finding(
                        candidate, Severity.HIGH,
                        "Extension-filter bypass exposes restricted file",
                        f"The server blocked {file_url} by extension but served it "
                        f"via a poison-null-byte bypass ({candidate}), defeating the "
                        f"allowlist and exposing the restricted file.",
                        resp, "CWE-158",
                        "Reject null bytes in paths; validate the canonical path, "
                        "not the trailing extension.",
                    ))
                    return findings  # one confirmation per file is enough
        return findings

    # -- helpers ---------------------------------------------------------------

    def _finding(self, url, severity, title, desc, resp, cwe, remediation) -> Finding:
        return Finding(
            id=f"SDE-{uuid.uuid4().hex[:8]}",
            vuln_type=VulnType.INFO_DISCLOSURE,
            severity=severity,
            title=f"{title}: {url}",
            description=desc,
            endpoint=Endpoint(url=url),
            evidence=resp.text[:200] if resp is not None else "",
            cwe_id=cwe,
            remediation=remediation,
            confirmed=True,
        )

    async def _get(self, url: str):
        if self._requests_sent >= MAX_REQUESTS:
            return None
        self._requests_sent += 1
        try:
            return await self.http.get(url)
        except Exception:
            return None
