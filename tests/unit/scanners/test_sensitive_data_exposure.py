"""Unit tests for the sensitive_data_exposure scanner.

The scanner is exercised against a fake HTTP client whose routing table maps
URLs to (status, body) pairs, so tests assert on generic behavior (listing
detection, backup discovery, null-byte bypass, soft-404 suppression) without
any real network or target-specific paths.
"""

from __future__ import annotations

import pytest

from diana.config import ScanConfig
from diana.core.models import VulnType
from diana.scanners.sensitive_data_exposure import SensitiveDataExposureScanner

SPA_SHELL = "<html><body><app-root></app-root></body></html>" + "x" * 300


class FakeResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": "text/html"}


class FakeHTTP:
    """Routes exact URLs to responses; everything else is the SPA soft-404."""

    def __init__(self, routes: dict[str, tuple[int, str]]):
        self.routes = routes
        self.requested: list[str] = []

    async def get(self, url: str, **kwargs):
        self.requested.append(url)
        if url in self.routes:
            status, body = self.routes[url]
            return FakeResponse(status, body)
        # Unknown route → SPA shell with 200 (soft-404).
        return FakeResponse(200, SPA_SHELL)


class FakeState:
    def __init__(self, urls: list[str]):
        self._items = [
            {"queue_id": i, "url": u, "method": "GET",
             "auth_context": "none", "payload": {}}
            for i, u in enumerate(urls)
        ]
        self.completed: list[int] = []

    def claim_work(self, scan_id, name, limit):
        return self._items[:limit]

    def complete_work(self, queue_id):
        self.completed.append(queue_id)


def _make(routes, urls):
    scanner = SensitiveDataExposureScanner(FakeHTTP(routes))
    scanner.scan_state = FakeState(urls)
    scanner.scan_id = "test"
    return scanner


@pytest.mark.asyncio
async def test_detects_open_directory_listing():
    listing_body = (
        "<html><head><title>Index of /files</title></head><body>"
        '<a href="../">../</a>'
        '<a href="secret.md">secret.md</a>'
        '<a href="notes.txt">notes.txt</a>'
        "</body></html>"
    )
    routes = {"http://t/files/": (200, listing_body)}
    scanner = _make(routes, ["http://t/app/main.js"])

    findings = await scanner.scan(ScanConfig())

    listings = [f for f in findings if "directory listing" in f.title.lower()]
    assert len(listings) == 1
    assert listings[0].vuln_type == VulnType.INFO_DISCLOSURE
    assert listings[0].cwe_id == "CWE-548"


@pytest.mark.asyncio
async def test_soft_404_does_not_trigger_listing():
    # No route returns a real listing; every dir probe hits the SPA shell.
    scanner = _make({}, ["http://t/app/main.js", "http://t/api/products"])
    findings = await scanner.scan(ScanConfig())
    assert findings == []


@pytest.mark.asyncio
async def test_finds_backup_of_static_file():
    # A crawled static file whose .bak is retrievable.
    routes = {
        "http://t/app/config.json": (200, '{"ok":true}'),
        "http://t/app/config.json.bak": (200, '{"db_password":"hunter2"}'),
    }
    scanner = _make(routes, ["http://t/app/config.json"])
    findings = await scanner.scan(ScanConfig())

    backups = [f for f in findings if "backup" in f.title.lower()]
    assert len(backups) == 1
    assert backups[0].cwe_id == "CWE-530"
    assert backups[0].endpoint.url == "http://t/app/config.json.bak"


@pytest.mark.asyncio
async def test_null_byte_bypass_when_extension_blocked():
    # Direct fetch is blocked (403); null-byte + allowed tail serves the file.
    routes = {
        "http://t/ftp/coupons.bak": (403, "Forbidden"),
        "http://t/ftp/coupons.bak%00.md": (200, "SECRET COUPON DATA " + "y" * 300),
    }
    scanner = _make(routes, ["http://t/ftp/coupons.bak"])
    findings = await scanner.scan(ScanConfig())

    bypass = [f for f in findings if "bypass" in f.title.lower()]
    assert len(bypass) == 1
    assert bypass[0].cwe_id == "CWE-158"


@pytest.mark.asyncio
async def test_no_backup_finding_for_soft_404_variant():
    # .bak of a served file returns the SPA shell → must NOT be a finding.
    routes = {"http://t/app/config.json": (200, '{"ok":true}')}
    scanner = _make(routes, ["http://t/app/config.json"])
    findings = await scanner.scan(ScanConfig())
    assert [f for f in findings if "backup" in f.title.lower()] == []


@pytest.mark.asyncio
async def test_respects_request_budget():
    scanner = _make({}, [f"http://t/dir{i}/f{i}.json" for i in range(50)])
    await scanner.scan(ScanConfig())
    from diana.scanners.sensitive_data_exposure import MAX_REQUESTS
    assert scanner._requests_sent <= MAX_REQUESTS


@pytest.mark.asyncio
async def test_derives_generic_common_dirs():
    scanner = _make({}, ["http://t/index.html"])
    dirs = scanner._candidate_dirs("http://t", ["http://t/index.html"])
    assert "http://t/ftp/" in dirs
    assert "http://t/backup/" in dirs
    assert "http://t/" not in dirs  # app root excluded


@pytest.mark.asyncio
async def test_derives_ancestor_dirs_from_paths():
    scanner = _make({}, [])
    dirs = scanner._candidate_dirs("http://t", ["http://t/a/b/c/file.js"])
    assert "http://t/a/" in dirs
    assert "http://t/a/b/" in dirs
    assert "http://t/a/b/c/" in dirs


@pytest.mark.asyncio
async def test_real_file_sharing_soft404_length_still_reported():
    # A genuinely-exposed file whose length is close to the SPA shell must NOT
    # be suppressed — head-comparison, not length, decides. (Regression guard.)
    near_len_body = "TOTALLY DIFFERENT CONTENT " + "z" * (len(SPA_SHELL) - 26)
    routes = {
        "http://t/app/data.json": (200, '{"ok":true}'),
        "http://t/app/data.json.bak": (200, near_len_body),
    }
    scanner = _make(routes, ["http://t/app/data.json"])
    findings = await scanner.scan(ScanConfig())
    assert [f for f in findings if "backup" in f.title.lower()]


@pytest.mark.asyncio
async def test_recurses_into_subdirectory_listing():
    # /support/ lists a logs/ subdir; logs/ lists access.log. The scanner must
    # follow the subdirectory, report the nested listing, and fetch the file.
    support_body = (
        "<html><title>Index of /support</title>"
        '<a href="../">../</a><a href="logs/">logs/</a></html>'
    )
    logs_body = (
        "<html><title>Index of /support/logs</title>"
        '<a href="../">../</a><a href="access.log">access.log</a></html>'
    )
    routes = {
        "http://t/support/": (200, support_body),
        "http://t/support/logs/": (200, logs_body),
        "http://t/support/logs/access.log": (200, "1.2.3.4 - GET /secret " + "L" * 300),
    }
    scanner = _make(routes, ["http://t/app/main.js"])
    findings = await scanner.scan(ScanConfig())

    titles = " ".join(f.title for f in findings)
    assert "http://t/support/logs/" in titles          # nested listing reported
    assert "http://t/support/logs/access.log" in scanner.http.requested  # file fetched


@pytest.mark.asyncio
async def test_completes_all_work_items():
    scanner = _make({}, ["http://t/a.js", "http://t/b.js"])
    await scanner.scan(ScanConfig())
    assert scanner.scan_state.completed == [0, 1]
