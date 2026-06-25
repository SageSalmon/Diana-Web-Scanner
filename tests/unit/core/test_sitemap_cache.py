"""Tests for the --sitemap-cache crawl-skip / save behavior.

These exercise ScanOrchestrator._obtain_sitemap directly (bound to a lightweight
SimpleNamespace) so we avoid the orchestrator's DB-backed __init__. The method is
the whole contract behind --sitemap-cache: load-and-skip-crawl when the cache
exists, crawl-and-save when it doesn't, and crawl-without-saving when no path is
set.
"""

from types import SimpleNamespace

import diana.core.orchestrator as orch_mod
from diana.core.models import Endpoint, SiteMap
from diana.core.orchestrator import ScanOrchestrator


def _make_sitemap() -> SiteMap:
    return SiteMap(
        base_url="http://target",
        endpoints=[
            Endpoint(url="http://target/a", method="GET", parameters={"id": "1"}),
            Endpoint(url="http://target/b", method="POST"),
        ],
    )


class _StubCrawler:
    """Stands in for the real network crawler."""

    def __init__(self, http, max_depth=0):
        pass

    async def crawl(self, target):
        return _make_sitemap()


class _StubSPACrawler:
    """No SPA routes → Playwright phases are skipped entirely."""

    def __init__(self, http):
        pass

    async def discover_routes(self, sitemap):
        return []


def _fake_orchestrator(sitemap_cache: str) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(sitemap_cache=sitemap_cache, target="http://target"),
        http=object(),
        enforcer=SimpleNamespace(max_crawl_depth=2),
    )


async def test_cache_hit_loads_and_skips_crawl(tmp_path, monkeypatch):
    cache = tmp_path / "sitemap.json"
    cache.write_text(_make_sitemap().model_dump_json())

    # Constructing the crawler at all is a failure on the cache-hit path.
    def _no_crawl(*args, **kwargs):
        raise AssertionError("crawl must be skipped when the cache exists")

    monkeypatch.setattr(orch_mod, "Crawler", _no_crawl)
    monkeypatch.setattr(orch_mod, "SPACrawler", _no_crawl)

    fake = _fake_orchestrator(str(cache))
    sitemap = await ScanOrchestrator._obtain_sitemap(fake)

    assert [e.url for e in sitemap.endpoints] == [
        "http://target/a",
        "http://target/b",
    ]
    # Parameters survive the round-trip — the cache must preserve dispatch inputs.
    assert sitemap.endpoints[0].parameters == {"id": "1"}
    assert fake._spa_findings == []


async def test_cache_miss_crawls_and_saves(tmp_path, monkeypatch):
    # Parent dir intentionally absent — _obtain_sitemap must create it.
    cache = tmp_path / "nested" / "sitemap.json"
    monkeypatch.setattr(orch_mod, "Crawler", _StubCrawler)
    monkeypatch.setattr(orch_mod, "SPACrawler", _StubSPACrawler)

    fake = _fake_orchestrator(str(cache))
    sitemap = await ScanOrchestrator._obtain_sitemap(fake)

    assert cache.exists(), "sitemap must be written on a cache miss"
    reloaded = SiteMap.model_validate_json(cache.read_text())
    assert [e.url for e in reloaded.endpoints] == [
        "http://target/a",
        "http://target/b",
    ]
    # The saved cache must round-trip back to what the scan actually used.
    assert [e.url for e in sitemap.endpoints] == [e.url for e in reloaded.endpoints]


async def test_no_cache_path_crawls_without_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(orch_mod, "Crawler", _StubCrawler)
    monkeypatch.setattr(orch_mod, "SPACrawler", _StubSPACrawler)

    fake = _fake_orchestrator("")  # caching disabled
    sitemap = await ScanOrchestrator._obtain_sitemap(fake)

    assert len(sitemap.endpoints) == 2
    # Nothing should be written when no cache path is configured.
    assert list(tmp_path.iterdir()) == []


def test_scan_config_sitemap_cache_defaults_empty():
    from diana.config import ScanConfig

    assert ScanConfig().sitemap_cache == ""
