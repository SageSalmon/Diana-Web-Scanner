"""Shared test fixtures for Diana scanner tests."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

import pytest

from diana.core.models import Endpoint, SiteMap, TechStack


@dataclass
class MockResponse:
    """Synthetic HTTP response for testing — no real network calls."""
    status_code: int = 200
    text: str = ""
    content: bytes = b""
    headers: dict = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {"content-type": "text/html"}
        if not self.content and self.text:
            self.content = self.text.encode()


@pytest.fixture
def mock_http_client():
    """Returns a mock ScopedHTTPClient with configurable responses.

    Usage:
        def test_something(mock_http_client):
            client = mock_http_client({"http://app/search?q=test": MockResponse(text="<p>test</p>")})
    """
    def _factory(response_map: dict[str, MockResponse] | None = None, default_response: MockResponse | None = None):
        client = AsyncMock()
        default = default_response or MockResponse(text="<html><body>OK</body></html>")

        async def mock_get(url, **kwargs):
            if response_map and url in response_map:
                return response_map[url]
            # Check prefix matches for URLs with query strings
            if response_map:
                for key, resp in response_map.items():
                    if url.startswith(key.split("?")[0]) and "?" in url:
                        return resp
            return default

        async def mock_post(url, **kwargs):
            if response_map and url in response_map:
                return response_map[url]
            return default

        client.get = mock_get
        client.post = mock_post
        client.enforcer = MagicMock()
        client._auth_headers = {}
        return client

    return _factory


@pytest.fixture
def sample_endpoint():
    """Create a sample Endpoint with configurable params."""
    def _factory(url="http://app/search", method="GET", parameters=None):
        return Endpoint(
            url=url,
            method=method,
            parameters=parameters or {"q": "test"},
        )
    return _factory


@pytest.fixture
def sample_sitemap():
    """Create a sample SiteMap with a few endpoints."""
    def _factory(base_url="http://app", endpoints=None):
        return SiteMap(
            base_url=base_url,
            endpoints=endpoints or [
                Endpoint(url=f"{base_url}/search", method="GET", parameters={"q": ""}),
                Endpoint(url=f"{base_url}/feedback", method="POST"),
                Endpoint(url=f"{base_url}/profile", method="GET", parameters={"id": "1"}),
            ],
        )
    return _factory
