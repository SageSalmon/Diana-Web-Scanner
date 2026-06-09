"""Scoped HTTP client — all outbound traffic goes through engagement enforcement."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from diana.engagement.enforcer import EngagementEnforcer
from diana.engagement.dns_guard import DNSGuard
from diana.engagement.models import ScopeViolation


class ScopedHTTPClient:
    """Async HTTP client that enforces engagement scope on every request.

    This is the ONLY way scanner components should make HTTP requests.
    It wraps httpx.AsyncClient with engagement enforcement at L2 (scope check)
    and L3 (DNS guard), plus rate limiting and redirect scope checking.
    """

    def __init__(
        self,
        enforcer: EngagementEnforcer,
        dns_guard: DNSGuard,
        timeout: int = 30,
    ):
        self.enforcer = enforcer
        self.dns_guard = dns_guard
        self._semaphore = asyncio.Semaphore(enforcer.max_concurrent)
        self._rate_limiter = RateLimiter(enforcer.rate_limit)
        self._auth_headers: dict[str, str] = {}
        self._auth_cookies: dict[str, str] = {}
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,  # We handle redirects manually for scope checking
            verify=True,
        )

    def inject_session(
        self,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        """Inject authentication session from the auth agent."""
        if headers:
            self._auth_headers.update(headers)
        if cookies:
            self._auth_cookies.update(cookies)
            for name, value in cookies.items():
                self._client.cookies.set(name, value)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: str | dict | None = None,
        json: Any = None,
        follow_redirects: bool = True,
        max_redirects: int = 10,
    ) -> httpx.Response:
        """Send a request after engagement scope validation."""
        # Merge auth headers into request
        merged_headers = dict(self._auth_headers)
        if headers:
            merged_headers.update(headers)
        headers = merged_headers if merged_headers else headers

        # L2: Application scope check
        self.enforcer.check_request(url, method)

        # L3: DNS guard — resolve and validate
        parsed = httpx.URL(url)
        hostname = parsed.host
        if hostname:
            self.dns_guard.resolve(hostname)

        # Rate limiting
        await self._rate_limiter.acquire()

        # Concurrency limiting
        async with self._semaphore:
            response = await self._client.request(
                method,
                url,
                headers=headers,
                data=data,
                json=json,
            )

        # Handle redirects with scope checking
        redirect_count = 0
        while response.is_redirect and follow_redirects and redirect_count < max_redirects:
            redirect_url = str(response.next_request.url) if response.next_request else ""
            if not redirect_url:
                break

            # Check if redirect stays in scope
            self.enforcer.check_redirect(url, redirect_url)

            await self._rate_limiter.acquire()
            async with self._semaphore:
                response = await self._client.request("GET", redirect_url, headers=headers)

            redirect_count += 1

        return response

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> ScopedHTTPClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, requests_per_second: int):
        self.rps = requests_per_second
        self._tokens = float(requests_per_second)
        self._max_tokens = float(requests_per_second)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._max_tokens, self._tokens + elapsed * self.rps)
            self._last_refill = now

            if self._tokens < 1.0:
                wait_time = (1.0 - self._tokens) / self.rps
                await asyncio.sleep(wait_time)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0
