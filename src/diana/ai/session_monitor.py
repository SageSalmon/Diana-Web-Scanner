"""Mid-scan session health monitor — detects session loss and re-authenticates."""

from __future__ import annotations

import json
import logging

from diana.ai.bedrock import BedrockClient
from diana.ai.prompts import SESSION_CHECK
from diana.core.http_client import ScopedHTTPClient

logger = logging.getLogger(__name__)


class SessionMonitor:
    """Monitors session health during scanning and triggers re-authentication."""

    def __init__(self, bedrock: BedrockClient, http: ScopedHTTPClient):
        self.bedrock = bedrock
        self.http = http
        self._baseline_url: str = ""
        self._baseline_status: int = 0
        self._baseline_excerpt: str = ""
        self._auth_indicators: str = ""
        self._check_interval: int = 20  # Check every N requests
        self._request_count: int = 0

    def set_baseline(
        self,
        url: str,
        status: int,
        body_excerpt: str,
        auth_indicators: str = "",
    ) -> None:
        """Set the authenticated baseline for comparison."""
        self._baseline_url = url
        self._baseline_status = status
        self._baseline_excerpt = body_excerpt[:1000]
        self._auth_indicators = auth_indicators or f"Status {status}, authenticated content"

    async def check_session(self, response_status: int, response_body: str, response_headers: dict) -> bool:
        """Quick heuristic check — is the session likely still alive?"""
        self._request_count += 1

        # Quick checks before burning an LLM call
        if response_status in (401, 403):
            logger.warning("Session may be lost — got %d", response_status)
            return await self._ai_verify_session()

        # Periodic full check
        if self._request_count % self._check_interval == 0:
            return await self._ai_verify_session()

        return True

    async def _ai_verify_session(self) -> bool:
        """Use AI to verify session by probing a known-good authenticated page."""
        if not self._baseline_url:
            return True

        try:
            response = await self.http.get(self._baseline_url)
        except Exception as e:
            logger.warning("Session probe failed: %s", e)
            return False

        prompt = SESSION_CHECK.format(
            auth_indicators=self._auth_indicators,
            status_code=response.status_code,
            response_headers=json.dumps(dict(response.headers)),
            body_excerpt=response.text[:1000],
            baseline_status=self._baseline_status,
            baseline_excerpt=self._baseline_excerpt,
        )

        try:
            result = self.bedrock.invoke_json(prompt)
            authenticated = result.get("authenticated", True)
            confidence = result.get("confidence", 0.5)
            reason = result.get("reason", "")

            if not authenticated and confidence > 0.7:
                logger.warning("Session lost (confidence: %.1f): %s", confidence, reason)
                return False

            return True
        except Exception as e:
            logger.warning("AI session check failed: %s", e)
            return True  # Assume alive if we can't verify
