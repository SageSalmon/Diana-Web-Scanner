"""AI-driven scan configurator — pre-scan intelligence phase.

Performs a light recon pass, then uses AI to auto-detect login flows,
crawl traps, session handling, and generate scan configuration.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from diana.ai.bedrock import BedrockClient
from diana.ai.prompts import SCAN_CONFIGURATOR, system_prompt
from diana.core.http_client import ScopedHTTPClient
from diana.engagement.models import EngagementConfig

logger = logging.getLogger(__name__)


@dataclass
class AuthDetection:
    type: str = ""  # form, oauth, saml, basic, none
    login_url: str = ""
    login_method: str = "POST"
    username_field: str = ""
    password_field: str = ""
    session_cookie: str = ""
    csrf_field: str = ""


@dataclass
class LogoutDetection:
    redirect_patterns: list[str] = field(default_factory=list)
    body_patterns: list[str] = field(default_factory=list)
    status_codes: list[int] = field(default_factory=lambda: [401, 403])


@dataclass
class CrawlExclusion:
    pattern: str
    reason: str


@dataclass
class FormStrategy:
    form_action: str
    field_strategies: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanSetupResult:
    auth: AuthDetection = field(default_factory=AuthDetection)
    logout: LogoutDetection = field(default_factory=LogoutDetection)
    crawl_exclusions: list[CrawlExclusion] = field(default_factory=list)
    form_strategies: list[FormStrategy] = field(default_factory=list)
    waf_detected: str = ""
    tech_stack_summary: str = ""


class ScanConfigurator:
    """Uses AI to auto-configure scan parameters from a light recon pass."""

    def __init__(self, bedrock: BedrockClient, http: ScopedHTTPClient):
        self.bedrock = bedrock
        self.http = http

    async def configure(
        self,
        target_url: str,
        engagement: EngagementConfig,
    ) -> ScanSetupResult:
        """Run light recon and generate AI-driven scan configuration."""
        # Light crawl — just the landing page and immediate links
        recon_data = await self._light_recon(target_url)

        prompt = SCAN_CONFIGURATOR.format(
            target_url=target_url,
            pages_summary=recon_data.get("pages", "N/A"),
            forms_summary=recon_data.get("forms", "N/A"),
            headers_summary=recon_data.get("headers", "N/A"),
            cookies_summary=recon_data.get("cookies", "N/A"),
            js_frameworks=recon_data.get("js_frameworks", "N/A"),
        )

        try:
            result = self.bedrock.invoke_json(
                prompt,
                system=system_prompt(engagement),
            )
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("AI scan configuration failed: %s — using defaults", e)
            return ScanSetupResult()

        return self._parse_config_result(result)

    async def _light_recon(self, target_url: str) -> dict[str, str]:
        """Fetch the target and a few linked pages to gather signals."""
        data: dict[str, str] = {}

        try:
            response = await self.http.get(target_url)
            headers = dict(response.headers)
            data["headers"] = json.dumps(headers, indent=2)

            cookies = [
                f"{k}={v}" for k, v in response.cookies.items()
            ]
            data["cookies"] = ", ".join(cookies) if cookies else "none"

            body = response.text[:5000]
            data["pages"] = f"Landing page ({response.status_code}): {len(body)} chars"

            # Detect JS frameworks from script tags
            frameworks = []
            body_lower = body.lower()
            for fw in ["react", "angular", "vue", "jquery", "next", "nuxt", "svelte"]:
                if fw in body_lower:
                    frameworks.append(fw)
            data["js_frameworks"] = ", ".join(frameworks) if frameworks else "none detected"

            # Extract forms
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(body, "lxml")
            forms = soup.find_all("form")
            form_summaries = []
            for form in forms:
                action = form.get("action", "")
                method = form.get("method", "GET")
                inputs = [
                    inp.get("name", "unnamed")
                    for inp in form.find_all("input")
                    if inp.get("name")
                ]
                form_summaries.append(f"{method} {action} — fields: {', '.join(inputs)}")
            data["forms"] = "\n".join(form_summaries) if form_summaries else "none found"

        except Exception as e:
            logger.warning("Light recon failed: %s", e)
            data["pages"] = f"Recon failed: {e}"

        return data

    def _parse_config_result(self, result: dict) -> ScanSetupResult:
        """Parse the AI's JSON response into a ScanSetupResult."""
        setup = ScanSetupResult()

        # Auth config
        auth_data = result.get("auth_config", {})
        if auth_data:
            setup.auth = AuthDetection(
                type=auth_data.get("type", ""),
                login_url=auth_data.get("login_url", ""),
                login_method=auth_data.get("login_method", "POST"),
                username_field=auth_data.get("username_field", ""),
                password_field=auth_data.get("password_field", ""),
                session_cookie=auth_data.get("session_cookie", ""),
                csrf_field=auth_data.get("csrf_field", ""),
            )

        # Logout detection
        logout_data = result.get("logout_detection", {})
        if logout_data:
            setup.logout = LogoutDetection(
                redirect_patterns=logout_data.get("redirect_patterns", []),
                body_patterns=logout_data.get("body_patterns", []),
                status_codes=logout_data.get("status_codes", [401, 403]),
            )

        # Crawl exclusions — AI may return dicts or plain strings
        for excl in result.get("crawl_exclusions", []):
            if isinstance(excl, dict):
                setup.crawl_exclusions.append(CrawlExclusion(
                    pattern=excl.get("pattern", ""),
                    reason=excl.get("reason", ""),
                ))
            elif isinstance(excl, str):
                setup.crawl_exclusions.append(CrawlExclusion(
                    pattern=excl, reason="AI-detected"
                ))

        # Form strategies — AI may return dicts or other shapes
        for fs in result.get("form_strategies", []):
            if isinstance(fs, dict):
                setup.form_strategies.append(FormStrategy(
                    form_action=fs.get("form_action", ""),
                    field_strategies=fs.get("field_strategies", {}),
                ))

        waf = result.get("waf_info", "")
        setup.waf_detected = waf if isinstance(waf, str) else str(waf)
        return setup
