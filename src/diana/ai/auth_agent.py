"""Auth Agent — AI-driven login discovery and session capture.

Uses Playwright (headless browser) + Bedrock AI to:
1. Discover the login page/form on the target
2. Identify form fields (username, password, CSRF tokens)
3. Execute the login with provided credentials
4. Capture the resulting session (cookies, JWT, bearer tokens)
5. Inject the session into the HTTP client for authenticated scanning
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

from diana.ai.bedrock import BedrockClient
from diana.engagement.models import CredentialConfig

logger = logging.getLogger(__name__)

AUTH_DISCOVERY_PROMPT = """Analyze this web page HTML and identify the login mechanism.

Page URL: {url}
Page HTML (truncated):
{html}

Determine:
1. Is this a login page? If not, where is the login page likely located?
2. What type of login is it? (form POST, SPA/AJAX, OAuth redirect, Basic Auth)
3. What are the form field names for username and password?
4. Is there a CSRF token field? If so, what is the field name?
5. What is the form action URL?
6. Are there any additional required fields (hidden inputs, etc.)?

Respond as JSON:
{{
  "is_login_page": bool,
  "login_url_hint": "URL if this isn't the login page",
  "login_type": "form|spa|oauth|basic",
  "form_action": "URL the form posts to",
  "username_field": "field name",
  "password_field": "field name",
  "csrf_field": "field name or null",
  "additional_fields": {{"name": "value"}},
  "submit_selector": "CSS selector for submit button"
}}"""

SESSION_ANALYSIS_PROMPT = """Analyze the HTTP response after a login attempt and determine if authentication was successful.

Request: {method} {url}
Response Status: {status}
Response Headers:
{headers}

Response Body (truncated):
{body}

Cookies Set:
{cookies}

Determine:
1. Was the login successful?
2. What session mechanism is being used? (cookie, JWT in body, bearer token, etc.)
3. What is the session token name and value?
4. Are there any redirect URLs that indicate success/failure?

Respond as JSON:
{{
  "success": bool,
  "reason": "why you think it succeeded or failed",
  "session_type": "cookie|jwt|bearer|other",
  "session_token_name": "name of the cookie or token field",
  "session_token_value": "the token value if visible",
  "redirect_url": "URL if redirected after login"
}}"""


@dataclass
class AuthSession:
    """Captured authentication session."""
    authenticated: bool = False
    session_type: str = ""  # cookie, jwt, bearer
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)  # Authorization headers
    token: str = ""
    login_url: str = ""
    username_field: str = ""
    password_field: str = ""


@dataclass
class LoginForm:
    """Discovered login form structure."""
    url: str = ""
    action: str = ""
    method: str = "POST"
    username_field: str = ""
    password_field: str = ""
    csrf_field: str = ""
    csrf_value: str = ""
    additional_fields: dict[str, str] = field(default_factory=dict)
    submit_selector: str = ""
    login_type: str = "form"  # form, spa, oauth, basic


class AuthAgent:
    """AI-driven authentication agent.

    Discovers login flows and captures sessions for authenticated scanning.
    Supports three modes:
    1. Playwright (headless browser) — for SPAs and JS-rendered login forms
    2. HTTP-only — for traditional form POSTs
    3. Pre-configured — skip discovery, use provided token
    """

    # Common login page paths to probe
    LOGIN_PATHS = [
        "/login", "/signin", "/sign-in", "/auth", "/authenticate",
        "/account/login", "/user/login", "/admin/login",
        "/api/login", "/rest/user/login",
        "/#/login", "/#/signin",  # SPA hash routes
    ]

    def __init__(self, bedrock: BedrockClient | None = None, enforcer=None):
        self.bedrock = bedrock
        self.enforcer = enforcer

    def _check_scope(self, url: str, method: str = "GET") -> None:
        """Check URL against engagement scope if enforcer is available."""
        if self.enforcer:
            self.enforcer.check_request(url, method)

    async def authenticate(
        self,
        base_url: str,
        credentials: CredentialConfig,
    ) -> AuthSession:
        """Discover the login flow and authenticate.

        Returns an AuthSession with cookies/headers to inject into the HTTP client.
        """
        # If a token is pre-configured, skip discovery entirely
        if credentials.token:
            logger.info("Using pre-configured token")
            return AuthSession(
                authenticated=True,
                session_type="bearer",
                headers={"Authorization": f"Bearer {credentials.token}"},
                token=credentials.token,
            )

        if not credentials.username or not credentials.password:
            logger.info("No credentials provided — scanning unauthenticated")
            return AuthSession()

        # Try HTTP API login first (faster, works for REST APIs)
        # Fall back to Playwright for traditional form-based sites
        session = await self._authenticate_http(base_url, credentials)
        if session.authenticated:
            return session

        logger.info("HTTP login failed — trying Playwright browser login")
        try:
            return await self._authenticate_playwright(base_url, credentials)
        except Exception as e:
            logger.warning("Playwright auth also failed: %s", e)
            return AuthSession()

    async def _authenticate_playwright(
        self,
        base_url: str,
        credentials: CredentialConfig,
    ) -> AuthSession:
        """Use Playwright headless browser to discover and execute login."""
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            # Step 1: Find the login page
            login_url = credentials.login_url
            if not login_url:
                login_url = await self._discover_login_page(page, base_url)

            if not login_url:
                logger.warning("Could not discover login page")
                await browser.close()
                return AuthSession()

            logger.info("Login page found: %s", login_url)

            # Step 2: Navigate to login page and analyze the form
            await page.goto(login_url, wait_until="networkidle", timeout=15000)
            html = await page.content()
            login_form = await self._analyze_login_form(login_url, html)

            if not login_form.username_field:
                logger.warning("Could not identify login form fields")
                await browser.close()
                return AuthSession()

            # Step 3: Fill and submit the form
            logger.info(
                "Filling login form: username=%s, password=%s",
                login_form.username_field, login_form.password_field
            )

            try:
                # Fill username — try multiple selectors, visible only
                await self._fill_field(
                    page, credentials.username,
                    login_form.username_field, fallback_type="email",
                )

                # Fill password
                await self._fill_field(
                    page, credentials.password,
                    login_form.password_field, fallback_type="password",
                )

                # Submit
                submit_selectors = [
                    login_form.submit_selector,
                    'button[type="submit"]',
                    'input[type="submit"]',
                    'button:has-text("Login")',
                    'button:has-text("Log in")',
                    'button:has-text("Sign in")',
                    'button[id*="login"]',
                    'button[id*="submit"]',
                ]
                for selector in submit_selectors:
                    if not selector:
                        continue
                    btn = page.locator(selector).first
                    if await btn.is_visible(timeout=1000):
                        await btn.click()
                        break

                # Wait for navigation/response
                await page.wait_for_load_state("networkidle", timeout=10000)

            except Exception as e:
                logger.warning("Form interaction failed: %s", e)
                await browser.close()
                return AuthSession()

            # Step 4: Capture session
            cookies = await context.cookies()
            session = AuthSession(
                login_url=login_url,
                username_field=login_form.username_field,
                password_field=login_form.password_field,
            )

            # Capture cookies
            for cookie in cookies:
                session.cookies[cookie["name"]] = cookie["value"]

            # Check for JWT in localStorage or response
            try:
                token = await page.evaluate(
                    "localStorage.getItem('token') || "
                    "sessionStorage.getItem('token') || "
                    "localStorage.getItem('access_token') || "
                    "sessionStorage.getItem('access_token') || ''"
                )
                if token:
                    session.token = token
                    session.session_type = "jwt"
                    session.headers["Authorization"] = f"Bearer {token}"
                    session.authenticated = True
                    logger.info("Captured JWT from browser storage")
            except Exception:
                pass

            # If no JWT, check if cookies indicate success
            if not session.authenticated and session.cookies:
                session.session_type = "cookie"
                session.authenticated = True
                logger.info("Captured %d session cookies", len(session.cookies))

            # Verify with AI if available
            if self.bedrock and session.authenticated:
                page_html = await page.content()
                verified = await self._verify_login_success(page_html, page.url)
                if not verified:
                    logger.warning("AI could not verify login success — proceeding anyway")

            await browser.close()
            return session

    async def _authenticate_http(
        self,
        base_url: str,
        credentials: CredentialConfig,
    ) -> AuthSession:
        """HTTP-only authentication for simple form POSTs and API logins."""
        import httpx

        login_url = credentials.login_url
        if not login_url:
            # Try common API login endpoints
            for path in ["/rest/user/login", "/api/login", "/auth/login", "/login"]:
                login_url = f"{base_url.rstrip('/')}{path}"
                try:
                    self._check_scope(login_url, "POST")
                    async with httpx.AsyncClient(verify=False, timeout=10) as client:
                        resp = await client.post(
                            login_url,
                            json={"email": credentials.username, "password": credentials.password},
                        )
                        if resp.status_code == 200:
                            body = resp.json() if "json" in resp.headers.get("content-type", "") else {}
                            token = (
                                body.get("authentication", {}).get("token")
                                or body.get("token")
                                or body.get("access_token")
                                or ""
                            )
                            if token:
                                logger.info("HTTP API login successful at %s", login_url)
                                return AuthSession(
                                    authenticated=True,
                                    session_type="jwt",
                                    token=token,
                                    headers={"Authorization": f"Bearer {token}"},
                                    login_url=login_url,
                                    cookies={k: v for k, v in resp.cookies.items()},
                                )

                            # Check cookies
                            if resp.cookies:
                                logger.info("HTTP login successful at %s (cookies)", login_url)
                                return AuthSession(
                                    authenticated=True,
                                    session_type="cookie",
                                    cookies={k: v for k, v in resp.cookies.items()},
                                    login_url=login_url,
                                )
                except Exception:
                    continue

            # Try form POST
            for path in ["/login", "/signin", "/auth"]:
                login_url = f"{base_url.rstrip('/')}{path}"
                try:
                    self._check_scope(login_url, "POST")
                    async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
                        resp = await client.post(
                            login_url,
                            data={"username": credentials.username, "password": credentials.password},
                        )
                        if resp.cookies:
                            return AuthSession(
                                authenticated=True,
                                session_type="cookie",
                                cookies={k: v for k, v in resp.cookies.items()},
                                login_url=login_url,
                            )
                except Exception:
                    continue

        return AuthSession()

    async def _discover_login_page(self, page, base_url: str) -> str | None:
        """Navigate the target and find the login page."""
        base = base_url.rstrip("/")

        # Try common login paths
        for path in self.LOGIN_PATHS:
            url = f"{base}{path}"
            try:
                resp = await page.goto(url, wait_until="networkidle", timeout=10000)
                if resp and resp.status == 200:
                    html = await page.content()
                    # Quick check: does this page have password input?
                    if 'type="password"' in html or "type='password'" in html:
                        return url
            except Exception:
                continue

        # Try navigating to the base and looking for login links
        try:
            await page.goto(base_url, wait_until="networkidle", timeout=10000)
            login_link = await page.query_selector(
                'a[href*="login"], a[href*="signin"], '
                'a:has-text("Login"), a:has-text("Sign in"), '
                'button:has-text("Login"), button:has-text("Sign in")'
            )
            if login_link:
                await login_link.click()
                await page.wait_for_load_state("networkidle", timeout=10000)
                html = await page.content()
                if 'type="password"' in html:
                    return page.url
        except Exception:
            pass

        return None

    async def _analyze_login_form(self, url: str, html: str) -> LoginForm:
        """Use AI to analyze the login page and identify form fields."""
        form = LoginForm(url=url)

        # Try AI analysis first
        if self.bedrock:
            try:
                truncated_html = html[:5000]
                prompt = AUTH_DISCOVERY_PROMPT.format(url=url, html=truncated_html)
                result = self.bedrock.invoke_json(prompt)

                form.action = result.get("form_action", "")
                form.username_field = result.get("username_field", "")
                form.password_field = result.get("password_field", "")
                form.csrf_field = result.get("csrf_field", "") or ""
                form.additional_fields = result.get("additional_fields", {}) or {}
                form.submit_selector = result.get("submit_selector", "")
                form.login_type = result.get("login_type", "form")

                if form.username_field and form.password_field:
                    logger.info("AI identified login form: user=%s pass=%s",
                                form.username_field, form.password_field)
                    return form
            except Exception as e:
                logger.warning("AI login analysis failed: %s", e)

        # Fallback: heuristic extraction
        form.username_field = self._find_field(html, ["email", "username", "user", "login"])
        form.password_field = self._find_field(html, ["password", "passwd", "pass"])
        form.csrf_field = self._find_field(html, ["csrf", "_token", "csrfmiddlewaretoken"])

        return form

    async def _verify_login_success(self, html: str, current_url: str) -> bool:
        """Use AI to verify if we're on an authenticated page after login."""
        if not self.bedrock:
            return True

        try:
            result = self.bedrock.invoke_json(
                f"Does this page appear to be an authenticated/logged-in state? "
                f"URL: {current_url}\n"
                f"HTML (truncated): {html[:3000]}\n\n"
                f"Respond as JSON: {{\"authenticated\": bool, \"reason\": str}}"
            )
            return result.get("authenticated", True)
        except Exception:
            return True

    @staticmethod
    async def _fill_field(
        page,
        value: str,
        field_name: str,
        fallback_type: str = "text",
    ) -> None:
        """Fill a form field, handling SPA frameworks (Angular Material, etc.)

        Tries multiple strategies:
        1. Direct selector by name/id (visible only)
        2. Fallback to input type
        3. Click the field wrapper first to activate it, then type
        """
        # Strategy 1: direct selectors, visible only
        selectors = [
            f'input[name="{field_name}"]:visible',
            f'input[id="{field_name}"]:visible',
            f'input[id*="{field_name}"]:visible',
            f'input[aria-label*="{field_name}" i]:visible',
            f'input[placeholder*="{field_name}" i]:visible',
        ]

        for selector in selectors:
            try:
                loc = page.locator(selector).first
                if await loc.is_visible(timeout=500):
                    await loc.fill(value, timeout=3000)
                    return
            except Exception:
                continue

        # Strategy 2: fallback to type (e.g. input[type="password"])
        try:
            loc = page.locator(f'input[type="{fallback_type}"]:visible').first
            if await loc.is_visible(timeout=500):
                await loc.fill(value, timeout=3000)
                return
        except Exception:
            pass

        # Strategy 3: click the container/label then type
        # SPA frameworks often hide the real input behind a wrapper
        label_selectors = [
            f'label:has-text("{field_name}") + * input:visible',
            f'mat-form-field:has(input[type="{fallback_type}"]) input:visible',
            f'div[class*="form"] input[type="{fallback_type}"]:visible',
        ]
        for selector in label_selectors:
            try:
                loc = page.locator(selector).first
                if await loc.is_visible(timeout=500):
                    await loc.click()
                    await loc.fill(value, timeout=3000)
                    return
            except Exception:
                continue

        # Strategy 4: just find any visible input of the right type and use keyboard
        try:
            if fallback_type == "password":
                loc = page.locator('input[type="password"]').first
            else:
                # For username, use the first non-hidden, non-password input
                loc = page.locator(
                    'input:not([type="password"]):not([type="hidden"]):not([type="submit"])'
                ).first
            await loc.click(timeout=3000)
            await page.keyboard.type(value)
        except Exception as e:
            logger.warning("Could not fill field %s: %s", field_name, e)

    @staticmethod
    def _find_field(html: str, keywords: list[str]) -> str:
        """Heuristic: find an input field matching keywords."""
        for kw in keywords:
            patterns = [
                rf'name=["\']({kw}[^"\']*)["\']',
                rf'id=["\']({kw}[^"\']*)["\']',
                rf'name=["\']([^"\']*{kw}[^"\']*)["\']',
            ]
            for pattern in patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    return match.group(1)
        return ""
