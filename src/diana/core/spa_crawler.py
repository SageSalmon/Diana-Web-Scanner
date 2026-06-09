"""SPA crawler — uses Playwright to render JavaScript and discover dynamic content.

Complements the HTTP crawler by:
1. Extracting client-side routes from JS bundles (Angular, React, Vue)
2. Navigating hash/history routes in a headless browser
3. Testing DOM XSS by injecting payloads into URL parameters in rendered context
4. Discovering forms and inputs only visible after JS execution
"""

from __future__ import annotations

import logging
import re
import uuid
from urllib.parse import quote, urljoin

from diana.core.http_client import ScopedHTTPClient
from diana.core.models import Endpoint, Finding, Form, FormField, Severity, SiteMap, VulnType

logger = logging.getLogger(__name__)

# Route definition patterns across major SPA frameworks
ROUTE_PATTERNS = [
    # Angular: path: "search", path: "admin"
    r'path:\s*["\']([a-zA-Z][a-zA-Z0-9/_:-]*)["\']',
    # React Router: path="/search", path: "/admin"
    r'path[=:]\s*["\']/?([a-zA-Z][a-zA-Z0-9/_:-]*)["\']',
    # Vue Router: path: '/search'
    r'path:\s*["\']/?([a-zA-Z][a-zA-Z0-9/_:-]*)["\']',
    # Generic: route("/search"), navigate("/admin")
    r'(?:route|navigate|push|replace)\s*\(\s*["\']/?([a-zA-Z][a-zA-Z0-9/_:-]*)["\']',
]

# DOM XSS payloads
DOM_XSS_PAYLOADS = [
    '<iframe src="javascript:alert(`xss`)">',
    '<img src=x onerror=alert(`xss`)>',
    '<svg onload=alert(`xss`)>',
]


class SPACrawler:
    """Discovers and tests SPA routes using Playwright headless browser."""

    def __init__(self, http: ScopedHTTPClient):
        self.http = http

    async def discover_routes(self, sitemap: SiteMap) -> list[str]:
        """Extract client-side routes from JS bundles."""
        routes: set[str] = set()

        # Scan all discovered JS files
        for js_url in sitemap.static_files:
            if not js_url.endswith((".js", ".mjs")):
                continue
            try:
                resp = await self.http.get(js_url)
                if resp.status_code == 200:
                    routes.update(self._extract_routes(resp.text))
            except Exception:
                continue

        # Also scan the main page
        try:
            resp = await self.http.get(sitemap.base_url)
            if resp.status_code == 200:
                routes.update(self._extract_routes(resp.text))
        except Exception:
            pass

        # Filter out framework internals and wildcards
        filtered = []
        skip = {"**", "", "engine.io", "socket.io", "403", "404", "500"}
        for route in sorted(routes):
            if route in skip:
                continue
            if route.startswith((":", "*")):
                continue
            # Skip parameterized segments for now (e.g., "order-completion/:id")
            clean = route.split(":")[0].rstrip("/")
            if clean and clean not in skip:
                filtered.append(clean)

        return list(set(filtered))

    async def crawl_routes(self, base_url: str, routes: list[str], max_routes: int = 15) -> list[Endpoint]:
        """Navigate to high-value discovered routes with Playwright and extract content.

        Only visits routes likely to have user input (search, login, forms, etc.)
        to avoid overwhelming the target. Capped at max_routes.
        """
        from playwright.async_api import async_playwright

        endpoints: list[Endpoint] = []
        base = base_url.rstrip("/")

        # Prioritize routes likely to have injectable inputs
        input_keywords = [
            "search", "login", "register", "contact", "feedback", "complain",
            "forgot", "change-password", "track", "recycle", "profile", "admin",
        ]
        priority = [r for r in routes if any(kw in r.lower() for kw in input_keywords)]
        others = [r for r in routes if r not in priority]
        ordered = (priority + others)[:max_routes]

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                for route in ordered:
                    url = f"{base}/#{route}" if not route.startswith("/") else f"{base}#{route}"

                    try:
                        await page.goto(url, wait_until="networkidle", timeout=10000)
                        html = await page.content()

                        # Extract forms from rendered page
                        forms = await self._extract_rendered_forms(page, url)

                        # Check for inputs that could accept injection
                        inputs = await page.query_selector_all(
                            'input:not([type="hidden"]):not([type="submit"]), textarea, select'
                        )

                        params = {}
                        for inp in inputs:
                            name = await inp.get_attribute("name") or await inp.get_attribute("id") or ""
                            input_type = await inp.get_attribute("type") or "text"
                            if name:
                                params[name] = ""

                        endpoints.append(Endpoint(
                            url=url,
                            method="GET",
                            parameters=params,
                        ))

                    except Exception as e:
                        logger.debug("Failed to crawl route %s: %s", route, e)
                        continue

                await browser.close()
        except Exception as e:
            logger.warning("Playwright crawl failed: %s", e)

        return endpoints

    async def test_dom_xss(self, base_url: str, routes: list[str]) -> list[Finding]:
        """Test DOM XSS by injecting payloads into URL search parameters.

        Navigates to routes like /#/search?q=<payload> and checks if the
        payload executes in the rendered DOM.
        """
        from playwright.async_api import async_playwright

        findings: list[Finding] = []
        base = base_url.rstrip("/")

        # Routes likely to reflect input in the DOM
        search_routes = [r for r in routes if any(
            kw in r.lower() for kw in ["search", "track", "find", "query"]
        )]

        if not search_routes:
            return findings

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)

                for route in search_routes:
                    for payload in DOM_XSS_PAYLOADS:
                        page = await browser.new_page()
                        encoded = quote(payload)
                        url = f"{base}/#{route}?q={encoded}"

                        dialog_fired = False

                        async def handle_dialog(dialog):
                            nonlocal dialog_fired
                            dialog_fired = True
                            await dialog.dismiss()

                        page.on("dialog", handle_dialog)

                        try:
                            await page.goto(url, wait_until="networkidle", timeout=10000)
                            # Small wait for any deferred JS execution
                            await page.wait_for_timeout(1000)
                        except Exception:
                            await page.close()
                            continue

                        if dialog_fired:
                            findings.append(Finding(
                                id=f"DOMXSS-{uuid.uuid4().hex[:8]}",
                                vuln_type=VulnType.XSS_DOM,
                                severity=Severity.HIGH,
                                title=f"DOM XSS at /{route}",
                                description=(
                                    f"DOM-based XSS triggered via URL parameter on "
                                    f"the /{route} route. User input is rendered into "
                                    f"the DOM without sanitization."
                                ),
                                endpoint=Endpoint(url=f"{base}/#{route}", method="GET",
                                                  parameters={"q": ""}),
                                evidence=f"Payload triggered alert dialog: {payload}",
                                payload_used=payload,
                                cwe_id="CWE-79",
                                remediation=(
                                    "Sanitize user input before inserting into the DOM. "
                                    "Use framework-provided sanitization (Angular DomSanitizer, "
                                    "React's JSX escaping, etc.)."
                                ),
                                confirmed=True,
                            ))
                            await page.close()
                            break  # One finding per route is enough

                        # Also check if payload is reflected in DOM without dialog
                        html = await page.content()
                        if payload in html:
                            findings.append(Finding(
                                id=f"DOMXSS-{uuid.uuid4().hex[:8]}",
                                vuln_type=VulnType.XSS_DOM,
                                severity=Severity.HIGH,
                                title=f"DOM XSS (reflected) at /{route}",
                                description=(
                                    f"XSS payload reflected in rendered DOM on /{route}. "
                                    f"User input from URL is inserted into the page without encoding."
                                ),
                                endpoint=Endpoint(url=f"{base}/#{route}", method="GET",
                                                  parameters={"q": ""}),
                                evidence=f"Payload found in rendered HTML",
                                payload_used=payload,
                                cwe_id="CWE-79",
                                remediation="Sanitize user input before DOM insertion.",
                                confirmed=True,
                            ))
                            await page.close()
                            break

                        await page.close()

                await browser.close()
        except Exception as e:
            logger.warning("DOM XSS testing failed: %s", e)

        return findings

    def _extract_routes(self, js_body: str) -> set[str]:
        """Extract client-side route definitions from JavaScript source."""
        routes: set[str] = set()
        for pattern in ROUTE_PATTERNS:
            matches = re.findall(pattern, js_body)
            routes.update(matches)
        return routes

    async def _extract_rendered_forms(self, page, page_url: str) -> list[Form]:
        """Extract forms from the rendered (post-JS) page."""
        forms: list[Form] = []

        form_elements = await page.query_selector_all("form")
        for form_el in form_elements:
            action = await form_el.get_attribute("action") or page_url
            method = (await form_el.get_attribute("method") or "POST").upper()

            fields: list[FormField] = []
            inputs = await form_el.query_selector_all("input, textarea, select")
            for inp in inputs:
                name = await inp.get_attribute("name") or await inp.get_attribute("id") or ""
                if not name:
                    continue
                field_type = await inp.get_attribute("type") or "text"
                required = await inp.get_attribute("required") is not None
                fields.append(FormField(name=name, field_type=field_type, required=required))

            if fields:
                forms.append(Form(action=action, method=method, fields=fields, page_url=page_url))

        return forms
