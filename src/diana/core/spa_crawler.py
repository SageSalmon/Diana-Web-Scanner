"""SPA crawler — uses Playwright to render JavaScript and discover dynamic content.

Complements the HTTP crawler by:
1. Extracting client-side routes from JS bundles (Angular, React, Vue)
2. Navigating hash/history routes in a headless browser
3. Testing DOM XSS by injecting payloads into URL parameters in rendered context
4. Discovering forms and inputs only visible after JS execution
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from urllib.parse import parse_qs, quote, urlsplit

from diana.core.http_client import ScopedHTTPClient
from diana.core.models import Endpoint, Finding, Form, FormField, Severity, SiteMap, VulnType

logger = logging.getLogger(__name__)

# Request methods whose JSON bodies we capture for input-validation fuzzing.
BODY_METHODS = {"POST", "PUT", "PATCH"}


def _benign_value(field_type: str, name: str) -> str:
    """A plausible, valid value for a form field so submission succeeds and the
    resulting XHR fires. Generic by field type/name — no target-specific values."""
    ft = (field_type or "").lower()
    n = (name or "").lower()
    if ft == "email" or "email" in n:
        return "diana.test@example.com"
    if ft == "password" or "password" in n or "passwd" in n:
        return "DianaTest123!"
    numeric_hints = ("amount", "qty", "quantity", "count", "rating", "stars")
    if ft == "number" or any(k in n for k in numeric_hints):
        return "1"
    if ft in ("url", "tel", "search"):
        return "diana-test"
    return "diana-test"


def _capture_json_body(
    method: str, url: str, post_data: str | None, base_origin: str,
) -> tuple[tuple[str, str], dict] | None:
    """Decide whether an observed request carries a JSON object body worth
    keeping, and if so return ((METHOD, url-without-query), body).

    Returns None for non-body methods, out-of-scope origins, empty/non-JSON
    bodies, or JSON that isn't a non-empty object. Pure function — unit-tested
    directly so the live request listener stays a thin wrapper.
    """
    method = (method or "").upper()
    if method not in BODY_METHODS:
        return None
    if _origin_of(url) != base_origin:
        return None
    if not post_data:
        return None
    try:
        body = json.loads(post_data)
    except (ValueError, TypeError):
        return None
    if not isinstance(body, dict) or not body:
        return None
    return (method, url.split("?", 1)[0]), body


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"

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

# Route-name substrings that suggest the page echoes a URL parameter back into
# the rendered DOM (search boxes, result/tracking/detail views). Generic across
# SPA frameworks — matched case-insensitively against the route path.
REFLECTION_ROUTE_KEYWORDS = [
    "search", "track", "find", "query", "result", "lookup",
    "view", "show", "detail", "product", "order", "page",
]

# Ubiquitous reflection parameter names, used as a fallback/supplement to the
# names actually observed during the crawl. NOT tuned to any target — these are
# the conventional query keys apps use for reflected input across the web.
COMMON_REFLECTION_PARAMS = ["q", "query", "search", "id", "term", "keyword", "s", "name"]

# Bounds for the browser-driven DOM-XSS param sweep. Each probe is a full page
# render, so the route x param x payload space is capped; overflow is logged,
# never silently dropped.
MAX_DOM_XSS_ROUTES = 12
MAX_DOM_XSS_PARAMS = 6


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

    @staticmethod
    def _parse_hashroute_params(href: str) -> tuple[str, list[str]] | None:
        """Extract ``(route, [param_names])`` from an in-app hash-route link.

        SPA links like ``#/track-result?id=5`` or ``/#/search?q=x`` carry the
        query params the destination route actually reads. Capturing those names
        turns a bare route into a *parameterized* endpoint, so the DOM-XSS sweep
        can probe the real reflecting key instead of guessing. Returns None for
        links without a hash fragment or query string. Generic across
        frameworks — keyed on URL shape, never on a specific route or param.
        """
        if not href or "#" not in href:
            return None
        fragment = href.split("#", 1)[1]
        if "?" not in fragment:
            return None
        path, query = fragment.split("?", 1)
        route = path.strip("/").split("/")[0]
        if not route:
            return None
        names = list(parse_qs(query, keep_blank_values=True).keys())
        if not names:
            return None
        return route, names

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

        # Captured JSON request bodies from XHR/fetch traffic, keyed by
        # (METHOD, url-without-query) so we keep one example per endpoint.
        captured_bodies: dict[tuple[str, str], dict] = {}
        base_origin = _origin_of(base_url)

        # Parameterized hash routes discovered from in-app links, keyed by route
        # so param names accumulate across pages (one endpoint per route).
        route_params: dict[str, set[str]] = {}

        def _on_request(request) -> None:
            try:
                result = _capture_json_body(
                    request.method, request.url, request.post_data, base_origin,
                )
                if result:
                    key, body = result
                    captured_bodies.setdefault(key, body)
            except Exception:
                return  # never let a captured request break the crawl

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                page.on("request", _on_request)

                for route in ordered:
                    url = f"{base}/#{route}" if not route.startswith("/") else f"{base}#{route}"

                    try:
                        await page.goto(url, wait_until="networkidle", timeout=10000)

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

                        # Capture parameterized hash-route links so the reflecting
                        # param names enter the sitemap (generic — any SPA that
                        # links to `#/route?key=value`).
                        try:
                            anchors = await page.query_selector_all("a[href]")
                            for a in anchors:
                                href = await a.get_attribute("href") or ""
                                parsed = self._parse_hashroute_params(href)
                                if parsed:
                                    r_name, r_params = parsed
                                    route_params.setdefault(r_name, set()).update(r_params)
                        except Exception:
                            pass

                        # Best-effort: fill visible inputs with benign values and
                        # submit, so the SPA issues its create/update XHR and we
                        # observe the request body. Generic across frameworks.
                        await self._fill_and_submit(page)

                    except Exception as e:
                        logger.debug("Failed to crawl route %s: %s", route, e)
                        continue

                await browser.close()
        except Exception as e:
            logger.warning("Playwright crawl failed: %s", e)

        # Turn captured XHR bodies into POST/PUT endpoints for the
        # input-validation module to replay and mutate.
        for (method, body_url), body in captured_bodies.items():
            endpoints.append(Endpoint(
                url=body_url,
                method=method,
                request_body=body,
            ))

        # Emit one parameterized endpoint per hash route discovered from links.
        for r_name, r_params in route_params.items():
            endpoints.append(Endpoint(
                url=f"{base}/#/{r_name}",
                method="GET",
                parameters={name: "" for name in sorted(r_params)},
            ))

        return endpoints

    async def _fill_and_submit(self, page) -> None:
        """Fill visible form fields with benign values and submit each form,
        triggering its XHR so the request body is observed. Bounded and
        best-effort — failures on any single form are ignored."""
        try:
            forms = await page.query_selector_all("form")
        except Exception:
            return

        for form_el in forms[:5]:  # cap interaction per page
            try:
                inputs = await form_el.query_selector_all(
                    'input:not([type="hidden"]):not([type="submit"]):not([type="button"]), textarea'
                )
                filled = False
                for inp in inputs:
                    name = (await inp.get_attribute("name")
                            or await inp.get_attribute("id")
                            or await inp.get_attribute("formcontrolname") or "")
                    field_type = await inp.get_attribute("type") or "text"
                    try:
                        await inp.fill(_benign_value(field_type, name), timeout=1000)
                        filled = True
                    except Exception:
                        continue
                if not filled:
                    continue

                # Try a real submit control first, then fall back to Enter.
                submit = await form_el.query_selector(
                    'button[type="submit"], input[type="submit"], button:not([type])'
                )
                if submit:
                    await submit.click(timeout=1000, no_wait_after=True)
                else:
                    await inputs[-1].press("Enter", timeout=1000, no_wait_after=True)

                # Give the XHR a moment to fire and be captured.
                await page.wait_for_timeout(500)
            except Exception:
                continue

    @staticmethod
    def _dom_candidate_params(observed_params: set[str] | None) -> list[str]:
        """Ordered, de-duplicated param names to probe for DOM reflection.

        Priority, highest signal first:
          1. names *observed* in the crawl that are also conventional reflection
             keys (the app demonstrably uses them, and they're the usual sinks),
          2. the remaining *observed* names (real app parameters — still far
             better evidence than a guess),
          3. conventional keys never seen in the crawl (a pure fallback so the
             sweep still fires on apps whose reflecting endpoint wasn't crawled).

        Observed names lead throughout, so probing is target-driven rather than a
        blind guess; the common-key fallback only fills leftover capacity. Every
        tier can reach the output, so the cap never turns a tier into dead code.
        Sorted within the observed tier for deterministic ordering. Capped at
        ``MAX_DOM_XSS_PARAMS``.
        """
        observed = sorted({(n or "").strip() for n in (observed_params or set())})
        observed_lower = {n.lower() for n in observed if n}

        ordered: list[str] = []
        seen: set[str] = set()

        def add(name: str) -> None:
            key = name.lower()
            if name and key not in seen:
                ordered.append(name)
                seen.add(key)

        for name in COMMON_REFLECTION_PARAMS:  # tier 1: observed ∩ common
            if name in observed_lower:
                add(name)
        for name in observed:                  # tier 2: other observed
            add(name)
        for name in COMMON_REFLECTION_PARAMS:  # tier 3: common-key fallback
            add(name)

        return ordered[:MAX_DOM_XSS_PARAMS]

    async def _probe_dom_reflection(
        self, browser, base: str, route: str, param: str, payload: str,
    ) -> Finding | None:
        """Render ``#/route?param=<payload>`` and report a finding if the payload
        executes (dialog) or lands unencoded in the rendered DOM."""
        page = await browser.new_page()
        url = f"{base}/#{route}?{param}={quote(payload)}"

        dialog_fired = False

        async def handle_dialog(dialog):
            nonlocal dialog_fired
            dialog_fired = True
            await dialog.dismiss()

        page.on("dialog", handle_dialog)

        try:
            await page.goto(url, wait_until="networkidle", timeout=10000)
            await page.wait_for_timeout(1000)  # let deferred JS run
            html = await page.content()
        except Exception:
            await page.close()
            return None

        endpoint = Endpoint(
            url=f"{base}/#{route}", method="GET", parameters={param: ""},
        )
        finding: Finding | None = None
        if dialog_fired:
            finding = Finding(
                id=f"DOMXSS-{uuid.uuid4().hex[:8]}",
                vuln_type=VulnType.XSS_REFLECTED,
                severity=Severity.HIGH,
                title=f"Reflected XSS via URL parameter '{param}' at /{route}",
                description=(
                    f"A payload placed in the '{param}' URL parameter on the "
                    f"/{route} route executed in the rendered page. Client-side "
                    f"code reads the parameter and injects it into the DOM "
                    f"without sanitization."
                ),
                endpoint=endpoint,
                evidence=f"Payload triggered alert dialog: {payload}",
                payload_used=payload,
                cwe_id="CWE-79",
                remediation=(
                    "Sanitize user input before inserting into the DOM. Use "
                    "framework-provided sanitization (Angular DomSanitizer, "
                    "React's JSX escaping, etc.)."
                ),
                confirmed=True,
            )
        elif payload in html:
            finding = Finding(
                id=f"DOMXSS-{uuid.uuid4().hex[:8]}",
                vuln_type=VulnType.XSS_REFLECTED,
                severity=Severity.HIGH,
                title=f"Reflected XSS via URL parameter '{param}' at /{route}",
                description=(
                    f"A payload placed in the '{param}' URL parameter on the "
                    f"/{route} route was reflected unencoded into the rendered "
                    f"DOM. Client-side code inserts the parameter into the page "
                    f"without encoding."
                ),
                endpoint=endpoint,
                evidence="Payload found unencoded in rendered HTML",
                payload_used=payload,
                cwe_id="CWE-79",
                remediation="Sanitize user input before DOM insertion.",
                confirmed=True,
            )

        await page.close()
        return finding

    async def test_dom_xss(
        self,
        base_url: str,
        routes: list[str],
        observed_params: set[str] | None = None,
    ) -> list[Finding]:
        """Test client-side reflected/DOM XSS by injecting payloads into URL
        parameters of rendered SPA routes.

        Navigates to ``/#/route?param=<payload>`` for each reflection-likely
        route and each candidate parameter name, checking whether the payload
        executes or is reflected unencoded in the DOM. Sweeping the parameter
        names (not just a hardcoded ``q``) is what lets it reach reflectors keyed
        on other names — an order-tracking view echoing ``id``, a profile view
        echoing ``name`` — while staying framework-agnostic.
        """
        from playwright.async_api import async_playwright

        findings: list[Finding] = []
        base = base_url.rstrip("/")

        # Routes whose name suggests they echo a URL parameter into the DOM.
        search_routes = [
            r for r in routes
            if any(kw in r.lower() for kw in REFLECTION_ROUTE_KEYWORDS)
        ]
        if not search_routes:
            return findings

        if len(search_routes) > MAX_DOM_XSS_ROUTES:
            logger.info(
                "DOM-XSS sweep capped at %d of %d candidate routes",
                MAX_DOM_XSS_ROUTES, len(search_routes),
            )
            search_routes = search_routes[:MAX_DOM_XSS_ROUTES]

        candidate_params = self._dom_candidate_params(observed_params)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)

                for route in search_routes:
                    hit = False
                    for param in candidate_params:
                        for payload in DOM_XSS_PAYLOADS:
                            finding = await self._probe_dom_reflection(
                                browser, base, route, param, payload,
                            )
                            if finding:
                                findings.append(finding)
                                hit = True
                                break  # one payload per param
                        if hit:
                            break  # one finding per route is enough

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
