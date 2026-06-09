"""Intelligent web crawler with engagement scope enforcement."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from diana.core.http_client import ScopedHTTPClient
from diana.core.models import Endpoint, Form, FormField, SiteMap, TechStack
from diana.engagement.models import ScopeViolation


class Crawler:
    """Spider a target within engagement scope, building a sitemap of endpoints and forms."""

    def __init__(
        self,
        http_client: ScopedHTTPClient,
        max_depth: int = 3,
        max_pages: int = 500,
    ):
        self.http = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self._visited: set[str] = set()
        self._endpoints: list[Endpoint] = []
        self._forms: list[Form] = []
        self._static_files: list[str] = []
        self._external_links: list[str] = []
        self._tech_stack = TechStack()

    async def crawl(self, base_url: str) -> SiteMap:
        """Crawl the target starting from base_url."""
        self._visited.clear()
        await self._crawl_page(base_url, depth=0)
        await self._discover_api_endpoints(base_url)
        return SiteMap(
            base_url=base_url,
            endpoints=self._endpoints,
            forms=self._forms,
            tech_stack=self._tech_stack,
            static_files=self._static_files,
            external_links=self._external_links,
        )

    async def _crawl_page(self, url: str, depth: int) -> None:
        normalized = self._normalize_url(url)
        if normalized in self._visited or depth > self.max_depth:
            return
        if len(self._visited) >= self.max_pages:
            return

        self._visited.add(normalized)

        try:
            response = await self.http.get(url)
        except ScopeViolation:
            return
        except Exception:
            return

        content_type = response.headers.get("content-type", "")

        self._endpoints.append(Endpoint(
            url=url,
            method="GET",
            headers=dict(response.headers),
            content_type=content_type,
        ))

        if depth == 0:
            self._detect_tech_stack(response)

        if "text/html" not in content_type:
            return

        soup = BeautifulSoup(response.text, "lxml")
        self._extract_forms(soup, url)

        # Gather links for next level
        tasks = []
        for link in self._extract_links(soup, url):
            tasks.append(self._crawl_page(link, depth + 1))

        if tasks:
            await asyncio.gather(*tasks)

    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        links: list[str] = []
        base_parsed = urlparse(page_url)

        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            absolute = urljoin(page_url, href)
            parsed = urlparse(absolute)

            # Skip fragments, mailto, javascript, etc.
            if parsed.scheme not in ("http", "https"):
                continue

            # Track external links but don't crawl them
            if parsed.netloc != base_parsed.netloc:
                self._external_links.append(absolute)
                continue

            links.append(absolute)

        # Also extract from script src, link href for static assets
        for tag in soup.find_all("script", src=True):
            src = urljoin(page_url, tag["src"])
            self._static_files.append(src)

        for tag in soup.find_all("link", href=True):
            href = urljoin(page_url, tag["href"])
            self._static_files.append(href)

        return links

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> None:
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            action_url = urljoin(page_url, action) if action else page_url
            method = form_tag.get("method", "GET").upper()

            fields: list[FormField] = []
            for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name", "")
                if not name:
                    continue

                field_type = input_tag.get("type", "text")
                required = input_tag.has_attr("required")
                value = input_tag.get("value", "")

                options: list[str] = []
                if input_tag.name == "select":
                    options = [
                        opt.get("value", opt.text)
                        for opt in input_tag.find_all("option")
                    ]

                fields.append(FormField(
                    name=name,
                    field_type=field_type,
                    required=required,
                    value=value,
                    options=options,
                ))

            if fields:
                self._forms.append(Form(
                    action=action_url,
                    method=method,
                    fields=fields,
                    page_url=page_url,
                ))

                self._endpoints.append(Endpoint(
                    url=action_url,
                    method=method,
                    parameters={f.name: f.value for f in fields},
                ))

    def _detect_tech_stack(self, response: httpx.Response) -> None:
        import httpx as _httpx  # already imported at module level

        headers = response.headers
        body = response.text

        # Server header
        self._tech_stack.server = headers.get("server", "")

        # X-Powered-By
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            self._tech_stack.frameworks.append(powered_by)

        # Detect frameworks from HTML
        framework_patterns = {
            "React": [r"react", r"_reactRoot", r"__NEXT_DATA__"],
            "Angular": [r"ng-app", r"ng-version", r"angular"],
            "Vue.js": [r"vue", r"v-app", r"__vue__"],
            "jQuery": [r"jquery", r"jQuery"],
            "Django": [r"csrfmiddlewaretoken", r"django"],
            "Rails": [r"csrf-token.*authenticity", r"rails"],
            "Express": [],  # detected via headers
            "Spring": [r"JSESSIONID"],
            "ASP.NET": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
            "Laravel": [r"laravel_session", r"_token"],
        }

        for framework, patterns in framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    if framework not in self._tech_stack.frameworks:
                        self._tech_stack.frameworks.append(framework)
                    break

        # WAF detection from headers
        waf_signatures = {
            "cloudflare": "Cloudflare",
            "awselb": "AWS ALB/WAF",
            "akamai": "Akamai",
            "incapsula": "Imperva/Incapsula",
        }
        server_lower = self._tech_stack.server.lower()
        for sig, waf_name in waf_signatures.items():
            if sig in server_lower or sig in str(headers).lower():
                self._tech_stack.waf = waf_name
                break

    async def _discover_api_endpoints(self, base_url: str) -> None:
        """Probe for common REST API patterns and extract routes from JS bundles.

        SPAs hide their endpoints behind JavaScript — this pass finds them by:
        1. Scanning JS bundles for API path patterns and query/body params
        2. Probing common REST prefixes (/api, /rest, /graphql, etc.)
        3. Generating IDOR variants for collection endpoints
        """
        base = base_url.rstrip("/")

        # Collect all JS source for param extraction
        all_js = ""

        # Extract API routes from JavaScript bundles
        for js_url in self._static_files:
            if not js_url.endswith((".js", ".mjs")):
                continue
            try:
                resp = await self.http.get(js_url)
                if resp.status_code == 200:
                    all_js += resp.text + "\n"
                    self._extract_api_routes_from_js(resp.text, base)
            except Exception:
                continue

        # Also scan the main page body for API patterns
        try:
            resp = await self.http.get(base_url)
            if resp.status_code == 200:
                all_js += resp.text + "\n"
                self._extract_api_routes_from_js(resp.text, base)
        except Exception:
            pass

        # Second pass: extract query and body params from JS context
        if all_js:
            self._extract_params_from_js(all_js, base)

        # Probe common API prefixes
        api_prefixes = [
            "/api", "/rest", "/graphql", "/v1", "/v2",
            "/api/v1", "/api/v2", "/rest/v1",
        ]
        for prefix in api_prefixes:
            url = f"{base}{prefix}"
            if url in self._visited:
                continue
            try:
                resp = await self.http.get(url)
                if resp.status_code in (200, 401, 403):
                    content_type = resp.headers.get("content-type", "")
                    if "json" in content_type or resp.text.strip().startswith(("{", "[")):
                        self._endpoints.append(Endpoint(
                            url=url, method="GET", content_type=content_type,
                        ))
            except Exception:
                continue

        # Generate IDOR variants for collection endpoints
        await self._generate_idor_endpoints(base)

    def _extract_api_routes_from_js(self, js_body: str, base_url: str) -> None:
        """Extract API endpoint paths from JavaScript source code."""
        # Match paths in single quotes, double quotes, AND backtick template literals
        # Backticks are critical — modern JS uses template literals for API URLs:
        #   `${host}/rest/products/search?q=${query}`
        api_patterns = re.findall(
            r'["\'`](/(?:api|rest|graphql|v[0-9])[/\w.-]*(?:\?[^"\'`$]*)?)["\'\s`$]',
            js_body,
        )

        seen = set()
        for path in api_patterns:
            # Skip obvious non-endpoints
            if any(ext in path for ext in [".js", ".css", ".map", ".html", ".svg"]):
                continue
            if path in seen:
                continue
            seen.add(path)

            # Split path and query string
            params = {}
            clean_path = path
            if "?" in path:
                clean_path, query = path.split("?", 1)
                for pair in query.split("&"):
                    if "=" in pair:
                        key = pair.split("=")[0]
                        params[key] = "test"
                    else:
                        params[pair] = "test"

            url = f"{base_url}{clean_path}"

            # Detect if path has an ID-like segment — add as parameterized
            if re.search(r'/\d+(/|$)', clean_path):
                params["id"] = "1"

            self._endpoints.append(Endpoint(
                url=url,
                method="GET",
                parameters=params,
            ))

            # Also add POST variant for non-GET endpoints
            if any(kw in path.lower() for kw in [
                "login", "user", "feedback", "review", "order",
                "register", "signup", "password", "reset", "comment",
            ]):
                self._endpoints.append(Endpoint(
                    url=url,
                    method="POST",
                    parameters=dict(params),  # Only real params — empty if unknown
                ))

    def _extract_params_from_js(self, js_body: str, base_url: str) -> None:
        """Extract query and POST body parameters from JS context around API paths.

        Looks for patterns like:
          - fetch("/rest/products/search?q=" + input)
          - HttpParams().set('q', value)
          - { email: ..., password: ... } near login URLs
          - URLSearchParams with .append('key', ...)
        """
        # Pattern 1: URL + query string concatenation
        # Matches all common JS patterns:
        #   "/rest/products/search?q=" + input       (string concat)
        #   `/rest/products/search?q=${input}`       (template literal)
        #   "/api/endpoint?param=" + value           (string concat)
        url_concat = re.findall(
            r'["\'`](/(?:api|rest|graphql|v[0-9])[/\w.-]*)\?(\w+)=["\']?\s*[\+\$`]',
            js_body,
        )
        for path, param in url_concat:
            url = f"{base_url}{path}"
            self._add_param_to_endpoint(url, "GET", param)

        # Pattern 1b: Template literals with ?param=${
        # e.g., `/rest/products/search?q=${e}`
        template_params = re.findall(
            r'`[^`]*/(?:api|rest|graphql|v[0-9])[/\w.-]*\?(\w+)=\$\{',
            js_body,
        )
        # Find the associated path
        for param in template_params:
            template_urls = re.findall(
                r'`([^`]*/(?:api|rest|graphql|v[0-9])[/\w.-]*)\?' + param + r'=',
                js_body,
            )
            for tmpl_path in template_urls:
                # Strip any ${...} prefix (e.g., ${this.host}/rest/...)
                clean = re.sub(r'\$\{[^}]*\}', '', tmpl_path).lstrip('/')
                if clean.startswith(('api/', 'rest/', 'graphql/', 'v1/', 'v2/')):
                    url = f"{base_url}/{clean}"
                    self._add_param_to_endpoint(url, "GET", param)

        # Pattern 2: HttpParams / URLSearchParams
        # e.g., .set('q', ...) or .append('q', ...)
        http_params = re.findall(
            r'\.(?:set|append)\s*\(\s*["\'](\w+)["\']\s*,',
            js_body,
        )
        # Associate with nearest API URL in context
        for param in http_params:
            # Find nearby API URL within ~500 chars
            for match in re.finditer(
                r'["\'](/(?:api|rest)[/\w.-]*)["\']', js_body
            ):
                start = max(0, match.start() - 500)
                end = min(len(js_body), match.end() + 500)
                context = js_body[start:end]
                if param in context:
                    url = f"{base_url}{match.group(1)}"
                    self._add_param_to_endpoint(url, "GET", param)
                    break

        # Pattern 3: POST body objects near API URLs
        # e.g., { email: x, password: y } or { "email": x, "password": y }
        post_body_patterns = re.findall(
            r'(?:post|put|patch)\s*\(\s*["\']?(/(?:api|rest)[/\w.-]*)["\']?\s*,\s*\{([^}]{5,200})\}',
            js_body,
            re.IGNORECASE,
        )
        for path, body_str in post_body_patterns:
            url = f"{base_url}{path}"
            field_names = re.findall(r'["\']?(\w+)["\']?\s*:', body_str)
            params = {name: "test" for name in field_names if len(name) > 1}
            if params:
                self._endpoints.append(Endpoint(
                    url=url, method="POST", parameters=params,
                ))

        # Pattern 4: Explicit body field names near common endpoints
        # Catches: JSON.stringify({ email: ..., password: ... })
        stringify_patterns = re.findall(
            r'stringify\s*\(\s*\{([^}]{5,300})\}',
            js_body,
        )
        for body_str in stringify_patterns:
            field_names = re.findall(r'["\']?(\w+)["\']?\s*:', body_str)
            # Try to find which endpoint this is for
            for name in field_names:
                if name in ("email", "username", "password"):
                    # Likely a login/register endpoint
                    for ep in self._endpoints:
                        if any(kw in ep.url for kw in ["login", "user", "register"]):
                            for fn in field_names:
                                if len(fn) > 1:
                                    ep.parameters[fn] = "test"
                    break

    def _add_param_to_endpoint(self, url: str, method: str, param: str) -> None:
        """Add a parameter to an existing endpoint or create a new one."""
        for ep in self._endpoints:
            if ep.url == url and ep.method == method:
                ep.parameters[param] = "test"
                return
        # Not found — create new
        self._endpoints.append(Endpoint(
            url=url, method=method, parameters={param: "test"},
        ))

    async def _generate_idor_endpoints(self, base_url: str) -> None:
        """Generate numbered-ID variants for REST collection endpoints.

        /api/Products → probe /api/Products/1, /api/Products/2
        If they return data, add as parameterized endpoints for IDOR testing.
        """
        # Find collection endpoints (no ID segment, look like REST resources)
        collections = []
        seen_urls = {ep.url for ep in self._endpoints}

        for ep in list(self._endpoints):
            # Skip if already has an ID segment
            if re.search(r'/\d+(/|$)', ep.url):
                continue
            # Must be under /api or /rest
            if "/api/" not in ep.url and "/rest/" not in ep.url:
                continue
            # Must look like a resource (PascalCase or lowercase segment at end)
            path = ep.url.split("?")[0]
            last_segment = path.rstrip("/").split("/")[-1]
            if last_segment and last_segment[0].isupper():
                collections.append(path)
            elif last_segment in ("users", "products", "orders", "feedbacks",
                                  "reviews", "baskets", "cards", "addresses",
                                  "complaints", "challenges", "memories"):
                collections.append(path)

        for collection_url in set(collections):
            for test_id in ["1", "2"]:
                url = f"{collection_url}/{test_id}"
                if url in seen_urls:
                    continue
                try:
                    resp = await self.http.get(url)
                    if resp.status_code == 200:
                        content_type = resp.headers.get("content-type", "")
                        if "json" in content_type or resp.text.strip().startswith(("{", "[")):
                            self._endpoints.append(Endpoint(
                                url=url,
                                method="GET",
                                parameters={"id": test_id},
                                content_type=content_type,
                            ))
                            seen_urls.add(url)
                except Exception:
                    continue

    @staticmethod
    def _normalize_url(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
