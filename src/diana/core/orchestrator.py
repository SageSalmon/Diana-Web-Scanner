"""Scan orchestrator — coordinates all phases of a Diana scan."""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from diana.ai.agent import AIAgent
from diana.ai.auth_agent import AuthAgent
from diana.ai.bedrock import BedrockClient
from diana.ai.configurator import ScanConfigurator
from diana.ai.session_monitor import SessionMonitor
from diana.config import ScanConfig
from diana.core.crawler import Crawler
from diana.core.spa_crawler import SPACrawler
from diana.core.http_client import ScopedHTTPClient
from diana.core.models import (
    Finding,
    Hypothesis,
    ScanResult,
    ScanStatus,
    SiteMap,
)
from diana.engagement.audit import AuditAction, AuditLogger
from diana.engagement.dns_guard import DNSGuard
from diana.engagement.enforcer import EngagementEnforcer
from diana.engagement.models import EngagementConfig
from diana.engagement.net_guard import NetGuard
from diana.core.state import ScanState
from diana.reporting.reporter import ReportGenerator
from diana.scanners.registry import ScannerRegistry


class ScanOrchestrator:
    """Coordinates the full scan lifecycle through all phases."""

    def __init__(
        self,
        engagement: EngagementConfig,
        scan_config: ScanConfig,
        log_dir: Path | None = None,
        allow_private: bool = False,
    ):
        self.engagement = engagement
        self.config = scan_config
        self.scan_id = str(uuid.uuid4())[:12]

        # Database-backed scan state
        self.state = ScanState(scan_config.database_url)
        self.state.create_tables()
        self.state.create_scan(
            self.scan_id, scan_config.target, engagement.engagement.id,
            git_sha=os.environ.get("GIT_SHA", ""),
            git_branch=os.environ.get("BRANCH_REF", ""),
            image_tag=os.environ.get("IMAGE_TAG", ""),
        )

        # L2: Engagement enforcer
        self.audit = AuditLogger(engagement.engagement.id, log_dir)
        self.enforcer = EngagementEnforcer(engagement, self.audit)

        # L3: DNS guard (allow_private=True for local Docker targets)
        self.dns_guard = DNSGuard(engagement, self.audit, allow_private=allow_private)

        # L4: Network guard
        self.net_guard = NetGuard(engagement, self.audit)

        # HTTP client (all traffic goes through enforcer)
        self.http = ScopedHTTPClient(
            self.enforcer,
            self.dns_guard,
            timeout=scan_config.timeout,
        )

        # AI components (unless --no-ai)
        self.bedrock: BedrockClient | None = None
        self.ai_agent: AIAgent | None = None
        self.configurator: ScanConfigurator | None = None
        self.session_monitor: SessionMonitor | None = None

        # Token tracker
        from diana.ai.token_tracker import TokenTracker
        self.token_tracker = TokenTracker(scan_state=self.state, scan_id=self.scan_id)

        if not scan_config.no_ai:
            self.bedrock = BedrockClient(
                model_id=scan_config.ai.model_id,
                region=scan_config.ai.region,
                max_tokens=scan_config.ai.max_tokens,
            )
            # LangChain LLM for agent modules — with token tracking callback
            from diana.ai.llm import create_llm
            self.llm = create_llm(
                model_id=scan_config.ai.model_id,
                region=scan_config.ai.region,
                max_tokens=scan_config.ai.max_tokens,
            )
            self.llm.callbacks = [self.token_tracker]
            self.ai_agent = AIAgent(self.bedrock, self.enforcer, llm=self.llm)
            self.configurator = ScanConfigurator(self.bedrock, self.http)
            self.session_monitor = SessionMonitor(self.bedrock, self.http)

        # Auth agent (works with or without AI — has heuristic fallback)
        self.auth_agent = AuthAgent(self.bedrock, enforcer=self.enforcer)

        # Scanner modules
        self.registry = ScannerRegistry(self.http, self.ai_agent)

    async def run(self) -> ScanResult:
        """Execute the full scan pipeline."""
        result = ScanResult(
            scan_id=self.scan_id,
            target=self.config.target,
            engagement_id=self.engagement.engagement.id,
            ai_model_used=self.config.ai.model_id if not self.config.no_ai else "none",
        )

        self.audit.event(AuditAction.SCAN_STARTED, f"Scan {self.scan_id} targeting {self.config.target}")

        try:
            # Resolve target IPs and apply network egress rules (L4)
            await self._setup_network_guard()

            # Phase 0a: AI scan configuration (if enabled)
            if self.configurator:
                result.status = ScanStatus.CONFIGURING
                await self.configurator.configure(self.config.target, self.engagement)

            # Phase 0b: Authentication (if credentials provided)
            # First credential = high-priv (used for scanning)
            # Second credential = low-priv (used by access control for IDOR comparison)
            high_priv = self.engagement.high_priv_credentials
            low_priv = self.engagement.low_priv_credentials

            if high_priv and (high_priv.username or high_priv.token):
                result.status = ScanStatus.CONFIGURING
                auth_session = await self.auth_agent.authenticate(
                    self.config.target,
                    high_priv,
                )
                if auth_session.authenticated:
                    self.http.inject_session(
                        headers=auth_session.headers,
                        cookies=auth_session.cookies,
                    )
                    self.audit.event(
                        AuditAction.SCAN_STARTED,
                        f"Authenticated as {high_priv.username} "
                        f"via {auth_session.session_type}",
                    )
                else:
                    self.audit.event(
                        AuditAction.SCAN_STARTED,
                        "Authentication failed — scanning unauthenticated",
                    )

            # If second credential provided, authenticate it too and store for IDOR
            if low_priv and (low_priv.username or low_priv.token):
                low_session = await self.auth_agent.authenticate(
                    self.config.target,
                    low_priv,
                )
                if low_session.authenticated:
                    low_token = (
                        low_session.headers.get("Authorization", "").replace("Bearer ", "")
                        or low_session.token
                    )
                    self.state.store_auth(
                        self.scan_id,
                        admin_token=self.http._auth_headers.get("Authorization", "").replace("Bearer ", ""),
                        user_token=low_token,
                    )
                    self.audit.event(
                        AuditAction.SCAN_STARTED,
                        f"Low-priv authenticated as {low_priv.username}",
                    )

            # Phase 1-2: Crawl and map (or load a cached sitemap)
            result.status = ScanStatus.CRAWLING
            sitemap = await self._obtain_sitemap()
            result.sitemap = sitemap

            # Store crawl results in database
            endpoint_dicts = [
                {
                    "url": ep.url,
                    "method": ep.method,
                    "parameters": ep.parameters,
                    "content_type": ep.content_type,
                }
                for ep in sitemap.endpoints
            ]
            stored = self.state.store_endpoints_bulk(self.scan_id, endpoint_dicts)

            # Store auth tokens in DB (accessible to agents)
            admin_token = self.http._auth_headers.get("Authorization", "").replace("Bearer ", "")
            self.state.store_auth(self.scan_id, admin_token=admin_token)

            # Log crawl results
            param_eps = [ep for ep in sitemap.endpoints if ep.parameters]
            post_eps = [ep for ep in sitemap.endpoints if ep.method == "POST"]
            print(f"\n  Crawl results: {len(sitemap.endpoints)} endpoints, "
                  f"{len(param_eps)} with params, {len(post_eps)} POST, "
                  f"{len(sitemap.forms)} forms")
            for ep in param_eps[:20]:
                print(f"    {ep.method} {ep.url} params={list(ep.parameters.keys())}")
            if len(param_eps) > 20:
                print(f"    ... and {len(param_eps) - 20} more")

            # Dispatch endpoints to per-module queues
            modules = self.config.scan.modules
            result.modules_run = modules
            self._dispatch_to_queues(sitemap, modules)

            # Log queue stats after dispatch
            queue_stats = self.state.get_queue_stats(self.scan_id)
            print(f"\n  Queue dispatch:")
            for mod, stats in sorted(queue_stats.items()):
                total = sum(stats.values())
                print(f"    {mod}: {total} items ({stats})")

            # Phase 3-4: AI analysis and hypothesis generation
            result.status = ScanStatus.ANALYZING
            hypotheses: list[Hypothesis] = []
            if self.ai_agent:
                hypotheses = await self.ai_agent.analyze_surface(sitemap)
            result.hypotheses_generated = len(hypotheses)

            # Phase 5-6: Active testing — modules pull from their queues
            result.status = ScanStatus.TESTING
            findings: list[Finding] = []

            # Include SPA findings (DOM XSS from Playwright)
            if hasattr(self, '_spa_findings'):
                findings.extend(self._spa_findings)

            for module_name in modules:
                scanner = self.registry.get(module_name)
                if scanner:
                    scanner.scan_state = self.state
                    scanner.scan_id = self.scan_id
                    self.token_tracker.set_module(module_name)
                    module_findings = await scanner.scan(self.config)
                    findings.extend(module_findings)

                    # Persist findings to DB
                    for finding in module_findings:
                        self.state.store_finding(self.scan_id, module_name, {
                            "id": finding.id,
                            "vuln_type": finding.vuln_type.value,
                            "severity": finding.severity.value,
                            "title": finding.title,
                            "description": finding.description,
                            "endpoint_url": finding.endpoint.url,
                            "endpoint_method": finding.endpoint.method,
                            "evidence": finding.evidence[:2000],
                            "payload_used": finding.payload_used,
                            "cwe_id": finding.cwe_id,
                            "remediation": finding.remediation,
                            "confirmed": finding.confirmed,
                        })

            result.payloads_tested = sum(1 for _ in findings)

            # Phase 7: AI validation
            result.status = ScanStatus.VALIDATING
            if self.ai_agent:
                for finding in findings:
                    if not finding.confirmed:  # Skip already-confirmed findings
                        is_valid = await self.ai_agent.validate_finding(finding)
                        finding.confirmed = is_valid
                        if not is_valid:
                            finding.false_positive = True
                            result.false_positives_rejected += 1
            else:
                # No AI — confirm all findings by default
                for finding in findings:
                    if not finding.confirmed:
                        finding.confirmed = True

            result.findings = [f for f in findings if f.confirmed]

            # Phase 8: Reporting
            result.status = ScanStatus.REPORTING
            reporter = ReportGenerator(self.bedrock)
            await reporter.generate(result, self.config.reporting)

            result.status = ScanStatus.COMPLETED
            result.completed_at = datetime.now(timezone.utc)
            result.duration_seconds = (
                result.completed_at - result.started_at
            ).total_seconds()

        except Exception as e:
            result.status = ScanStatus.FAILED
            self.state.update_scan_status(self.scan_id, "failed")
            self.audit.event(AuditAction.SCAN_COMPLETED, f"Scan failed: {e}")
            raise
        finally:
            await self.http.close()

        self.state.update_scan_status(self.scan_id, "completed")
        self.token_tracker.persist(self.scan_id, self.state)
        self.token_tracker.print_summary()
        self.audit.event(
            AuditAction.SCAN_COMPLETED,
            f"Scan {self.scan_id} completed — {len(result.findings)} findings",
        )
        return result

    async def _obtain_sitemap(self) -> SiteMap:
        """Crawl the target, or load a cached sitemap to skip the crawl.

        If ``config.sitemap_cache`` names an existing file, the sitemap is
        loaded from it and the crawl + Playwright phases are skipped — this is
        what makes fast inner-loop iterations cheap when a change does not touch
        the crawler. If the path is set but the file is absent, a normal crawl
        runs and the fully-assembled sitemap (including SPA-rendered endpoints)
        is written there for reuse. SPA-derived DOM XSS findings are only
        produced on a live crawl; ``_spa_findings`` is always initialized.
        """
        self._spa_findings: list[Finding] = []
        cache_path = Path(self.config.sitemap_cache) if self.config.sitemap_cache else None

        if cache_path and cache_path.exists():
            sitemap = SiteMap.model_validate_json(cache_path.read_text())
            print(f"\n  Loaded cached sitemap from {cache_path} "
                  f"({len(sitemap.endpoints)} endpoints) — skipping crawl")
            return sitemap

        crawler = Crawler(
            self.http,
            max_depth=self.enforcer.max_crawl_depth,
        )
        sitemap = await crawler.crawl(self.config.target)

        # Phase 2b: SPA route discovery + Playwright rendering
        spa = SPACrawler(self.http)
        try:
            spa_routes = await spa.discover_routes(sitemap)
        except Exception:
            spa_routes = []

        # Playwright browser phases — run in thread pool to avoid
        # blocking the async event loop (Playwright has sync internals)
        if spa_routes:
            print(f"\n  SPA routes discovered: {len(spa_routes)}")
            for r in spa_routes[:15]:
                print(f"    /{r}")

            try:
                # Crawl rendered SPA pages for forms and inputs
                spa_endpoints = await asyncio.to_thread(
                    lambda: asyncio.run(spa.crawl_routes(self.config.target, spa_routes))
                )
                if spa_endpoints:
                    print(f"  Playwright found {len(spa_endpoints)} rendered endpoints")
                    sitemap.endpoints.extend(spa_endpoints)

                # Test DOM XSS with real browser execution
                dom_xss_findings = await asyncio.to_thread(
                    lambda: asyncio.run(spa.test_dom_xss(self.config.target, spa_routes))
                )
                if dom_xss_findings:
                    print(f"  Playwright found {len(dom_xss_findings)} DOM XSS findings")
                    self._spa_findings.extend(dom_xss_findings)
            except Exception as e:
                print(f"  Playwright SPA phases failed: {e}")

        if cache_path:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(sitemap.model_dump_json())
            print(f"  Saved sitemap cache to {cache_path} "
                  f"({len(sitemap.endpoints)} endpoints)")

        return sitemap

    def _dispatch_to_queues(self, sitemap: SiteMap, modules: list[str]) -> None:
        """Dispatch crawled endpoints to per-module queues based on relevance.

        Each module gets endpoints appropriate to its specialty.
        The dedup key is module-specific so the same URL can exist
        in multiple queues without being considered a duplicate.
        """
        for ep in sitemap.endpoints:
            has_params = bool(ep.parameters)
            param_names = list(ep.parameters.keys()) if ep.parameters else []
            is_post = ep.method == "POST"
            url_lower = ep.url.lower()

            for module in modules:
                should_enqueue = False
                payload: dict = {}
                auth = "admin"  # Default: test as high-priv user
                dedup_key = ""  # Will default to method|url|auth in enqueue()

                if module in ("sqli", "sqli_agent"):
                    if has_params:
                        for param in param_names:
                            self.state.enqueue(
                                self.scan_id, module, "crawler",
                                ep.url, ep.method, auth_context="admin",
                                payload={"params": {param: ep.parameters[param]}},
                                dedup_key=f"{ep.method}|{ep.url}|{param}|admin",
                            )
                        continue
                    elif any(kw in url_lower for kw in ["login", "auth", "signin"]):
                        should_enqueue = True
                        auth = "none"  # Test login injection unauthenticated
                        payload = {"type": "login_endpoint"}

                elif module in ("xss", "xss_agent"):
                    if has_params:
                        for param in param_names:
                            self.state.enqueue(
                                self.scan_id, module, "crawler",
                                ep.url, ep.method, auth_context="admin",
                                payload={"params": {param: ep.parameters[param]},
                                         "parameters": ep.parameters},
                                dedup_key=f"{ep.method}|{ep.url}|{param}|admin",
                            )
                        continue
                    elif is_post:
                        should_enqueue = True
                        payload = {"type": "post_endpoint"}
                    elif ep.url == sitemap.base_url:
                        # Always enqueue base URL for DOM XSS sink analysis
                        should_enqueue = True
                        payload = {"type": "base_url"}

                elif module in ("access_control",):
                    # Access control needs all three auth levels. Pass the actual
                    # parameters through — the module's IDOR sweep keys on them
                    # (e.g. numeric "id"), so dropping them makes it test nothing.
                    for auth_level in ["admin", "user", "none"]:
                        self.state.enqueue(
                            self.scan_id, module, "crawler",
                            ep.url, ep.method, auth_context=auth_level,
                            payload={"has_params": has_params,
                                     "parameters": ep.parameters},
                        )
                    continue

                elif module in ("discovery", "discovery_agent"):
                    if ep.url == sitemap.base_url:
                        should_enqueue = True
                        auth = "none"  # Discovery probes unauthenticated first
                        payload = {"type": "base_url"}

                elif module == "headers":
                    if ep.url == sitemap.base_url:
                        should_enqueue = True
                        auth = "none"

                elif module == "info_disclosure":
                    should_enqueue = True

                elif module == "ssrf":
                    if has_params and any(
                        p in ["url", "uri", "link", "href", "src", "redirect",
                              "dest", "path", "callback", "proxy", "fetch"]
                        for p in param_names
                    ):
                        should_enqueue = True
                        payload = {"params": ep.parameters}

                elif module == "auth":
                    if has_params and any(
                        p in ["id", "user_id", "uid", "account_id"]
                        for p in param_names
                    ):
                        should_enqueue = True
                        payload = {"params": ep.parameters}

                if should_enqueue:
                    self.state.enqueue(
                        self.scan_id, module, "crawler",
                        ep.url, ep.method, auth_context=auth,
                        payload=payload, dedup_key=dedup_key,
                    )

    async def _setup_network_guard(self) -> None:
        """Resolve in-scope domains and apply L4 network rules."""
        for domain in self.engagement.get_whitelisted_domains():
            try:
                self.dns_guard.resolve(domain)
            except ValueError:
                pass  # Docker service names may not resolve in all envs

        resolved = self.dns_guard.get_cached_ips()
        if resolved:
            self.net_guard.apply_iptables(resolved)
