"""Engagement scope enforcer — Layer 2 of defense in depth.

Wraps the HTTP client to validate every outbound request against the
engagement configuration before it is sent. This is not optional middleware —
it is the only path to the network.
"""

from __future__ import annotations

from urllib.parse import urlparse

from diana.engagement.audit import AuditAction, AuditLogger
from diana.engagement.models import EngagementConfig, ScopeViolation, ScopeViolationType


class EngagementEnforcer:
    """Validates URLs, methods, and redirects against the engagement scope."""

    def __init__(self, config: EngagementConfig, audit: AuditLogger):
        self.config = config
        self.audit = audit
        self.audit.event(
            AuditAction.ENGAGEMENT_LOADED,
            f"Engagement {config.engagement.id} loaded — "
            f"{len(config.scope.targets)} targets in scope",
        )

    def check_request(self, url: str, method: str = "GET") -> None:
        """Validate a request against engagement scope. Raises ScopeViolation."""
        try:
            self.config.check_url(url, method)
            self.audit.allowed(url, method)
        except ScopeViolation as e:
            self.audit.blocked(url, method, e.violation_type.value, e.detail)
            raise

    def check_redirect(self, original_url: str, redirect_url: str) -> None:
        """Check if a redirect target is still in scope."""
        try:
            self.config.check_url(redirect_url)
        except ScopeViolation:
            self.audit.blocked(
                redirect_url,
                "GET",
                ScopeViolationType.REDIRECT_OUT_OF_SCOPE.value,
                f"Redirect from {original_url} leads out of scope",
                layer="redirect_checker",
            )
            raise ScopeViolation(
                ScopeViolationType.REDIRECT_OUT_OF_SCOPE,
                redirect_url,
                f"Redirect from {original_url} would leave engagement scope",
            )

    def check_destructive(self, payload: str) -> None:
        """Block destructive payloads if not allowed by engagement."""
        if self.config.restrictions.destructive_payloads:
            return

        destructive_patterns = [
            "DROP TABLE", "DROP DATABASE", "DELETE FROM", "TRUNCATE",
            "rm -rf", "rm -f", "shutdown", "FORMAT",
            "; DROP", "'; DROP", "\"; DROP",
        ]
        payload_upper = payload.upper()
        for pattern in destructive_patterns:
            if pattern.upper() in payload_upper:
                raise ScopeViolation(
                    ScopeViolationType.DESTRUCTIVE_PAYLOAD,
                    "",
                    f"Payload contains destructive pattern: {pattern}",
                )

    @property
    def rate_limit(self) -> int:
        return self.config.restrictions.rate_limit

    @property
    def max_concurrent(self) -> int:
        return self.config.restrictions.max_concurrent

    @property
    def max_crawl_depth(self) -> int:
        return self.config.restrictions.max_crawl_depth
