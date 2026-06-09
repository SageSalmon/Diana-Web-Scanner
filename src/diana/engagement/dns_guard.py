"""Whitelisted DNS resolver — Layer 3 of defense in depth.

Only resolves domains explicitly listed in the engagement scope.
All other lookups return empty, preventing out-of-scope traffic
even if the application layer has a bug. Also detects DNS rebinding
by verifying resolved IPs remain consistent.
"""

from __future__ import annotations

import socket
from ipaddress import ip_address

from diana.engagement.audit import AuditLogger
from diana.engagement.models import EngagementConfig


class DNSGuard:
    """Custom DNS resolver that only resolves whitelisted domains."""

    def __init__(
        self,
        config: EngagementConfig,
        audit: AuditLogger,
        allow_private: bool = False,
    ):
        self.config = config
        self.audit = audit
        self.allow_private = allow_private
        self._whitelisted_domains = {
            d.lower() for d in config.get_whitelisted_domains()
        }
        self._resolved_cache: dict[str, list[str]] = {}

    def is_whitelisted(self, domain: str) -> bool:
        return domain.lower() in self._whitelisted_domains

    def resolve(self, domain: str) -> list[str]:
        """Resolve a domain, but only if it's in the engagement whitelist.

        Returns list of IP addresses, or raises ValueError for out-of-scope domains.
        """
        domain_lower = domain.lower()

        if not self.is_whitelisted(domain_lower):
            self.audit.blocked(
                domain, "", "dns_not_whitelisted",
                f"DNS resolution blocked — {domain} not in engagement scope",
                layer="dns_guard",
            )
            raise ValueError(f"DNS resolution denied: {domain} is not in engagement scope")

        try:
            results = socket.getaddrinfo(domain, None, socket.AF_INET)
            ips = list({r[4][0] for r in results})
        except socket.gaierror as e:
            self.audit.blocked(
                domain, "", "dns_resolution_failed",
                f"DNS resolution failed: {e}",
                layer="dns_guard",
            )
            raise ValueError(f"DNS resolution failed for {domain}: {e}") from e

        if not ips:
            raise ValueError(f"No addresses found for {domain}")

        # DNS rebinding detection: if we've resolved this domain before,
        # ensure the IPs haven't changed to something unexpected
        if domain_lower in self._resolved_cache:
            original_ips = set(self._resolved_cache[domain_lower])
            new_ips = set(ips)
            if not new_ips.issubset(original_ips):
                unexpected = new_ips - original_ips
                self.audit.blocked(
                    domain, "", "dns_rebinding",
                    f"DNS rebinding detected: new IPs {unexpected} not in original {original_ips}",
                    layer="dns_guard",
                )
                raise ValueError(
                    f"DNS rebinding detected for {domain}: "
                    f"new IPs {unexpected} differ from original {original_ips}"
                )

        # Block resolution to private/internal IPs (SSRF against scanner itself)
        # Skipped when allow_private=True (local dev / Docker Compose testing)
        if not self.allow_private:
            for resolved_ip in ips:
                addr = ip_address(resolved_ip)
                if addr.is_private or addr.is_loopback or addr.is_link_local:
                    self.audit.blocked(
                        domain, "", "dns_private_ip",
                        f"Domain {domain} resolves to private IP {resolved_ip}",
                        layer="dns_guard",
                    )
                    raise ValueError(
                        f"DNS resolution blocked: {domain} resolves to private IP {resolved_ip}"
                    )

        self._resolved_cache[domain_lower] = ips
        return ips

    def get_cached_ips(self) -> dict[str, list[str]]:
        """Return all resolved IPs for use by the network egress guard."""
        return dict(self._resolved_cache)
