"""Engagement and scope models — the authority boundary for all scanning."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from fnmatch import fnmatch
from ipaddress import IPv4Network, ip_address
from pathlib import Path
from typing import Self
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field, model_validator


class ScopeViolationType(str, Enum):
    DOMAIN_NOT_IN_SCOPE = "domain_not_in_scope"
    PATH_EXCLUDED = "path_excluded"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    PORT_NOT_ALLOWED = "port_not_allowed"
    DENY_LIST_MATCH = "deny_list_match"
    ENGAGEMENT_EXPIRED = "engagement_expired"
    OUTSIDE_TIME_WINDOW = "outside_time_window"
    REDIRECT_OUT_OF_SCOPE = "redirect_out_of_scope"
    DESTRUCTIVE_PAYLOAD = "destructive_payload"
    DNS_REBINDING = "dns_rebinding"


class ScopeViolation(Exception):
    """Raised when a request would violate engagement scope."""

    def __init__(self, violation_type: ScopeViolationType, url: str, detail: str = ""):
        self.violation_type = violation_type
        self.url = url
        self.detail = detail
        super().__init__(f"Scope violation [{violation_type.value}]: {url} — {detail}")


class PathScope(BaseModel):
    include: list[str] = Field(default_factory=lambda: ["/*"])
    exclude: list[str] = Field(default_factory=list)

    def is_allowed(self, path: str) -> bool:
        included = any(fnmatch(path, pattern) for pattern in self.include)
        excluded = any(fnmatch(path, pattern) for pattern in self.exclude)
        return included and not excluded


class TargetScope(BaseModel):
    domain: str
    ports: list[int] = Field(default_factory=lambda: [443])
    paths: PathScope = Field(default_factory=PathScope)
    methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE"])

    def matches_domain(self, domain: str) -> bool:
        return fnmatch(domain.lower(), self.domain.lower())

    def is_port_allowed(self, port: int) -> bool:
        return port in self.ports

    def is_method_allowed(self, method: str) -> bool:
        return method.upper() in [m.upper() for m in self.methods]


class TimeWindow(BaseModel):
    timezone: str = "UTC"
    allowed_hours: str = "00:00-23:59"
    allowed_days: list[str] = Field(
        default_factory=lambda: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    )

    def is_within_window(self, now: datetime | None = None) -> bool:
        import zoneinfo

        if now is None:
            now = datetime.now(timezone.utc)

        tz = zoneinfo.ZoneInfo(self.timezone)
        local_now = now.astimezone(tz)

        day_name = local_now.strftime("%a").lower()
        if day_name not in self.allowed_days:
            return False

        start_str, end_str = self.allowed_hours.split("-")
        start_h, start_m = map(int, start_str.split(":"))
        end_h, end_m = map(int, end_str.split(":"))

        current_minutes = local_now.hour * 60 + local_now.minute
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m

        if start_minutes <= end_minutes:
            return start_minutes <= current_minutes <= end_minutes
        # Overnight window (e.g., 22:00-06:00)
        return current_minutes >= start_minutes or current_minutes <= end_minutes


class Restrictions(BaseModel):
    rate_limit: int = 10
    max_concurrent: int = 5
    time_window: TimeWindow = Field(default_factory=TimeWindow)
    destructive_payloads: bool = False
    max_crawl_depth: int = 5


class NotificationConfig(BaseModel):
    on_scope_violation: str = "warn_and_block"
    webhook: str | None = None


class EngagementInfo(BaseModel):
    id: str
    client: str
    start_date: datetime
    end_date: datetime
    tester: str

    def is_active(self, now: datetime | None = None) -> bool:
        if now is None:
            now = datetime.now(timezone.utc)
        return self.start_date <= now <= self.end_date


class ScopeConfig(BaseModel):
    targets: list[TargetScope] = Field(default_factory=list)
    deny_list: list[str] = Field(default_factory=list)

    def is_denied(self, host: str) -> bool:
        for pattern in self.deny_list:
            if fnmatch(host.lower(), pattern.lower()):
                return True
            try:
                network = IPv4Network(pattern, strict=False)
                if ip_address(host) in network:
                    return True
            except ValueError:
                continue
        return False

    def find_target(self, domain: str) -> TargetScope | None:
        for target in self.targets:
            if target.matches_domain(domain):
                return target
        return None


class CredentialConfig(BaseModel):
    """A single set of credentials for authenticated scanning."""
    username: str = ""
    password: str = ""
    login_url: str = ""  # If known — otherwise the auth agent will discover it
    type: str = "auto"   # auto, form, api, basic, bearer
    token: str = ""      # Pre-existing bearer/API token (skip login if set)


class EngagementConfig(BaseModel):
    engagement: EngagementInfo
    scope: ScopeConfig
    credentials: list[CredentialConfig] = Field(default_factory=list)
    restrictions: Restrictions = Field(default_factory=Restrictions)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)

    @property
    def high_priv_credentials(self) -> CredentialConfig | None:
        """First credential is treated as high-privilege."""
        return self.credentials[0] if self.credentials else None

    @property
    def low_priv_credentials(self) -> CredentialConfig | None:
        """Second credential is treated as low-privilege."""
        return self.credentials[1] if len(self.credentials) > 1 else None

    @classmethod
    def from_yaml(cls, path: str | Path) -> Self:
        path = Path(path)
        with path.open() as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)

    def get_whitelisted_domains(self) -> list[str]:
        return [t.domain for t in self.scope.targets]

    def get_whitelisted_ports(self) -> dict[str, list[int]]:
        return {t.domain: t.ports for t in self.scope.targets}

    def check_url(self, url: str, method: str = "GET") -> None:
        """Validate a URL against the engagement scope. Raises ScopeViolation on failure."""
        now = datetime.now(timezone.utc)

        if not self.engagement.is_active(now):
            raise ScopeViolation(
                ScopeViolationType.ENGAGEMENT_EXPIRED,
                url,
                f"Engagement {self.engagement.id} expired at {self.engagement.end_date}",
            )

        if not self.restrictions.time_window.is_within_window(now):
            raise ScopeViolation(
                ScopeViolationType.OUTSIDE_TIME_WINDOW,
                url,
                f"Current time outside allowed window: {self.restrictions.time_window.allowed_hours}",
            )

        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"

        if self.scope.is_denied(hostname):
            raise ScopeViolation(
                ScopeViolationType.DENY_LIST_MATCH,
                url,
                f"Host {hostname} is on the deny list",
            )

        target = self.scope.find_target(hostname)
        if target is None:
            raise ScopeViolation(
                ScopeViolationType.DOMAIN_NOT_IN_SCOPE,
                url,
                f"Domain {hostname} not in engagement scope",
            )

        if not target.is_port_allowed(port):
            raise ScopeViolation(
                ScopeViolationType.PORT_NOT_ALLOWED,
                url,
                f"Port {port} not allowed for {hostname} (allowed: {target.ports})",
            )

        if not target.is_method_allowed(method):
            raise ScopeViolation(
                ScopeViolationType.METHOD_NOT_ALLOWED,
                url,
                f"Method {method} not allowed for {hostname} (allowed: {target.methods})",
            )

        if not target.paths.is_allowed(path):
            raise ScopeViolation(
                ScopeViolationType.PATH_EXCLUDED,
                url,
                f"Path {path} is excluded from scope",
            )
