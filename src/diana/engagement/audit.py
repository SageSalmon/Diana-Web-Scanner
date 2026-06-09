"""Audit logging for all engagement scope decisions."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class AuditAction(str, Enum):
    REQUEST_ALLOWED = "request_allowed"
    REQUEST_BLOCKED = "request_blocked"
    REDIRECT_BLOCKED = "redirect_blocked"
    DNS_BLOCKED = "dns_blocked"
    NETWORK_BLOCKED = "network_blocked"
    SESSION_REAUTH = "session_reauth"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_PAUSED = "scan_paused"
    ENGAGEMENT_LOADED = "engagement_loaded"


class AuditEntry(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    action: AuditAction
    engagement_id: str
    url: str = ""
    method: str = ""
    layer: str = ""
    detail: str = ""
    violation_type: str = ""

    def to_log_line(self) -> str:
        return json.dumps(self.model_dump(mode="json"), default=str)


class AuditLogger:
    """Append-only audit log for all scope enforcement decisions.

    Every request — allowed or blocked — is recorded with the engagement ID,
    URL, method, enforcement layer, and decision reason. This provides a
    complete forensic trail for the engagement.
    """

    def __init__(self, engagement_id: str, log_dir: Path | None = None):
        self.engagement_id = engagement_id
        self.logger = logging.getLogger(f"diana.audit.{engagement_id}")

        if log_dir:
            log_dir.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(log_dir / f"audit_{engagement_id}.jsonl")
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(handler)

        self.logger.setLevel(logging.INFO)

    def log(self, entry: AuditEntry) -> None:
        self.logger.info(entry.to_log_line())

    def allowed(self, url: str, method: str, layer: str = "enforcer") -> None:
        self.log(AuditEntry(
            action=AuditAction.REQUEST_ALLOWED,
            engagement_id=self.engagement_id,
            url=url,
            method=method,
            layer=layer,
        ))

    def blocked(
        self,
        url: str,
        method: str,
        violation_type: str,
        detail: str,
        layer: str = "enforcer",
    ) -> None:
        self.log(AuditEntry(
            action=AuditAction.REQUEST_BLOCKED,
            engagement_id=self.engagement_id,
            url=url,
            method=method,
            layer=layer,
            violation_type=violation_type,
            detail=detail,
        ))

    def event(self, action: AuditAction, detail: str = "") -> None:
        self.log(AuditEntry(
            action=action,
            engagement_id=self.engagement_id,
            detail=detail,
        ))
