"""Base scanner interface — all detection modules implement this."""

from __future__ import annotations

from abc import ABC, abstractmethod

from diana.ai.agent import AIAgent
from diana.config import ScanConfig
from diana.core.http_client import ScopedHTTPClient
from diana.core.models import Finding, Hypothesis, SiteMap


class BaseScanner(ABC):
    """Abstract base for all vulnerability detection modules.

    Modules pull work from their queue via scan_state.claim_work().
    Any module can enqueue work to any other module's queue via
    scan_state.enqueue().
    """

    name: str = ""
    description: str = ""

    def __init__(self, http: ScopedHTTPClient, ai_agent: AIAgent | None = None):
        self.http = http
        self.ai = ai_agent
        self.scan_state = None  # Set by orchestrator before scan
        self.scan_id = ""       # Set by orchestrator before scan

    @abstractmethod
    async def scan(self, config: ScanConfig) -> list[Finding]:
        """Run the scanner, pulling work from the queue. Returns findings."""
        ...

    def claim_work(self, limit: int = 10) -> list[dict]:
        """Pull work items from this module's queue."""
        if self.scan_state and self.scan_id:
            return self.scan_state.claim_work(self.scan_id, self.name, limit)
        return []

    def complete_work(self, queue_id: int) -> None:
        """Mark a work item as completed."""
        if self.scan_state:
            self.scan_state.complete_work(queue_id)

    def enqueue_to(
        self, target_module: str, url: str, method: str = "GET",
        auth_context: str = "admin", payload: dict | None = None,
        dedup_key: str = "",
    ) -> bool:
        """Enqueue a work item to another module's queue."""
        if self.scan_state and self.scan_id:
            return self.scan_state.enqueue(
                self.scan_id, target_module, self.name,
                url, method, auth_context, payload, dedup_key,
            )
        return False

    def _relevant_hypotheses(self, hypotheses: list[Hypothesis]) -> list[Hypothesis]:
        """Filter hypotheses relevant to this scanner's vuln types."""
        return [h for h in hypotheses if h.vuln_type in self.vuln_types]

    @property
    @abstractmethod
    def vuln_types(self) -> list:
        """VulnType values this scanner can detect."""
        ...
