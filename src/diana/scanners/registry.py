"""Scanner module registry — maps module names to scanner implementations."""

from __future__ import annotations

from diana.ai.agent import AIAgent
from diana.core.http_client import ScopedHTTPClient
from diana.scanners.access_control import AccessControlScanner
from diana.scanners.auth import AuthScanner
from diana.scanners.base import BaseScanner
from diana.scanners.discovery import DiscoveryScanner
from diana.scanners.discovery_agent import DiscoveryAgent
from diana.scanners.headers import HeadersScanner
from diana.scanners.info_disclosure import InfoDisclosureScanner
from diana.scanners.sqli import SQLiScanner
from diana.scanners.sqli_agent import SQLiAgent
from diana.scanners.ssrf import SSRFScanner
from diana.scanners.xss import XSSScanner
from diana.scanners.xss_agent import XSSAgent


class ScannerRegistry:
    """Registry of available scanner modules."""

    def __init__(self, http: ScopedHTTPClient, ai_agent: AIAgent | None = None):
        self._scanners: dict[str, BaseScanner] = {
            # Static modules (work without AI)
            "xss": XSSScanner(http, ai_agent),
            "sqli": SQLiScanner(http, ai_agent),
            "ssrf": SSRFScanner(http, ai_agent),
            "headers": HeadersScanner(http, ai_agent),
            "info_disclosure": InfoDisclosureScanner(http, ai_agent),
            "auth": AuthScanner(http, ai_agent),
            "discovery": DiscoveryScanner(http, ai_agent),
            # AI agent modules (require Bedrock, skip gracefully without)
            "access_control": AccessControlScanner(http, ai_agent),
            "sqli_agent": SQLiAgent(http, ai_agent),
            "xss_agent": XSSAgent(http, ai_agent),
            "discovery_agent": DiscoveryAgent(http, ai_agent),
        }

    def get(self, name: str) -> BaseScanner | None:
        return self._scanners.get(name)

    def list_modules(self) -> list[str]:
        return list(self._scanners.keys())

    def get_all(self) -> list[BaseScanner]:
        return list(self._scanners.values())
