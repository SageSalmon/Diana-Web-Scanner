"""Integration tests for access_control queue dispatch and graceful degradation.

These tests verify two things introduced/affected by enabling access_control:

1. The orchestrator's `_dispatch_to_queues` routes crawled endpoints into the
   access_control queue (across all three auth levels) when the module is
   enabled, and does NOT when it is absent.
2. The access_control scanner degrades gracefully — returning no findings and
   raising no exception — when its prerequisites are missing.

All inputs are synthetic. No live target, no Juice Shop fixtures.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from diana.core.models import Endpoint, SiteMap
from diana.core.orchestrator import ScanOrchestrator
from diana.scanners.access_control import AccessControlScanner


def _make_sitemap():
    base = "http://app"
    return SiteMap(
        base_url=base,
        endpoints=[
            Endpoint(url=f"{base}/search", method="GET", parameters={"q": ""}),
            Endpoint(url=f"{base}/orders", method="GET", parameters={"id": "1"}),
            Endpoint(url=f"{base}/feedback", method="POST"),
        ],
    )


def _dispatch_with_modules(modules):
    """Run the real _dispatch_to_queues against a mock state, return enqueue calls."""
    state = MagicMock()
    state.enqueue.return_value = True
    fake_self = SimpleNamespace(state=state, scan_id="scan-1")
    ScanOrchestrator._dispatch_to_queues(fake_self, _make_sitemap(), modules)
    return state.enqueue.call_args_list


def _calls_for_module(calls, module):
    # enqueue(scan_id, target_module, source_module, url, method, auth_context=..., ...)
    return [c for c in calls if c.args[1] == module]


def test_dispatch_routes_endpoints_to_access_control():
    """With access_control enabled, every crawled endpoint is enqueued for it."""
    calls = _dispatch_with_modules(["access_control"])
    ac_calls = _calls_for_module(calls, "access_control")
    # 3 endpoints x 3 auth levels (admin, user, none) = 9 items
    assert len(ac_calls) == 9


def test_dispatch_covers_all_three_auth_levels():
    """Access control testing requires admin, user, and unauthenticated views."""
    calls = _dispatch_with_modules(["access_control"])
    ac_calls = _calls_for_module(calls, "access_control")
    auth_levels = {c.kwargs.get("auth_context") for c in ac_calls}
    assert auth_levels == {"admin", "user", "none"}


def test_dispatch_skips_access_control_when_module_absent():
    """If access_control is not in the module list, nothing is enqueued for it."""
    calls = _dispatch_with_modules(["xss", "sqli"])
    assert _calls_for_module(calls, "access_control") == []


def _make_scanner(work_items, auth_headers=None, auth_cookies=None):
    http = SimpleNamespace(
        _auth_headers=auth_headers or {},
        _auth_cookies=auth_cookies or {},
    )
    scanner = AccessControlScanner(http, ai_agent=None)
    state = MagicMock()
    state.claim_work.return_value = work_items
    scanner.scan_state = state
    scanner.scan_id = "scan-1"
    return scanner, state


@pytest.mark.asyncio
async def test_scan_no_work_items_returns_empty():
    """No queued work -> no findings, no exception."""
    scanner, _ = _make_scanner(work_items=[])
    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))
    assert findings == []


@pytest.mark.asyncio
async def test_scan_no_auth_context_returns_empty_and_clears_queue():
    """With work items but no admin token and no cookies, the scanner cannot
    test anything — it should bail out cleanly and not leave work claimed."""
    work = [{"queue_id": 1, "url": "http://app/orders", "method": "GET", "payload": {}}]
    scanner, state = _make_scanner(work_items=work, auth_headers={}, auth_cookies={})
    findings = await scanner.scan(config=SimpleNamespace(no_ai=True))
    assert findings == []
    # The single claimed item must be marked complete so it isn't stuck.
    state.complete_work.assert_called_once_with(1)
