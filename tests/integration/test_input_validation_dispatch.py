"""Integration tests for input_validation queue dispatch and default-module
registration.

Verifies that the orchestrator routes body-carrying and parameterized endpoints
into the input_validation queue, and that the module is enabled by default and
registered. All inputs are synthetic — no live target, no Juice Shop fixtures.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from diana.config import ScanModuleConfig
from diana.core.models import Endpoint, SiteMap
from diana.core.orchestrator import ScanOrchestrator


def _make_sitemap():
    base = "http://app"
    return SiteMap(
        base_url=base,
        endpoints=[
            # query-param GET → param fuzzing
            Endpoint(url=f"{base}/search", method="GET", parameters={"q": ""}),
            # observed POST body → body fuzzing
            Endpoint(url=f"{base}/api/Feedbacks", method="POST",
                     request_body={"rating": 5, "comment": "x"}),
            # no params, no body → not enqueued
            Endpoint(url=f"{base}/about", method="GET"),
        ],
    )


def _dispatch(modules):
    state = MagicMock()
    state.enqueue.return_value = True
    fake_self = SimpleNamespace(state=state, scan_id="scan-1")
    ScanOrchestrator._dispatch_to_queues(fake_self, _make_sitemap(), modules)
    return [c for c in state.enqueue.call_args_list if c.args[1] == "input_validation"]


def test_body_endpoint_dispatched_with_request_body():
    calls = _dispatch(["input_validation"])
    body_calls = [c for c in calls if c.args[4] == "POST"]
    assert len(body_calls) == 1
    payload = body_calls[0].kwargs.get("payload") or body_calls[0].args[7]
    assert payload["request_body"] == {"rating": 5, "comment": "x"}


def test_param_endpoint_dispatched():
    calls = _dispatch(["input_validation"])
    get_calls = [c for c in calls if c.args[4] == "GET"]
    # /search has a param; /about has neither → only one GET enqueued.
    assert len(get_calls) == 1
    assert get_calls[0].args[3] == "http://app/search"


def test_endpoint_without_params_or_body_not_dispatched():
    calls = _dispatch(["input_validation"])
    urls = {c.args[3] for c in calls}
    assert "http://app/about" not in urls


def test_no_dispatch_when_module_absent():
    assert _dispatch(["xss", "sqli"]) == []


def test_input_validation_in_default_modules():
    assert "input_validation" in ScanModuleConfig().modules


def test_default_modules_have_no_duplicates():
    modules = ScanModuleConfig().modules
    assert len(modules) == len(set(modules))
