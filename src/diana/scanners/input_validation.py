"""Input-validation / fuzzing module.

Replays request bodies and query parameters observed during the crawl, mutating
one field at a time with boundary and type-violating values (zero, negative,
empty, null, oversized, type-mismatch, omitted). Sending these live requests is
what exercises the target's input handling — a server that accepts an obviously
invalid value (e.g. a negative quantity, an empty required field, a zero rating)
is failing to validate input.

The technique is framework-agnostic: it mutates whatever fields the crawler
discovered, with no hard-coded endpoints, paths, or field names.
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlencode

import httpx

from diana.config import ScanConfig
from diana.core.models import Endpoint, Finding, Severity, VulnType
from diana.scanners.base import BaseScanner

# Bounds to keep runtime/cost predictable on large sitemaps.
MAX_FIELDS_PER_ENDPOINT = 12
MAX_REQUESTS = 400

# An oversized string for length/buffer validation checks.
OVERSIZED = "A" * 10_000
# A value carrying an embedded null byte (truncation / injection probe).
NULL_BYTE = "diana\x00test"


class InputValidationScanner(BaseScanner):
    name = "input_validation"
    description = "Boundary/type input-validation fuzzing (zero, negative, empty, null)"

    def __init__(self, http, ai_agent=None):
        super().__init__(http, ai_agent)
        self._admin_token: str = ""
        self._user_token: str = ""
        self._requests_sent: int = 0

    @property
    def vuln_types(self) -> list:
        return [VulnType.IMPROPER_INPUT_VALIDATION]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        work_items = self.claim_work(limit=1000)
        if not work_items:
            return findings

        self._admin_token = self.http._auth_headers.get("Authorization", "").replace("Bearer ", "")
        if self.scan_state and self.scan_id:
            auth_data = self.scan_state.get_auth(self.scan_id)
            self._user_token = auth_data.get("user_token", "") or ""

        seen_findings: set[tuple[str, str, str, str]] = set()
        body_eps = 0
        param_eps = 0

        for item in work_items:
            if self._requests_sent >= MAX_REQUESTS:
                self.complete_work(item["queue_id"])
                continue

            payload = item.get("payload", {}) or {}
            method = item.get("method", "GET").upper()
            token = self._token_for(item.get("auth_context", "admin"))
            request_body = payload.get("request_body") or {}
            parameters = payload.get("parameters") or {}

            if request_body:
                body_eps += 1
                new = await self._fuzz_body(
                    item["url"], method, request_body, token, seen_findings,
                )
                findings.extend(new)
            elif parameters:
                param_eps += 1
                new = await self._fuzz_params(
                    item["url"], method, parameters, token, seen_findings,
                )
                findings.extend(new)

            self.complete_work(item["queue_id"])

        print(
            f"  input_validation: {body_eps} body endpoints, {param_eps} param "
            f"endpoints, {self._requests_sent} probes sent, {len(findings)} findings"
        )
        return findings

    def _token_for(self, auth_context: str) -> str:
        if auth_context == "user" and self._user_token:
            return self._user_token
        if auth_context == "none":
            return ""
        return self._admin_token

    async def _fuzz_body(
        self,
        url: str,
        method: str,
        body: dict[str, Any],
        token: str,
        seen: set[tuple[str, str, str, str]],
    ) -> list[Finding]:
        """Replay a JSON body, mutating one field at a time."""
        findings: list[Finding] = []
        for field in list(body.keys())[:MAX_FIELDS_PER_ENDPOINT]:
            for label, value, expect_reject in _mutations_for(body[field]):
                if self._requests_sent >= MAX_REQUESTS:
                    return findings
                mutated = dict(body)
                if label == "omit":
                    mutated.pop(field, None)
                else:
                    mutated[field] = value
                resp = await self._send(url, method, token, json_body=mutated)
                finding = self._evaluate(
                    url, method, field, label, expect_reject, resp, seen,
                )
                if finding:
                    findings.append(finding)
        return findings

    async def _fuzz_params(
        self,
        url: str,
        method: str,
        params: dict[str, str],
        token: str,
        seen: set[tuple[str, str, str, str]],
    ) -> list[Finding]:
        """Mutate query/form parameters one at a time."""
        findings: list[Finding] = []
        for field in list(params.keys())[:MAX_FIELDS_PER_ENDPOINT]:
            for label, value, expect_reject in _mutations_for(params[field]):
                if self._requests_sent >= MAX_REQUESTS:
                    return findings
                if value is None or label == "omit":
                    continue  # query strings can't carry a JSON null
                mutated = dict(params)
                mutated[field] = str(value)
                if method == "GET":
                    target = url + ("&" if "?" in url else "?") + urlencode(mutated)
                    resp = await self._send(target, "GET", token)
                else:
                    resp = await self._send(url, method, token, form=mutated)
                finding = self._evaluate(
                    url, method, field, label, expect_reject, resp, seen,
                )
                if finding:
                    findings.append(finding)
        return findings

    async def _send(
        self,
        url: str,
        method: str,
        token: str,
        json_body: dict | None = None,
        form: dict | None = None,
    ) -> httpx.Response | None:
        """Send one probe through the scope enforcer with the given auth token."""
        try:
            self.http.enforcer.check_request(url, method)
        except Exception:
            return None
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._requests_sent += 1
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                return await client.request(
                    method, url, headers=headers, json=json_body, data=form,
                )
        except Exception:
            return None

    def _evaluate(
        self,
        url: str,
        method: str,
        field: str,
        label: str,
        expect_reject: bool,
        resp: httpx.Response | None,
        seen: set[tuple[str, str, str, str]],
    ) -> Finding | None:
        """A finding is an invalid value the server accepted (2xx) when it should
        have rejected it."""
        if resp is None or not expect_reject:
            return None
        if resp.status_code not in (200, 201):
            return None

        key = (method, url, field, label)
        if key in seen:
            return None
        seen.add(key)

        return Finding(
            id=f"IV-{uuid.uuid4().hex[:8]}",
            vuln_type=VulnType.IMPROPER_INPUT_VALIDATION,
            severity=Severity.MEDIUM,
            title=f"Improper input validation: '{field}' accepts {label} value",
            description=(
                f"The '{field}' field on {method} {url} accepted an invalid "
                f"'{label}' value and the server responded {resp.status_code}. "
                f"Missing server-side validation can enable business-logic abuse "
                f"(e.g. negative quantities, zero-value submissions, oversized input)."
            ),
            endpoint=Endpoint(url=url, method=method),
            evidence=f"mutation={label} field={field} status={resp.status_code}",
            cwe_id="CWE-20",
            remediation=(
                "Validate all input server-side: enforce type, range, length, and "
                "required-field constraints; reject values outside expected bounds."
            ),
            confirmed=True,
        )


def _mutations_for(value: Any) -> list[tuple[str, Any, bool]]:
    """Mutations for a field given its observed value's type.

    Returns (label, new_value, expect_reject) tuples. expect_reject marks values
    a well-validated server should refuse — those drive findings; the rest are
    sent as coverage probes.
    """
    muts: list[tuple[str, Any, bool]] = [("omit", None, True)]
    if isinstance(value, bool):
        # bool is a subclass of int — handle it before the numeric branch.
        muts += [("null", None, True), ("type-mismatch", "not-a-bool", True)]
    elif isinstance(value, (int, float)):
        muts += [
            ("zero", 0, True),
            ("negative", -1, True),
            ("negative-large", -999_999, True),
            ("overflow", 2**31, True),
            ("type-mismatch", "not-a-number", True),
            ("null", None, True),
        ]
    elif isinstance(value, str):
        muts += [
            ("empty", "", True),
            ("null", None, True),
            ("oversized", OVERSIZED, True),
            ("type-mismatch", 0, True),
            ("null-byte", NULL_BYTE, True),
        ]
    else:
        # Nested object / array / unknown: just probe null and omission.
        muts += [("null", None, True)]
    return muts
