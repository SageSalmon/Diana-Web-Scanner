"""Tests for SPA-crawler XHR body capture and benign form-fill value selection.

Synthetic inputs only — no browser, no live target. The pure helpers that back
the Playwright request listener are tested directly.
"""

from __future__ import annotations

import json

from diana.core.spa_crawler import _benign_value, _capture_json_body

ORIGIN = "http://app"


class TestCaptureJsonBody:
    def test_captures_post_json_object(self):
        result = _capture_json_body(
            "POST", "http://app/api/Feedbacks",
            json.dumps({"rating": 5, "comment": "hi"}), ORIGIN,
        )
        assert result is not None
        key, body = result
        assert key == ("POST", "http://app/api/Feedbacks")
        assert body == {"rating": 5, "comment": "hi"}

    def test_put_and_patch_captured(self):
        for method in ("PUT", "PATCH"):
            result = _capture_json_body(
                method, "http://app/api/BasketItems/1",
                json.dumps({"quantity": 2}), ORIGIN,
            )
            assert result is not None
            assert result[0][0] == method

    def test_get_not_captured(self):
        assert _capture_json_body(
            "GET", "http://app/api/Products", None, ORIGIN,
        ) is None

    def test_out_of_scope_origin_ignored(self):
        assert _capture_json_body(
            "POST", "http://analytics.example.com/collect",
            json.dumps({"e": "x"}), ORIGIN,
        ) is None

    def test_non_json_body_ignored(self):
        assert _capture_json_body(
            "POST", "http://app/api/x", "not-json-at-all", ORIGIN,
        ) is None

    def test_empty_body_ignored(self):
        assert _capture_json_body("POST", "http://app/api/x", "", ORIGIN) is None

    def test_json_array_ignored(self):
        # Only object bodies give us named fields to mutate.
        assert _capture_json_body(
            "POST", "http://app/api/x", json.dumps([1, 2, 3]), ORIGIN,
        ) is None

    def test_query_string_stripped_from_key(self):
        result = _capture_json_body(
            "POST", "http://app/api/x?token=abc",
            json.dumps({"a": 1}), ORIGIN,
        )
        assert result is not None
        assert result[0] == ("POST", "http://app/api/x")


class TestBenignValue:
    def test_email_field_gets_email(self):
        assert "@" in _benign_value("email", "userEmail")
        assert "@" in _benign_value("text", "email")

    def test_password_field_gets_password(self):
        assert _benign_value("password", "pw") == "DianaTest123!"

    def test_numeric_field_gets_number(self):
        assert _benign_value("number", "anything") == "1"
        assert _benign_value("text", "quantity") == "1"

    def test_generic_field_gets_safe_default(self):
        assert _benign_value("text", "comment") == "diana-test"
