"""Tests for SPA-crawler parameterized-route capture and DOM-XSS param sweeping.

Synthetic inputs only — no browser, no live target. The pure helpers that back
the Playwright-driven crawl and DOM-reflection sweep are tested directly:

  - ``_parse_hashroute_params``  — capture query-param names from hash-route links
  - ``_dom_candidate_params``    — order/dedup/cap the param names to probe

Neutral URLs and generic param names throughout — nothing here is tied to any
specific target application.
"""

from __future__ import annotations

from diana.core.spa_crawler import (
    COMMON_REFLECTION_PARAMS,
    MAX_DOM_XSS_PARAMS,
    SPACrawler,
)


class TestParseHashrouteParams:
    def test_extracts_route_and_param(self):
        assert SPACrawler._parse_hashroute_params("#/track-result?id=5") == (
            "track-result", ["id"],
        )

    def test_absolute_href_with_hash(self):
        assert SPACrawler._parse_hashroute_params(
            "http://app/#/search?q=shoes"
        ) == ("search", ["q"])

    def test_leading_slash_hash(self):
        assert SPACrawler._parse_hashroute_params("/#/view?name=x") == (
            "view", ["name"],
        )

    def test_multiple_params_preserved(self):
        route, names = SPACrawler._parse_hashroute_params(
            "#/report?id=1&format=html"
        )
        assert route == "report"
        assert set(names) == {"id", "format"}

    def test_first_path_segment_is_route(self):
        assert SPACrawler._parse_hashroute_params("#/orders/detail?id=9") == (
            "orders", ["id"],
        )

    def test_none_without_hash(self):
        assert SPACrawler._parse_hashroute_params("/track-result?id=5") is None

    def test_none_without_query(self):
        assert SPACrawler._parse_hashroute_params("#/track-result") is None

    def test_none_for_empty_route(self):
        assert SPACrawler._parse_hashroute_params("#/?id=5") is None

    def test_none_for_empty_href(self):
        assert SPACrawler._parse_hashroute_params("") is None


class TestDomCandidateParams:
    def test_none_falls_back_to_common(self):
        result = SPACrawler._dom_candidate_params(None)
        assert result == COMMON_REFLECTION_PARAMS[:MAX_DOM_XSS_PARAMS]

    def test_observed_common_name_ranked_first(self):
        # 'id' is observed AND common — it must lead, ahead of un-observed
        # common names like 'q'.
        result = SPACrawler._dom_candidate_params({"id"})
        assert result[0] == "id"

    def test_capped_at_max(self):
        many = {f"p{i}" for i in range(50)}
        result = SPACrawler._dom_candidate_params(many)
        assert len(result) == MAX_DOM_XSS_PARAMS

    def test_observed_and_common_name_leads_large_set(self):
        # An observed-AND-common key ('id', tier 1) leads even when a flood of
        # other observed names competes for the capped slots.
        observed = {f"col_{i}" for i in range(40)} | {"id"}
        result = SPACrawler._dom_candidate_params(observed)
        assert result[0] == "id"

    def test_observed_noncommon_name_is_probed(self):
        # Tier 2: a real app param that isn't a conventional key must still be
        # probed — it outranks the never-seen common fallbacks. (This is the
        # tier the previous cap made unreachable.)
        result = SPACrawler._dom_candidate_params({"orderref"})
        assert "orderref" in result
        # ...and it precedes the pure-guess fallback names it isn't equal to.
        assert result.index("orderref") < result.index("term")

    def test_observed_name_deduped_case_insensitively(self):
        # Two observed names differing only in case collapse to one entry.
        # Reachable through the public API now that observed names (tier 2)
        # aren't sliced off by the cap. A case-sensitive dedup would keep both.
        result = SPACrawler._dom_candidate_params({"OrderRef", "orderref"})
        matches = [n for n in result if n.lower() == "orderref"]
        assert len(matches) == 1

    def test_blank_names_ignored(self):
        result = SPACrawler._dom_candidate_params({"", "  "})
        assert result == COMMON_REFLECTION_PARAMS[:MAX_DOM_XSS_PARAMS]
