"""Tests for the default scan module configuration.

Covers the change that enables the access_control module by default. These
tests are stack-agnostic: they assert on configuration and routing behavior,
not on any specific target application.
"""

from __future__ import annotations

from diana.config import ScanConfig, ScanModuleConfig


def test_access_control_in_default_modules():
    """access_control must be enabled by default so authorization flaws
    (IDOR, method tampering, privilege escalation) are actually tested."""
    modules = ScanModuleConfig().modules
    assert "access_control" in modules


def test_default_modules_preserved():
    """Enabling access_control must not drop any previously-default module."""
    modules = ScanModuleConfig().modules
    for required in ("xss", "sqli", "ssrf", "headers", "info_disclosure", "auth"):
        assert required in modules, f"{required} missing from default modules"


def test_access_control_runs_last():
    """access_control is AI-driven and slower and depends on auth context from
    earlier phases, so it should be ordered after the static modules."""
    modules = ScanModuleConfig().modules
    assert modules[-1] == "access_control"


def test_default_modules_have_no_duplicates():
    modules = ScanModuleConfig().modules
    assert len(modules) == len(set(modules))


def test_scan_config_exposes_default_modules():
    """The top-level ScanConfig should surface the same defaults."""
    cfg = ScanConfig()
    assert "access_control" in cfg.scan.modules
