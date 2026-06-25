"""Configuration management for Diana scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class AIConfig(BaseModel):
    model_id: str = "deepseek.v3.2"
    region: str = "us-east-1"
    max_tokens: int = 4096
    temperature: float = 0.1


class AuthConfig(BaseModel):
    type: str = ""  # bearer, basic, cookie, form, none
    token: str = ""
    username: str = ""
    password: str = ""
    login_url: str = ""
    token_field: str = ""


class ScanModuleConfig(BaseModel):
    modules: list[str] = Field(default_factory=lambda: [
        "xss", "sqli", "ssrf", "headers", "info_disclosure", "auth",
        # Access control (OWASP A01) runs last: it's AI-driven and slower, and
        # depends on auth context established by earlier phases. The module was
        # registered but never enabled by default, so authorization flaws (IDOR,
        # method tampering, privilege escalation) went entirely untested.
        "access_control",
    ])


class ReportingConfig(BaseModel):
    format: str = "html"
    output: str = "./reports/"


class ScanConfig(BaseSettings):
    """Scanner configuration — loaded from file, env vars, or CLI args.

    AI is enabled by default (for deployed ECS). Set DIANA_AI_ENABLED=false
    in .env or environment to disable Bedrock calls for local runs.
    """

    target: str = ""
    engagement_file: str = ""
    database_url: str = "postgresql://diana:diana_dev@localhost:5432/diana"
    depth: int = 3
    rate_limit: int = 10
    timeout: int = 30
    verbose: bool = False
    no_ai: bool = False

    ai: AIConfig = Field(default_factory=AIConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    scan: ScanModuleConfig = Field(default_factory=ScanModuleConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ScanConfig:
        path = Path(path)
        with path.open() as f:
            data = yaml.safe_load(f) or {}
        return cls.model_validate(data)

    @classmethod
    def from_cli_args(cls, **kwargs: Any) -> ScanConfig:
        filtered = {k: v for k, v in kwargs.items() if v is not None}
        return cls.model_validate(filtered)
