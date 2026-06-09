"""LLM provider abstraction.

Supports:
  - Bedrock (Claude, DeepSeek) — set DIANA_LLM_PROVIDER=bedrock
  - Ollama (local, free) — set DIANA_LLM_PROVIDER=ollama

Swap providers by changing the env var. All agents, prompts, and tools
use LangChain's BaseChatModel interface — provider-agnostic.
"""

from __future__ import annotations

import os

from langchain_core.language_models import BaseChatModel


def create_llm(
    model_id: str = "",
    region: str = "us-east-1",
    temperature: float = 0.1,
    max_tokens: int = 4096,
) -> BaseChatModel:
    """Create a LangChain chat model based on DIANA_LLM_PROVIDER env var.

    Provider defaults:
      bedrock: deepseek.v3.2
      ollama: deepseek-r1:8b
    """
    provider = os.environ.get("DIANA_LLM_PROVIDER", "bedrock").lower()

    if provider == "ollama":
        from langchain_ollama import ChatOllama
        ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        return ChatOllama(
            model=model_id or "deepseek-r1:8b",
            base_url=ollama_url,
            temperature=temperature,
            num_predict=max_tokens,
        )
    else:
        from langchain_aws import ChatBedrockConverse
        return ChatBedrockConverse(
            model=model_id or "deepseek.v3.2",
            region_name=region,
            temperature=temperature,
            max_tokens=max_tokens,
        )
