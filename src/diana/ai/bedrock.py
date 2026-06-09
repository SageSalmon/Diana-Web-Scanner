"""LLM client for Diana AI operations.

Routes through Bedrock or Ollama based on DIANA_LLM_PROVIDER env var.
Uses the same LangChain LLM created by llm.py for consistency.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

logger = logging.getLogger(__name__)


class BedrockClient:
    """LLM client — works with Bedrock or Ollama via LangChain.

    Despite the name (kept for backward compatibility), this now routes
    through whichever provider is configured in DIANA_LLM_PROVIDER.
    """

    def __init__(
        self,
        model_id: str = "",
        region: str = "us-east-1",
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ):
        self.model_id = model_id
        self.region = region
        self.max_tokens = max_tokens
        self.temperature = temperature

        from diana.ai.llm import create_llm
        self._llm = create_llm(
            model_id=model_id,
            region=region,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def invoke(
        self,
        prompt: str,
        system: str = "",
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> str:
        """Invoke the model and return the text response."""
        messages = []
        if system:
            messages.append(SystemMessage(content=system))
        messages.append(HumanMessage(content=prompt))

        response = self._llm.invoke(messages)
        return response.content

    def invoke_json(
        self,
        prompt: str,
        system: str = "",
    ) -> dict[str, Any]:
        """Invoke the model and parse the response as JSON."""
        full_prompt = (
            f"{prompt}\n\n"
            "Respond with valid JSON only. No markdown, no code fences, no explanation."
        )
        text = self.invoke(full_prompt, system=system)

        # Strip markdown code fences if present
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])

        return json.loads(text)
