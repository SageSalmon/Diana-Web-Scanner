"""Token usage tracking — records input/output tokens per module per scan.

Uses LangChain callbacks to capture token counts from every LLM call,
then persists to the scan_token_usage table.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler

from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker


class TokenTracker(BaseCallbackHandler):
    """LangChain callback that accumulates token usage per module.

    Usage:
        tracker = TokenTracker(scan_state=state, scan_id=scan_id)
        llm = create_llm(callbacks=[tracker])

        tracker.set_module("sqli_agent")
        # ... run agent ...
        usage = tracker.get_usage("sqli_agent")
        # {"input_tokens": 12000, "output_tokens": 3000, "calls": 15}

        tracker.persist(scan_id, state)  # Write to DB
    """

    def __init__(self, scan_state=None, scan_id: str = ""):
        super().__init__()
        self._lock = threading.Lock()
        self._current_module: str = "unknown"
        self._usage: dict[str, dict[str, int]] = {}
        self._scan_state = scan_state
        self._scan_id = scan_id

    def set_module(self, module: str) -> None:
        """Set the current module name for attribution."""
        self._current_module = module

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called after each LLM invocation — capture token usage."""
        usage_metadata = None

        # LangChain wraps usage in different places depending on provider
        if hasattr(response, "llm_output") and response.llm_output:
            usage_metadata = response.llm_output.get("usage")
            if not usage_metadata:
                usage_metadata = response.llm_output.get("token_usage")

        # Also check response generations for usage_metadata
        if not usage_metadata and hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    if hasattr(gen, "message") and hasattr(gen.message, "usage_metadata"):
                        um = gen.message.usage_metadata
                        if um:
                            usage_metadata = {
                                "input_tokens": um.get("input_tokens", 0),
                                "output_tokens": um.get("output_tokens", 0),
                            }
                            break

        if not usage_metadata:
            # No token data available — just count the call
            with self._lock:
                if self._current_module not in self._usage:
                    self._usage[self._current_module] = {
                        "input_tokens": 0, "output_tokens": 0, "calls": 0,
                    }
                self._usage[self._current_module]["calls"] += 1
            return

        input_tokens = usage_metadata.get("input_tokens", 0) or usage_metadata.get("prompt_tokens", 0) or 0
        output_tokens = usage_metadata.get("output_tokens", 0) or usage_metadata.get("completion_tokens", 0) or 0

        with self._lock:
            if self._current_module not in self._usage:
                self._usage[self._current_module] = {
                    "input_tokens": 0, "output_tokens": 0, "calls": 0,
                }
            self._usage[self._current_module]["input_tokens"] += input_tokens
            self._usage[self._current_module]["output_tokens"] += output_tokens
            self._usage[self._current_module]["calls"] += 1

        # Also push to module_metrics table for real-time tracking
        if self._scan_state and self._scan_id:
            try:
                self._scan_state.increment_module_metrics(
                    self._scan_id, self._current_module,
                    llm_calls=1,
                    llm_input_tokens=input_tokens,
                    llm_output_tokens=output_tokens,
                )
            except Exception:
                pass  # Don't crash the scan over metrics

    def get_usage(self, module: str | None = None) -> dict:
        """Get token usage for a module or all modules."""
        with self._lock:
            if module:
                return dict(self._usage.get(module, {
                    "input_tokens": 0, "output_tokens": 0, "calls": 0,
                }))
            return {k: dict(v) for k, v in self._usage.items()}

    def get_total(self) -> dict:
        """Get total token usage across all modules."""
        with self._lock:
            total = {"input_tokens": 0, "output_tokens": 0, "calls": 0}
            for usage in self._usage.values():
                total["input_tokens"] += usage["input_tokens"]
                total["output_tokens"] += usage["output_tokens"]
                total["calls"] += usage["calls"]
            return total

    def persist(self, scan_id: str, scan_state) -> None:
        """Write accumulated token usage to the database."""
        if not scan_state:
            return

        with self._lock:
            for module, usage in self._usage.items():
                scan_state.store_token_usage(
                    scan_id=scan_id,
                    module=module,
                    input_tokens=usage["input_tokens"],
                    output_tokens=usage["output_tokens"],
                    calls=usage["calls"],
                )

    def print_summary(self) -> None:
        """Print token usage summary to stdout."""
        total = self.get_total()
        if total["calls"] == 0:
            return

        print(f"\n  Token Usage:")
        with self._lock:
            for module, usage in sorted(self._usage.items()):
                print(
                    f"    {module:25s} "
                    f"in={usage['input_tokens']:>8,} "
                    f"out={usage['output_tokens']:>7,} "
                    f"calls={usage['calls']}"
                )
        print(
            f"    {'TOTAL':25s} "
            f"in={total['input_tokens']:>8,} "
            f"out={total['output_tokens']:>7,} "
            f"calls={total['calls']}"
        )
