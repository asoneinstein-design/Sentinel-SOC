from typing import Any

from .base import LLMAdapter
from .ollama_adapter import OllamaAdapter
from .gemini_adapter import GeminiAdapter


class LLMRouter:
    """
    Routes LLM requests through the Sentinel SOC fallback chain.

    Primary:
        Qwen3 8B via local Ollama

    Backup:
        Gemini
    """

    def __init__(
        self,
        primary: LLMAdapter | None = None,
        fallback: LLMAdapter | None = None,
    ) -> None:
        self.primary = primary or OllamaAdapter()
        self.fallback = fallback or GeminiAdapter()

        self.last_provider: str | None = None
        self.last_error: str | None = None

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:

        # Try Qwen3 8B first.
        try:
            result = self.primary.chat(messages, tools)
            self.last_provider = "ollama"
            self.last_error = None

            return result

        except Exception as primary_error:
            self.last_error = str(primary_error)

            # Fall back to Gemini.
            try:
                result = self.fallback.chat(messages, tools)
                self.last_provider = "gemini"

                return result

            except Exception as fallback_error:
                self.last_provider = None
                raise RuntimeError(
                    "Both LLM providers failed.\n"
                    f"Qwen/Ollama error: {primary_error}\n"
                    f"Gemini error: {fallback_error}"
                ) from fallback_error
