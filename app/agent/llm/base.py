from abc import ABC, abstractmethod
from typing import Any


class LLMAdapter(ABC):
    """Common interface for all Sentinel LLM providers."""

    @abstractmethod
    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> Any:
        raise NotImplementedError
