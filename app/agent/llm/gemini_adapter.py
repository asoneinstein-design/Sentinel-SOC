from __future__ import annotations

import os
from typing import Any

from google import genai
from google.genai import types

from .base import LLMAdapter


class GeminiAdapter(LLMAdapter):
    """Gemini fallback adapter with Ollama -> Gemini tool translation."""

    def __init__(
        self,
        model: str = "gemini-3.6-flash",
    ) -> None:
        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is not configured."
            )

        self.model = model

        self.client = genai.Client(
            api_key=api_key,
        )

    def _convert_tools(
        self,
        tools: list[dict[str, Any]] | None,
    ) -> list[types.Tool] | None:

        if not tools:
            return None

        function_declarations: list[dict[str, Any]] = []

        for tool in tools:
            function = tool.get("function")

            if not isinstance(function, dict):
                continue

            name = function.get("name")

            if not name:
                continue

            declaration = {
                "name": name,
                "description": function.get(
                    "description",
                    "",
                ),
                "parameters": function.get(
                    "parameters",
                    {
                        "type": "object",
                        "properties": {},
                    },
                ),
            }

            function_declarations.append(
                declaration
            )

        if not function_declarations:
            return None

        return [
            types.Tool(
                function_declarations=function_declarations
            )
        ]

    def _build_contents(
        self,
        messages: list[dict[str, Any]],
    ) -> tuple[str | None, list[types.Content]]:

        system_instruction: str | None = None
        contents: list[types.Content] = []

        for message in messages:

            role = message.get(
                "role",
                "user",
            )

            if role == "system":
                system_instruction = str(
                    message.get(
                        "content",
                        "",
                    )
                )
                continue

            if role == "assistant":
                gemini_role = "model"
            else:
                gemini_role = "user"

            content = message.get(
                "content",
                "",
            )

            if content is None:
                content = ""

            contents.append(
                types.Content(
                    role=gemini_role,
                    parts=[
                        types.Part.from_text(
                            text=str(content)
                        )
                    ],
                )
            )

        return system_instruction, contents

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:

        system_instruction, contents = (
            self._build_contents(messages)
        )

        gemini_tools = self._convert_tools(
            tools
        )

        config_kwargs: dict[str, Any] = {
            "automatic_function_calling": (
                types.AutomaticFunctionCallingConfig(
                    disable=True
                )
            )
        }

        if system_instruction:
            config_kwargs[
                "system_instruction"
            ] = system_instruction

        if gemini_tools:
            config_kwargs["tools"] = gemini_tools

        config = types.GenerateContentConfig(
            **config_kwargs
        )

        response = self.client.models.generate_content(
            model=self.model,
            contents=contents,
            config=config,
        )

        assistant_message: dict[str, Any] = {
            "role": "assistant",
            "content": "",
            "tool_calls": [],
        }

        if not response.candidates:
            return {
                "model": self.model,
                "message": assistant_message,
            }

        candidate = response.candidates[0]

        if not candidate.content:
            return {
                "model": self.model,
                "message": assistant_message,
            }

        text_parts: list[str] = []

        for index, part in enumerate(
            candidate.content.parts
        ):

            if getattr(part, "text", None):
                text_parts.append(
                    part.text
                )

            function_call = getattr(
                part,
                "function_call",
                None,
            )

            if function_call:

                arguments = dict(
                    function_call.args or {}
                )

                call_id = getattr(
                    function_call,
                    "id",
                    None,
                )

                if not call_id:
                    call_id = (
                        f"gemini-call-{index}"
                    )

                assistant_message[
                    "tool_calls"
                ].append(
                    {
                        "id": call_id,
                        "function": {
                            "name": function_call.name,
                            "arguments": arguments,
                        },
                    }
                )

        if text_parts:
            assistant_message["thinking"] = (
                "\n".join(text_parts)
            )

        return {
            "model": self.model,
            "message": assistant_message,
        }