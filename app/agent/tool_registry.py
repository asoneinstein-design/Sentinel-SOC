from __future__ import annotations

from typing import Any, Callable

from app.environment.simulator import SOCEnvironment
from app.tools.cve_lookup import lookup_cve
from app.tools.firewall import firewall_block
from app.tools.network import check_network_activity
from app.tools.nids import search_nids_alerts
from app.tools.quarantine import quarantine_host
from app.tools.server_logs import search_server_logs


class ToolRegistry:
    """
    Controlled registry of tools available to the LLM.

    The LLM can request a tool by name, but execution is always
    performed by this Python registry.

    Arguments are validated before the underlying function runs.
    """

    def __init__(self, environment: SOCEnvironment) -> None:
        self.environment = environment

        self._tools: dict[str, Callable[..., dict[str, Any]]] = {
            "search_nids_alerts": self._search_nids_alerts,
            "search_server_logs": self._search_server_logs,
            "lookup_cve": self._lookup_cve,
            "check_network_activity": self._check_network_activity,
            "firewall_block": self._firewall_block,
            "quarantine_host": self._quarantine_host,
        }

        self._allowed_arguments: dict[str, set[str]] = {
            "search_nids_alerts": {
                "incident_id",
                "source_ip",
                "destination_ip",
            },
            "search_server_logs": {
                "host",
                "source_ip",
            },
            "lookup_cve": {
                "service",
                "version",
            },
            "check_network_activity": {
                "target_ip",
                "target_host_ip",
            },
            "firewall_block": {
                "ip",
                "reason",
            },
            "quarantine_host": {
                "host_id",
                "reason",
            },
        }

        self._required_arguments: dict[str, set[str]] = {
            "search_nids_alerts": set(),
            "search_server_logs": set(),
            "lookup_cve": {
                "service",
                "version",
            },
            "check_network_activity": set(),
            "firewall_block": {
                "ip",
                "reason",
            },
            "quarantine_host": {
                "host_id",
                "reason",
            },
        }

    def definitions(self) -> list[dict[str, Any]]:
        """Return all tool definitions in Ollama-compatible format."""

        return [
            {
                "type": "function",
                "function": {
                    "name": "search_nids_alerts",
                    "description": (
                        "Search NIDS alerts for suspicious network activity. "
                        "Do not provide a service parameter."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "incident_id": {
                                "type": "string",
                                "description": "Optional incident identifier.",
                            },
                            "source_ip": {
                                "type": "string",
                                "description": "Optional source IP address.",
                            },
                            "destination_ip": {
                                "type": "string",
                                "description": "Optional destination IP address.",
                            },
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_server_logs",
                    "description": (
                        "Search authentication, process, and server logs."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "host": {
                                "type": "string",
                                "description": "Hostname such as FILE-01.",
                            },
                            "source_ip": {
                                "type": "string",
                                "description": "Source IP address.",
                            },
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "lookup_cve",
                    "description": (
                        "Look up vulnerabilities for an exact service and version."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "service": {
                                "type": "string",
                                "description": "Service name such as SMB.",
                            },
                            "version": {
                                "type": "string",
                                "description": "Exact service version.",
                            },
                        },
                        "required": ["service", "version"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "check_network_activity",
                    "description": (
                        "Check active network connections in the SOC environment."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target_ip": {
                                "type": "string",
                                "description": "Optional source IP address.",
                            },
                            "target_host_ip": {
                                "type": "string",
                                "description": "Optional destination host IP.",
                            },
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "firewall_block",
                    "description": (
                        "Block a malicious source IP in the simulated firewall. "
                        "Use only after compromise has been established."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ip": {
                                "type": "string",
                                "description": "Source IP to block.",
                            },
                            "reason": {
                                "type": "string",
                                "description": "Reason for containment.",
                            },
                        },
                        "required": ["ip", "reason"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "quarantine_host",
                    "description": (
                        "Isolate a compromised host in the simulated environment."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "host_id": {
                                "type": "string",
                                "description": "Host ID such as FILE-01.",
                            },
                            "reason": {
                                "type": "string",
                                "description": "Reason for host quarantine.",
                            },
                        },
                        "required": ["host_id", "reason"],
                    },
                },
            },
        ]

    def execute(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Validate and execute a registered tool.

        Invalid arguments are returned as structured tool errors so
        the LLM can correct itself on the next turn.
        """

        tool = self._tools.get(name)

        if tool is None:
            return {
                "success": False,
                "error": f"Unknown tool: {name}",
                "error_type": "UNKNOWN_TOOL",
            }

        if not isinstance(arguments, dict):
            return {
                "success": False,
                "error": "Tool arguments must be a JSON object.",
                "error_type": "INVALID_ARGUMENT_FORMAT",
            }

        validation_error = self._validate_arguments(
            name,
            arguments,
        )

        if validation_error is not None:
            return {
                "success": False,
                "error": validation_error,
                "error_type": "INVALID_ARGUMENTS",
                "tool": name,
                "allowed_arguments": sorted(
                    self._allowed_arguments[name]
                ),
            }

        try:
            result = tool(**arguments)

            return {
                "success": True,
                "result": result,
            }

        except Exception as exc:
            return {
                "success": False,
                "error": str(exc),
                "error_type": "TOOL_EXECUTION_ERROR",
                "tool": name,
            }

    def _validate_arguments(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> str | None:

        allowed = self._allowed_arguments[tool_name]
        required = self._required_arguments[tool_name]

        unknown = set(arguments) - allowed

        if unknown:
            unknown_names = ", ".join(sorted(unknown))

            return (
                f"Unsupported argument(s) for {tool_name}: "
                f"{unknown_names}. "
                f"Allowed arguments are: "
                f"{', '.join(sorted(allowed))}."
            )

        missing = {
            name
            for name in required
            if name not in arguments
            or arguments[name] is None
            or (
                isinstance(arguments[name], str)
                and not arguments[name].strip()
            )
        }

        if missing:
            return (
                f"Missing required argument(s) for {tool_name}: "
                f"{', '.join(sorted(missing))}."
            )

        return None

    def _search_nids_alerts(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return search_nids_alerts(**kwargs)

    def _search_server_logs(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return search_server_logs(**kwargs)

    def _lookup_cve(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return lookup_cve(**kwargs)

    def _check_network_activity(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return check_network_activity(
            self.environment,
            **kwargs,
        )

    def _firewall_block(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return firewall_block(
            self.environment,
            **kwargs,
        )

    def _quarantine_host(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return quarantine_host(
            self.environment,
            **kwargs,
        )