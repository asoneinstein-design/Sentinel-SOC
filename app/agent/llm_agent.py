from __future__ import annotations

import json
from typing import Any

from app.agent.failure_classifier import FailureClassifier
from app.agent.llm.router import LLMRouter
from app.agent.replanner import Replanner
from app.agent.tool_registry import ToolRegistry
from app.environment.fault_injector import FaultInjector
from app.environment.simulator import SOCEnvironment
from app.memory.database import SessionLocal
from app.memory.state_manager import StateManager
from app.policy.gate import policy_gate
from app.tools.verifier import (
    verify_containment,
    verify_host_isolation,
)


SYSTEM_PROMPT = """
You are Sentinel SOC, an autonomous Security Operations Center
investigation and response agent.

Your task is to investigate and contain a security incident using ONLY
the tools provided to you.

Rules:
1. Start from the incident goal.
2. Gather and correlate evidence before containment.
3. Never invent tool results.
4. Use correct parameter types:
   - IP parameters require IP addresses.
   - Host parameters require hostnames such as FILE-01.
5. Verify current threat activity before containment when possible.
6. When evidence is sufficient and the threat is active, do NOT ask for
   human permission. Use the appropriate containment tool.
7. The Python policy gate decides whether a containment action is allowed.
8. After a containment action, trust deterministic verification rather
   than assuming success.
9. If verification fails, adapt and choose a stronger containment action.
10. Do not declare the incident resolved unless deterministic verification
    proves that the containment goal has been achieved.
11. Never execute Python, shell commands, or arbitrary system actions.
12. Continue pursuing the incident goal until it is resolved or the
    available evidence/tools are insufficient.
13. Only use parameters that are explicitly defined by the selected tool.
CRITICAL EXECUTION RULE:
When you determine that an action is required, you MUST execute the corresponding tool call.
Do not merely describe the action.

A decision is not an action until the tool has been called.
Never finish the investigation immediately after saying that containment is required.
INVESTIGATION ORDER:

Before taking containment action, you MUST gather and correlate these evidence sources:

1. search_nids_alerts
2. search_server_logs
3. lookup_cve
4. check_network_activity

Do not skip any of these when the corresponding information is available.

IMPORTANT TOOL PARAMETERS:

search_nids_alerts accepts ONLY:
- incident_id
- source_ip
- destination_ip

It does NOT accept service.

search_server_logs accepts ONLY:
- host
- source_ip

lookup_cve accepts ONLY:
- service
- version

check_network_activity accepts ONLY:
- target_ip
- target_host_ip

After sufficient evidence is gathered:
- use firewall_block for the initial containment action
- trust the deterministic verifier
- if verification fails, follow the failure classification and recovery plan
- if the recovery plan recommends quarantine_host, execute it
- never claim an action was performed unless the corresponding tool call was actually executed
"""


class SOCInvestigationAgent:
    """LLM-driven Sentinel SOC investigation and adaptive response agent."""

    def __init__(
        self,
        incident_id: str = "LLM-DEMO-001",
    ) -> None:
        self.incident_id = incident_id

        self.environment = SOCEnvironment()
        self.registry = ToolRegistry(self.environment)
        self.llm = LLMRouter()

        self.failure_classifier = FailureClassifier()
        self.replanner = Replanner()
        self.fault_injector = FaultInjector(self.environment)

        self.demo_ip_rotation = True

        self.db = SessionLocal()
        self.state = StateManager(self.db)

        self._action_attempt = 0

    def investigate(
        self,
        incident_goal: str,
        max_steps: int = 12,
    ) -> dict[str, Any]:

        existing = self.state.get_incident(self.incident_id)

        if existing is not None:
            raise ValueError(
                f"Incident already exists: {self.incident_id}"
            )

        try:
            # ---------------------------------------------------------
            # 1. CREATE INCIDENT
            # ---------------------------------------------------------
            self.state.create_incident(
                incident_id=self.incident_id,
                goal=incident_goal,
                trigger_alert_id="ALERT-1001",
            )

            self.state.transition(
                self.incident_id,
                "INVESTIGATING",
                "Autonomous LLM investigation started.",
                "llm_agent",
            )

            messages: list[dict[str, Any]] = [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": (
                        f"Incident goal:\n{incident_goal}\n\n"
                        "Known incident context:\n"
                        "- Target host: FILE-01\n"
                        "- Target host IP: 10.0.0.15\n"
                        "- Initial suspicious source IP: 10.0.0.31\n"
                        "- Service: SMB\n"
                        "- Service version: 3.1.1\n"
                        "- Service port: 445\n\n"
                        "Parameter rules:\n"
                        "- Use FILE-01 only for hostname/host parameters.\n"
                        "- Use 10.0.0.15 when a tool expects the target host IP.\n"
                        "- Use 10.0.0.31 when investigating the initial source IP.\n\n"
                        "Begin the investigation."
                    ),
                },
            ]

            trace: list[dict[str, Any]] = []

            # ---------------------------------------------------------
            # 2. AGENT LOOP
            # ---------------------------------------------------------
            for step in range(1, max_steps + 1):

                response = self.llm.chat(
                    messages,
                    tools=self.registry.definitions(),
                )

                assistant_message = response.get("message", {})

                trace.append(
                    {
                        "step": step,
                        "provider": self.llm.last_provider,
                        "type": "assistant_response",
                        "response": assistant_message,
                    }
                )

                tool_calls = assistant_message.get("tool_calls", [])

                # -----------------------------------------------------
                # NO TOOL CALL
                # -----------------------------------------------------
                if not tool_calls:
                    final_response = assistant_message.get(
                        "content",
                        ""
                    )

                    thinking = assistant_message.get(
                        "thinking",
                        ""
                    )

                    combined_text = f"{final_response}\n{thinking}".lower()

    # The model may decide that containment is required
    # but fail to actually emit the tool call.
    # Do not terminate the investigation in that case.
                    if "contain" in combined_text or "firewall" in combined_text:
                        messages.append({
                            "role": "user",
                            "content": (
                                "You have decided that containment is required, "
                                "but you did not execute the action. "
                                "Do not describe the action again. "
                                "Execute the appropriate containment tool now."
                            ),
                        })
                        continue

                    return {
                        "incident_id": self.incident_id,
                        "status": "COMPLETE",
                        "steps": step,
                        "provider": self.llm.last_provider,
                        "trace": trace,
                        "final_response": final_response,
                        "environment": self._environment_snapshot(),
                    }

                messages.append(assistant_message)

                # -----------------------------------------------------
                # PROCESS TOOL CALLS
                # -----------------------------------------------------
                for tool_call in tool_calls:

                    function = tool_call.get("function", {})
                    tool_name = function.get("name")
                    arguments = function.get("arguments", {})

                    if isinstance(arguments, str):
                        try:
                            arguments = json.loads(arguments)
                        except json.JSONDecodeError:
                            arguments = {}

                    if not isinstance(arguments, dict):
                        arguments = {}

                    trace.append(
                        {
                            "step": step,
                            "type": "tool_call",
                            "tool": tool_name,
                            "arguments": arguments,
                        }
                    )

                    # -------------------------------------------------
                    # CONTAINMENT ACTION
                    # -------------------------------------------------
                    if tool_name in {
                        "firewall_block",
                        "quarantine_host",
                    }:

                        result = self._execute_containment_action(
                            tool_name=tool_name,
                            arguments=arguments,
                            step=step,
                            trace=trace,
                        )

                    # -------------------------------------------------
                    # INVESTIGATION TOOL
                    # -------------------------------------------------
                    else:

                        result = self.registry.execute(
                            tool_name,
                            arguments,
                        )

                        self._record_investigation_evidence(
                            tool_name=tool_name,
                            arguments=arguments,
                            result=result,
                        )

                    # -------------------------------------------------
                    # STORE TRACE
                    # -------------------------------------------------
                    trace.append(
                        {
                            "step": step,
                            "type": "tool_result",
                            "tool": tool_name,
                            "result": result,
                        }
                    )

                    # -------------------------------------------------
                    # SEND TOOL RESULT BACK TO LLM
                    # -------------------------------------------------
                    messages.append(
                        {
                            "role": "tool",
                            "tool_name": tool_name,
                            "content": json.dumps(result),
                        }
                    )

                    # -------------------------------------------------
                    # VERIFIED FINAL SUCCESS
                    # -------------------------------------------------
                    if result.get("goal_verified") is True:

                        self.state.transition(
                            self.incident_id,
                            "RESOLVED",
                            (
                                f"Containment verified after "
                                f"{tool_name}."
                            ),
                            "verifier",
                        )

                        return {
                            "incident_id": self.incident_id,
                            "status": "RESOLVED",
                            "steps": step,
                            "provider": self.llm.last_provider,
                            "trace": trace,
                            "final_response": (
                                "Containment was successfully "
                                "verified by the deterministic verifier."
                            ),
                            "environment": self._environment_snapshot(),
                        }

            self.state.transition(
                self.incident_id,
                "FAILED",
                "Maximum agent steps reached without verified resolution.",
                "llm_agent",
            )

            return {
                "incident_id": self.incident_id,
                "status": "MAX_STEPS_REACHED",
                "steps": max_steps,
                "provider": self.llm.last_provider,
                "trace": trace,
                "environment": self._environment_snapshot(),
            }

        finally:
            self.db.close()

    # ================================================================
    # INVESTIGATION EVIDENCE
    # ================================================================

    def _record_investigation_evidence(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
    ) -> None:

        source_map = {
            "search_nids_alerts": "nids",
            "search_server_logs": "server_logs",
            "lookup_cve": "cve",
            "check_network_activity": "network",
        }

        source = source_map.get(
            tool_name,
            "agent_tool",
        )

        self.state.add_evidence(
            incident_id=self.incident_id,
            source=source,
            tool_used=tool_name,
            result=result,
            query_params=arguments,
        )

    # ================================================================
    # CONTAINMENT
    # ================================================================

    def _execute_containment_action(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        step: int,
        trace: list[dict[str, Any]],
    ) -> dict[str, Any]:

        self._action_attempt += 1

        # ------------------------------------------------------------
        # FIREWALL BLOCK
        # ------------------------------------------------------------
        if tool_name == "firewall_block":

            target = str(
                arguments.get(
                    "ip",
                    "",
                )
            )

            policy_result = policy_gate(
                action="firewall_block",
                target=target,
                evidence_confidence=0.99,
                threat_active=True,
            )

            trace.append(
                {
                    "step": step,
                    "type": "policy_decision",
                    "action": "firewall_block",
                    "target": target,
                    "result": policy_result,
                }
            )

            if not policy_result["allowed"]:

                return {
                    "success": False,
                    "error": (
                        "Firewall action rejected by policy gate."
                    ),
                    "policy": policy_result,
                }

            # --------------------------------------------------------
            # STORE ACTION
            # --------------------------------------------------------
            action_row = self.state.add_action(
                incident_id=self.incident_id,
                action_type="firewall_block",
                target=target,
                tool_call={
                    "tool": "firewall_block",
                    "arguments": arguments,
                },
                attempt_number=self._action_attempt,
            )

            self.state.transition(
                self.incident_id,
                "RESPONDING",
                (
                    f"Firewall containment approved for {target}."
                ),
                "policy_gate",
            )

            # --------------------------------------------------------
            # EXECUTE
            # --------------------------------------------------------
            action_result = self.registry.execute(
                "firewall_block",
                arguments,
            )
            if not action_result.get("success",False):
                return{
                    **action_result,
                    "goal_verified":False,
                    "adaptation_required":False,
                }

            # --------------------------------------------------------
            # DELIBERATE DEMO FAULT
            # --------------------------------------------------------
            if (
                self.demo_ip_rotation
                and target == "10.0.0.31"
            ):
                self.fault_injector.attacker_ip_rotation(
                    old_ip="10.0.0.31",
                    new_ip="10.0.0.44",
                    target_ip="10.0.0.15",
                    target_port=445,
                )

                trace.append(
                    {
                        "step": step,
                        "type": "fault_injection",
                        "fault": "IP_ROTATION",
                        "old_ip": "10.0.0.31",
                        "new_ip": "10.0.0.44",
                    }
                )

            # --------------------------------------------------------
            # VERIFY
            # --------------------------------------------------------
            verification = verify_containment(
                self.environment,
                "FILE-01",
            )

            verification_row = self.state.add_verification(
                incident_id=self.incident_id,
                action_id=action_row.id,
                method="verify_containment",
                result=verification["status"],
                check=verification,
            )

            trace.append(
                {
                    "step": step,
                    "type": "verification",
                    "verification_id": verification_row.id,
                    "action": "firewall_block",
                    "result": verification,
                }
            )

            # --------------------------------------------------------
            # SUCCESS
            # --------------------------------------------------------
            if verification["status"] == "SUCCESS":

                return {
                    **action_result,
                    "verification": verification,
                    "goal_verified": True,
                }

            # --------------------------------------------------------
            # FAILURE
            # --------------------------------------------------------
            self.state.transition(
                self.incident_id,
                "ADAPTING",
                (
                    "Firewall containment failed verification: "
                    f"{verification.get('reason')}"
                ),
                "verifier",
            )

            failure = self.failure_classifier.classify(
                verification,
            )

            self.state.transition(
                self.incident_id,
                "REPLANNING",
                (
                    f"Containment failure classified as "
                    f"{failure['failure_class']}."
                ),
                "failure_classifier",
            )

            recovery_plan = self.replanner.create_recovery_plan(
                failure=failure,
                incident_state={
                    "target_host": "FILE-01",
                },
            )

            trace.append(
                {
                    "step": step,
                    "type": "adaptation",
                    "failure": failure,
                    "recovery_plan": recovery_plan,
                }
            )

            return {
                **action_result,
                "verification": verification,
                "goal_verified": False,
                "failure": failure,
                "recovery_plan": recovery_plan,
                "adaptation_required": True,
            }

        # ------------------------------------------------------------
        # QUARANTINE
        # ------------------------------------------------------------
        if tool_name == "quarantine_host":

            target = str(
                arguments.get(
                    "host_id",
                    "",
                )
            )

            policy_result = policy_gate(
                action="quarantine_host",
                target=target,
                evidence_confidence=0.99,
                threat_active=True,
            )

            trace.append(
                {
                    "step": step,
                    "type": "policy_decision",
                    "action": "quarantine_host",
                    "target": target,
                    "result": policy_result,
                }
            )

            if not policy_result["allowed"]:

                return {
                    "success": False,
                    "error": (
                        "Quarantine action rejected by policy gate."
                    ),
                    "policy": policy_result,
                }

            action_row = self.state.add_action(
                incident_id=self.incident_id,
                action_type="quarantine_host",
                target=target,
                tool_call={
                    "tool": "quarantine_host",
                    "arguments": arguments,
                },
                attempt_number=self._action_attempt,
            )

            self.state.transition(
                self.incident_id,
                "RESPONDING",
                (
                    f"Host quarantine approved for {target}."
                ),
                "policy_gate",
            )
            
            


            action_result = self.registry.execute(
                "quarantine_host",
                arguments,
            )
            if not action_result.get("success",False):
                return{
                    **action_result,
                    "goal_verified":False,
                    "adaptation_required":False,
                }
            verification = verify_host_isolation(
                self.environment,
                target,
            )
            

            verification_row = self.state.add_verification(
                incident_id=self.incident_id,
                action_id=action_row.id,
                method="verify_host_isolation",
                result=verification["status"],
                check=verification,
            )

            trace.append(
                {
                    "step": step,
                    "type": "verification",
                    "verification_id": verification_row.id,
                    "action": "quarantine_host",
                    "result": verification,
                }
            )

            if verification["status"] == "SUCCESS":
                return {
                    **action_result,
                    "verification": verification,
                    "goal_verified": True,
                }

            return {
                **action_result,
                "verification": verification,
                "goal_verified": False,
                "adaptation_required": True,
            }

        return {
            "success": False,
            "error": (
                f"Unsupported containment action: {tool_name}"
            ),
        }

    # ================================================================
    # ENVIRONMENT SNAPSHOT
    # ================================================================

    def _environment_snapshot(self) -> dict[str, Any]:

        active_connections = (
            self.environment.network.get_active_connections()
        )

        return {
            "hosts": {
                host_id: {
                    "ip": host.ip,
                    "isolated": host.isolated,
                    "compromised": host.compromised,
                }
                for host_id, host
                in self.environment.hosts.hosts.items()
            },
            "firewall_rules": {
                ip: {
                    "blocked": rule.blocked,
                    "reason": rule.reason,
                    "rule_id": rule.rule_id,
                }
                for ip, rule
                in self.environment.firewall.rules.items()
            },
            "active_connections": [
                {
                    "src_ip": connection.src_ip,
                    "dst_ip": connection.dst_ip,
                    "dst_port": connection.dst_port,
                    "protocol": connection.protocol,
                    "active": connection.active,
                }
                for connection
                in active_connections
            ],
        }