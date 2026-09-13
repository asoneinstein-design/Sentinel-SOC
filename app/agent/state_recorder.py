from __future__ import annotations

from typing import Any

from app.memory.database import SessionLocal
from app.memory.state_manager import StateManager


class AgentStateRecorder:
    """Persists LLM-agent activity into the Sentinel SOC state store."""

    def __init__(self, incident_id: str) -> None:
        self.incident_id = incident_id
        self.db = SessionLocal()
        self.state = StateManager(self.db)

    def create_incident(
        self,
        goal: str,
        trigger_alert_id: str = "ALERT-1001",
    ) -> None:
        existing = self.state.get_incident(self.incident_id)

        if existing is None:
            self.state.create_incident(
                incident_id=self.incident_id,
                goal=goal,
                trigger_alert_id=trigger_alert_id,
            )

    def transition(
        self,
        new_state: str,
        reason: str,
        actor: str,
    ) -> None:
        self.state.transition(
            self.incident_id,
            new_state,
            reason,
            actor,
        )

    def add_evidence(
        self,
        source: str,
        tool_used: str,
        result: dict[str, Any],
        query_params: dict[str, Any],
    ) -> None:
        self.state.add_evidence(
            incident_id=self.incident_id,
            source=source,
            tool_used=tool_used,
            result=result,
            query_params=query_params,
        )

    def add_action(
        self,
        action_type: str,
        target: str,
        tool_call: dict[str, Any],
        attempt_number: int,
    ) -> Any:
        return self.state.add_action(
            incident_id=self.incident_id,
            action_type=action_type,
            target=target,
            tool_call=tool_call,
            attempt_number=attempt_number,
        )

    def add_verification(
        self,
        action_id: Any,
        method: str,
        result: dict[str, Any],
    ) -> Any:
        return self.state.add_verification(
            incident_id=self.incident_id,
            action_id=action_id,
            method=method,
            result=result.get("status", "UNKNOWN"),
            check=result,
        )

    def close(self) -> None:
        self.db.close()
