import json
from typing import Any

from sqlalchemy.orm import Session

from app.memory.models import (
    Action,
    Evidence,
    Hypothesis,
    Incident,
    StateTransition,
    Verification,
)


class StateManager:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_incident(
        self,
        incident_id: str,
        goal: str,
        trigger_alert_id: str | None = None,
    ) -> Incident:
        incident = Incident(
            incident_id=incident_id,
            status="OPEN",
            trigger_alert_id=trigger_alert_id,
            current_goal=goal,
        )

        self.db.add(incident)
        self.db.commit()
        self.db.refresh(incident)

        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        return (
            self.db.query(Incident)
            .filter(Incident.incident_id == incident_id)
            .first()
        )

    def transition(
        self,
        incident_id: str,
        to_state: str,
        reason: str,
        triggered_by: str,
    ) -> StateTransition:
        incident = self.get_incident(incident_id)

        if incident is None:
            raise ValueError(f"Incident not found: {incident_id}")

        from_state = incident.status
        incident.status = to_state

        transition = StateTransition(
            incident_id=incident_id,
            from_state=from_state,
            to_state=to_state,
            reason=reason,
            triggered_by=triggered_by,
        )

        self.db.add(transition)
        self.db.commit()
        self.db.refresh(transition)

        return transition

    def add_evidence(
        self,
        incident_id: str,
        source: str,
        tool_used: str,
        result: dict[str, Any],
        query_params: dict[str, Any] | None = None,
    ) -> Evidence:
        evidence = Evidence(
            incident_id=incident_id,
            source=source,
            tool_used=tool_used,
            query_params_json=json.dumps(query_params or {}),
            raw_result_json=json.dumps(result),
        )

        self.db.add(evidence)
        self.db.commit()
        self.db.refresh(evidence)

        return evidence

    def add_hypothesis(
        self,
        incident_id: str,
        statement: str,
        confidence: float,
        evidence_ids: list[int],
        status: str = "PROPOSED",
    ) -> Hypothesis:
        hypothesis = Hypothesis(
            incident_id=incident_id,
            statement=statement,
            confidence=confidence,
            supporting_evidence_ids_json=json.dumps(evidence_ids),
            status=status,
        )

        self.db.add(hypothesis)
        self.db.commit()
        self.db.refresh(hypothesis)

        return hypothesis

    def add_action(
        self,
        incident_id: str,
        action_type: str,
        target: str,
        tool_call: dict[str, Any],
        attempt_number: int = 1,
    ) -> Action:
        action = Action(
            incident_id=incident_id,
            action_type=action_type,
            target=target,
            tool_call_json=json.dumps(tool_call),
            attempt_number=attempt_number,
        )

        self.db.add(action)
        self.db.commit()
        self.db.refresh(action)

        return action

    def add_verification(
        self,
        incident_id: str,
        method: str,
        result: str,
        check: dict[str, Any],
        action_id: int | None = None,
    ) -> Verification:
        verification = Verification(
            incident_id=incident_id,
            action_id=action_id,
            method=method,
            result=result,
            raw_check_json=json.dumps(check),
        )

        self.db.add(verification)
        self.db.commit()
        self.db.refresh(verification)

        return verification
