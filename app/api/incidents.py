from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException

from app.memory.database import SessionLocal
from app.memory.models import (
    Action,
    Evidence,
    Hypothesis,
    Incident,
    StateTransition,
    Verification,
)


router = APIRouter(
    prefix="/api/incidents",
    tags=["incidents"],
)


# ============================================================
# HELPERS
# ============================================================

def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None

    return value.isoformat()


def _json_loads(
    value: str | None,
    default: Any,
) -> Any:
    if not value:
        return default

    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


# ============================================================
# LIST INCIDENTS
# ============================================================

@router.get("")
def list_incidents() -> list[dict[str, Any]]:
    db = SessionLocal()

    try:
        incidents = (
            db.query(Incident)
            .order_by(Incident.created_at.desc())
            .all()
        )

        return [
            {
                "incident_id": incident.incident_id,
                "status": incident.status,
                "trigger_alert_id": incident.trigger_alert_id,
                "goal": incident.current_goal,
                "created_at": _iso(
                    incident.created_at
                ),
            }
            for incident in incidents
        ]

    finally:
        db.close()


# ============================================================
# COMPLETE INCIDENT
# ============================================================

@router.get("/{incident_id}")
def get_incident(
    incident_id: str,
) -> dict[str, Any]:

    db = SessionLocal()

    try:

        # ------------------------------------------------------
        # INCIDENT
        # ------------------------------------------------------

        incident = (
            db.query(Incident)
            .filter(
                Incident.incident_id == incident_id
            )
            .first()
        )

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )


        # ------------------------------------------------------
        # EVIDENCE
        # ------------------------------------------------------

        evidence = (
            db.query(Evidence)
            .filter(
                Evidence.incident_id == incident_id
            )
            .order_by(
                Evidence.collected_at.asc()
            )
            .all()
        )


        # ------------------------------------------------------
        # HYPOTHESES
        # ------------------------------------------------------

        hypotheses = (
            db.query(Hypothesis)
            .filter(
                Hypothesis.incident_id == incident_id
            )
            .order_by(
                Hypothesis.formed_at.asc()
            )
            .all()
        )


        # ------------------------------------------------------
        # ACTIONS
        # ------------------------------------------------------

        actions = (
            db.query(Action)
            .filter(
                Action.incident_id == incident_id
            )
            .order_by(
                Action.executed_at.asc()
            )
            .all()
        )


        # ------------------------------------------------------
        # VERIFICATIONS
        # ------------------------------------------------------

        verifications = (
            db.query(Verification)
            .filter(
                Verification.incident_id == incident_id
            )
            .order_by(
                Verification.verified_at.asc()
            )
            .all()
        )


        # ------------------------------------------------------
        # STATE TRANSITIONS
        # ------------------------------------------------------

        transitions = (
            db.query(StateTransition)
            .filter(
                StateTransition.incident_id == incident_id
            )
            .order_by(
                StateTransition.at.asc()
            )
            .all()
        )


        # ------------------------------------------------------
        # RESPONSE
        # ------------------------------------------------------

        return {

            "incident": {
                "incident_id": incident.incident_id,

                "status": incident.status,

                "trigger_alert_id": (
                    incident.trigger_alert_id
                ),

                "goal": incident.current_goal,

                "current_plan": _json_loads(
                    incident.current_plan_json,
                    None,
                ),

                "created_at": _iso(
                    incident.created_at
                ),
            },


            "evidence": [
                {
                    "id": item.id,

                    "source": item.source,

                    "tool": item.tool_used,

                    "query_params": _json_loads(
                        item.query_params_json,
                        {},
                    ),

                    "result": _json_loads(
                        item.raw_result_json,
                        {},
                    ),

                    "collected_at": _iso(
                        item.collected_at
                    ),
                }

                for item in evidence
            ],


            "hypotheses": [
                {
                    "id": item.id,

                    "statement": item.statement,

                    "confidence": item.confidence,

                    "evidence_ids": _json_loads(
                        item.supporting_evidence_ids_json,
                        [],
                    ),

                    "status": item.status,

                    "formed_at": _iso(
                        item.formed_at
                    ),
                }

                for item in hypotheses
            ],


            "actions": [
                {
                    "id": item.id,

                    "action_type": item.action_type,

                    "target": item.target,

                    "attempt": item.attempt_number,

                    "tool_call": _json_loads(
                        item.tool_call_json,
                        {},
                    ),

                    "executed_at": _iso(
                        item.executed_at
                    ),
                }

                for item in actions
            ],


            "verifications": [
                {
                    "id": item.id,

                    "action_id": item.action_id,

                    "method": item.method,

                    "result": item.result,

                    "check": _json_loads(
                        item.raw_check_json,
                        {},
                    ),

                    "verified_at": _iso(
                        item.verified_at
                    ),
                }

                for item in verifications
            ],


            "transitions": [
                {
                    "id": item.id,

                    "from": item.from_state,

                    "to": item.to_state,

                    "reason": item.reason,

                    "triggered_by": item.triggered_by,

                    "at": _iso(
                        item.at
                    ),
                }

                for item in transitions
            ],
        }

    finally:
        db.close()


# ============================================================
# INCIDENT TIMELINE
# ============================================================

@router.get("/{incident_id}/timeline")
def incident_timeline(
    incident_id: str,
) -> list[dict[str, Any]]:

    db = SessionLocal()

    try:

        # ------------------------------------------------------
        # VERIFY INCIDENT EXISTS
        # ------------------------------------------------------

        incident = (
            db.query(Incident)
            .filter(
                Incident.incident_id == incident_id
            )
            .first()
        )

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )


        events: list[dict[str, Any]] = []


        # ------------------------------------------------------
        # STATE TRANSITIONS
        # ------------------------------------------------------

        transitions = (
            db.query(StateTransition)
            .filter(
                StateTransition.incident_id == incident_id
            )
            .order_by(
                StateTransition.at.asc()
            )
            .all()
        )

        for item in transitions:

            events.append(
                {
                    "type": "state_transition",

                    "timestamp": _iso(
                        item.at
                    ),

                    "title": (
                        f"{item.from_state} → "
                        f"{item.to_state}"
                    ),

                    "description": item.reason,

                    "triggered_by":
                        item.triggered_by,
                }
            )


        # ------------------------------------------------------
        # EVIDENCE
        # ------------------------------------------------------

        evidence = (
            db.query(Evidence)
            .filter(
                Evidence.incident_id == incident_id
            )
            .order_by(
                Evidence.collected_at.asc()
            )
            .all()
        )

        for item in evidence:

            events.append(
                {
                    "type": "evidence",

                    "timestamp": _iso(
                        item.collected_at
                    ),

                    "title":
                        item.tool_used,

                    "description": (
                        f"Evidence source: "
                        f"{item.source}"
                    ),

                    "tool":
                        item.tool_used,

                    "source":
                        item.source,
                }
            )


        # ------------------------------------------------------
        # HYPOTHESES
        # ------------------------------------------------------

        hypotheses = (
            db.query(Hypothesis)
            .filter(
                Hypothesis.incident_id == incident_id
            )
            .order_by(
                Hypothesis.formed_at.asc()
            )
            .all()
        )

        for item in hypotheses:

            confidence_percent = round(
                item.confidence * 100
            )

            events.append(
                {
                    "type": "hypothesis",

                    "timestamp": _iso(
                        item.formed_at
                    ),

                    "title":
                        "Threat hypothesis formed",

                    "description": (
                        f"{item.statement} "
                        f"Confidence: "
                        f"{confidence_percent}%"
                    ),

                    "confidence":
                        item.confidence,

                    "status":
                        item.status,
                }
            )


        # ------------------------------------------------------
        # ACTIONS
        # ------------------------------------------------------

        actions = (
            db.query(Action)
            .filter(
                Action.incident_id == incident_id
            )
            .order_by(
                Action.executed_at.asc()
            )
            .all()
        )

        for item in actions:

            tool_call = _json_loads(
                item.tool_call_json,
                {},
            )

            events.append(
                {
                    "type": "action",

                    "timestamp": _iso(
                        item.executed_at
                    ),

                    "title":
                        item.action_type,

                    "description": (
                        f"Target: {item.target}"
                    ),

                    "target":
                        item.target,

                    "tool":
                        tool_call.get(
                            "tool",
                            item.action_type,
                        ),

                    "attempt":
                        item.attempt_number,
                }
            )


        # ------------------------------------------------------
        # VERIFICATIONS
        # ------------------------------------------------------

        verifications = (
            db.query(Verification)
            .filter(
                Verification.incident_id == incident_id
            )
            .order_by(
                Verification.verified_at.asc()
            )
            .all()
        )

        for item in verifications:

            check = _json_loads(
                item.raw_check_json,
                {},
            )

            description = (
                f"Result: {item.result}"
            )

            reason = check.get(
                "reason"
            )

            if reason:
                description += (
                    f" · {reason}"
                )

            observed_sources = check.get(
                "observed_sources"
            )

            if observed_sources:
                description += (
                    " · Sources: "
                    + ", ".join(
                        map(
                            str,
                            observed_sources,
                        )
                    )
                )

            events.append(
                {
                    "type": "verification",

                    "timestamp": _iso(
                        item.verified_at
                    ),

                    "title":
                        item.method,

                    "description":
                        description,

                    "result":
                        item.result,

                    "check":
                        check,

                    "action_id":
                        item.action_id,
                }
            )


        # ------------------------------------------------------
        # SORT EVERYTHING CHRONOLOGICALLY
        # ------------------------------------------------------

        events.sort(
            key=lambda event:
                event.get(
                    "timestamp"
                ) or ""
        )


        return events

    finally:
        db.close()