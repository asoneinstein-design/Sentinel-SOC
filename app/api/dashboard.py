from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from app.memory.database import SessionLocal
from app.memory.models import (
    Action,
    Evidence,
    Incident,
    Verification,
)

router = APIRouter(
    prefix="/api/dashboard",
    tags=["dashboard"],
)


@router.get("/{incident_id}")
def dashboard_data(
    incident_id: str,
) -> dict[str, Any]:

    db = SessionLocal()

    try:
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

        evidence_count = (
            db.query(Evidence)
            .filter(
                Evidence.incident_id == incident_id
            )
            .count()
        )

        action_count = (
            db.query(Action)
            .filter(
                Action.incident_id == incident_id
            )
            .count()
        )

        verification_count = (
            db.query(Verification)
            .filter(
                Verification.incident_id == incident_id
            )
            .count()
        )

        successful_verifications = (
            db.query(Verification)
            .filter(
                Verification.incident_id == incident_id,
                Verification.result == "SUCCESS",
            )
            .count()
        )

        failed_verifications = (
            db.query(Verification)
            .filter(
                Verification.incident_id == incident_id,
                Verification.result == "FAILURE",
            )
            .count()
        )

        return {
            "incident_id": incident.incident_id,
            "status": incident.status,
            "goal": incident.current_goal,
            "created_at": (
                incident.created_at.isoformat()
                if incident.created_at
                else None
            ),
            "metrics": {
                "evidence_count": evidence_count,
                "action_count": action_count,
                "verification_count": verification_count,
                "successful_verifications": (
                    successful_verifications
                ),
                "failed_verifications": (
                    failed_verifications
                ),
            },
        }

    finally:
        db.close()
