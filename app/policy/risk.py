from typing import Any


def assess_risk(
    action: str,
    evidence_confidence: float,
    threat_active: bool,
) -> dict[str, Any]:
    """
    Deterministic risk assessment.

    The LLM does not determine the final risk level.
    """

    if not threat_active:
        return {
            "risk": "LOW",
            "approved": False,
            "reason": "No active threat verified.",
        }

    if evidence_confidence >= 0.90:
        risk = "HIGH"
    elif evidence_confidence >= 0.70:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    approved = risk in {"HIGH", "MEDIUM"}

    return {
        "risk": risk,
        "approved": approved,
        "action": action,
        "evidence_confidence": evidence_confidence,
        "reason": (
            "Active threat with sufficient correlated evidence."
            if approved
            else "Insufficient evidence for automated containment."
        ),
    }
