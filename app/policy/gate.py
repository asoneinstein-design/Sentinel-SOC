from typing import Any

from app.policy.risk import assess_risk
from app.policy.rules import validate_action


def policy_gate(
    action: str,
    target: str,
    evidence_confidence: float,
    threat_active: bool,
) -> dict[str, Any]:
    """
    Deterministic safety gate.

    The LLM may propose an action, but this gate decides
    whether the action is permitted.
    """

    rule_check = validate_action(action, target)

    if not rule_check["allowed"]:
        return {
            "allowed": False,
            "stage": "RULE_CHECK",
            "reason": rule_check["reason"],
        }

    risk_check = assess_risk(
        action=action,
        evidence_confidence=evidence_confidence,
        threat_active=threat_active,
    )

    if not risk_check["approved"]:
        return {
            "allowed": False,
            "stage": "RISK_CHECK",
            "risk": risk_check["risk"],
            "reason": risk_check["reason"],
        }

    return {
        "allowed": True,
        "stage": "APPROVED",
        "risk": risk_check["risk"],
        "action": action,
        "target": target,
        "reason": risk_check["reason"],
    }
