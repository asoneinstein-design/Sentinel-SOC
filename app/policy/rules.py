from typing import Any


ALLOWED_ACTIONS = {
    "firewall_block",
    "quarantine_host",
}


def is_action_allowed(action: str) -> bool:
    return action in ALLOWED_ACTIONS


def validate_action(action: str, target: str) -> dict[str, Any]:
    if not is_action_allowed(action):
        return {
            "allowed": False,
            "reason": f"Action '{action}' is not permitted.",
        }

    if not target:
        return {
            "allowed": False,
            "reason": "Action target is required.",
        }

    return {
        "allowed": True,
        "reason": "Action is permitted by policy.",
    }
