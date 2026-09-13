from typing import Any


class Replanner:
    """
    Generates a recovery plan from the actual classified failure.

    This is deliberately deterministic for the first implementation.
    The LLM can be introduced later as a proposal layer.
    """

    def create_recovery_plan(
        self,
        failure: dict[str, Any],
        incident_state: dict[str, Any],
    ) -> dict[str, Any]:

        failure_class = failure.get("failure_class")

        if failure_class == "IP_ROTATION":
            return {
                "plan_type": "RECOVERY",
                "reason": "Individual IP blocking did not contain the threat.",
                "objective": "Contain the affected host.",
                "action": "quarantine_host",
                "target": incident_state.get(
                    "target_host", "FILE-01"
                ),
                "verification": "verify_host_isolation",
            }

        if failure_class == "WRONG_TARGET":
            return {
                "plan_type": "RECOVERY",
                "reason": "Target state is inconsistent.",
                "objective": "Refresh asset information.",
                "action": "refresh_asset_state",
                "target": incident_state.get(
                    "target_host", "FILE-01"
                ),
                "verification": "verify_target",
            }

        if failure_class == "UNKNOWN_ACTIVE_TRAFFIC":
            return {
                "plan_type": "RECOVERY",
                "reason": "Threat remains active but source is unclear.",
                "objective": "Investigate additional active sources.",
                "action": "check_network_activity",
                "target": incident_state.get(
                    "target_host", "FILE-01"
                ),
                "verification": "verify_network_activity",
            }

        return {
            "plan_type": "RECOVERY",
            "reason": "Failure could not be classified.",
            "objective": "Reinvestigate incident.",
            "action": "reinvestigate",
            "target": incident_state.get(
                "target_host", "FILE-01"
            ),
            "verification": "verify_evidence",
        }
