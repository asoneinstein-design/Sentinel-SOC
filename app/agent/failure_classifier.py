from typing import Any


class FailureClassifier:
    """
    Classifies verified environmental failures into actionable
    recovery categories.

    This component must use actual verifier output, not LLM guesses.
    """

    def classify(self, verification: dict[str, Any]) -> dict[str, Any]:
        if verification.get("status") == "SUCCESS":
            return {
                "failure": False,
                "failure_class": None,
                "reason": "VERIFICATION_SUCCEEDED",
                "recommended_recovery": None,
            }

        reason = verification.get("reason")

        if reason == "ACTIVE_TRAFFIC_REMAINS":
            observed_sources = verification.get(
                "observed_sources", []
            )

            if len(observed_sources) > 0:
                return {
                    "failure": True,
                    "failure_class": "IP_ROTATION",
                    "reason": (
                        "Original source was contained, but active "
                        "traffic remains from another source."
                    ),
                    "observed_sources": observed_sources,
                    "recommended_recovery": "QUARANTINE_HOST",
                }

            return {
                "failure": True,
                "failure_class": "UNKNOWN_ACTIVE_TRAFFIC",
                "reason": "Active traffic remains after containment.",
                "observed_sources": [],
                "recommended_recovery": "FURTHER_INVESTIGATION",
            }

        if reason == "TARGET_HOST_NOT_FOUND":
            return {
                "failure": True,
                "failure_class": "WRONG_TARGET",
                "reason": "The requested target host does not exist.",
                "recommended_recovery": "REFRESH_ASSET_STATE",
            }

        if reason == "HOST_ISOLATED":
            return {
                "failure": False,
                "failure_class": None,
                "reason": "HOST_ALREADY_ISOLATED",
                "recommended_recovery": None,
            }

        return {
            "failure": True,
            "failure_class": "UNKNOWN_FAILURE",
            "reason": "The verifier reported an unclassified failure.",
            "recommended_recovery": "REINVESTIGATE",
        }
