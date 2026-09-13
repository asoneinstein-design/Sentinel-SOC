from typing import Any


def build_hypothesis(
    nids_result: dict[str, Any],
    server_result: dict[str, Any],
    cve_result: dict[str, Any],
) -> dict[str, Any]:
    alerts = nids_result.get("alerts", [])

    authentication = server_result.get("authentication", {})
    failed_attempts = authentication.get("failed_attempts", 0)
    successful_authentication = authentication.get(
        "successful_authentication", []
    )

    suspicious_processes = server_result.get(
        "suspicious_processes", []
    )

    cve_matches = cve_result.get("matches", [])

    evidence_score = 0

    if alerts:
        evidence_score += 25

    if failed_attempts >= 2:
        evidence_score += 20

    if successful_authentication:
        evidence_score += 25

    if suspicious_processes:
        evidence_score += 20

    if cve_matches:
        evidence_score += 10

    confidence = min(evidence_score / 100, 0.99)

    compromised = (
        bool(alerts)
        and failed_attempts >= 2
        and bool(successful_authentication)
        and bool(suspicious_processes)
        and bool(cve_matches)
    )

    if compromised:
        statement = (
            "FILE-01 is likely compromised based on correlated "
            "network, authentication, process, and vulnerability evidence."
        )
        status = "CONFIRMED"
    else:
        statement = (
            "Available evidence is insufficient to confirm compromise."
        )
        status = "PROPOSED"

    evidence = {
        "nids_alerts": len(alerts),
        "failed_authentication_attempts": failed_attempts,
        "successful_authentication_events": len(
            successful_authentication
        ),
        "suspicious_processes": len(suspicious_processes),
        "cve_matches": len(cve_matches),
    }

    return {
        "statement": statement,
        "confidence": confidence,
        "status": status,
        "compromised": compromised,
        "evidence_summary": evidence,
    }
