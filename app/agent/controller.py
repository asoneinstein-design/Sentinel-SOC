from typing import Any

from app.agent.failure_classifier import FailureClassifier
from app.agent.hypothesis import build_hypothesis
from app.agent.replanner import Replanner
from app.environment.fault_injector import FaultInjector
from app.environment.simulator import SOCEnvironment
from app.memory.database import SessionLocal
from app.memory.state_manager import StateManager
from app.tools.cve_lookup import lookup_cve
from app.tools.firewall import firewall_block
from app.tools.nids import search_nids_alerts
from app.tools.network import check_network_activity
from app.tools.quarantine import quarantine_host
from app.tools.server_logs import search_server_logs
from app.tools.verifier import (
    verify_containment,
    verify_host_isolation,
)


class SOCController:
    def __init__(self) -> None:
        self.environment = SOCEnvironment()
        self.failure_classifier = FailureClassifier()
        self.replanner = Replanner()

    def run(self, incident_id: str = "DEMO-001") -> dict[str, Any]:
        db = SessionLocal()
        state = StateManager(db)

        try:
            # ---------------------------------------------------------
            # 1. CREATE INCIDENT
            # ---------------------------------------------------------
            incident = state.get_incident(incident_id)

            if incident is not None:
                raise ValueError(
                    f"Incident already exists: {incident_id}"
                )

            incident = state.create_incident(
                incident_id=incident_id,
                goal="Investigate and contain the suspicious activity on FILE-01.",
                trigger_alert_id="ALERT-1001",
            )

            state.transition(
                incident_id,
                "INVESTIGATING",
                "SOC incident investigation started.",
                "controller",
            )

            # ---------------------------------------------------------
            # 2. NIDS INVESTIGATION
            # ---------------------------------------------------------
            nids_result = search_nids_alerts(
                source_ip="10.0.0.31"
            )

            nids_evidence = state.add_evidence(
                incident_id=incident_id,
                source="nids",
                tool_used="search_nids_alerts",
                result=nids_result,
                query_params={"source_ip": "10.0.0.31"},
            )

            # ---------------------------------------------------------
            # 3. SERVER LOG INVESTIGATION
            # ---------------------------------------------------------
            server_result = search_server_logs(
                host="FILE-01",
                source_ip="10.0.0.31",
            )

            server_evidence = state.add_evidence(
                incident_id=incident_id,
                source="server_logs",
                tool_used="search_server_logs",
                result=server_result,
                query_params={
                    "host": "FILE-01",
                    "source_ip": "10.0.0.31",
                },
            )

            # ---------------------------------------------------------
            # 4. CVE INVESTIGATION
            # ---------------------------------------------------------
            cve_result = lookup_cve(
                service="SMB",
                version="3.1.1",
            )

            cve_evidence = state.add_evidence(
                incident_id=incident_id,
                source="cve",
                tool_used="lookup_cve",
                result=cve_result,
                query_params={
                    "service": "SMB",
                    "version": "3.1.1",
                },
            )

            # ---------------------------------------------------------
            # 5. FORM HYPOTHESIS
            # ---------------------------------------------------------
            hypothesis = build_hypothesis(
                nids_result=nids_result,
                server_result=server_result,
                cve_result=cve_result,
            )

            hypothesis_row = state.add_hypothesis(
                incident_id=incident_id,
                statement=hypothesis["statement"],
                confidence=hypothesis["confidence"],
                evidence_ids=[
                    nids_evidence.id,
                    server_evidence.id,
                    cve_evidence.id,
                ],
                status=hypothesis["status"],
            )

            state.transition(
                incident_id,
                "VERIFYING",
                f"Hypothesis H{hypothesis_row.id} created from correlated evidence.",
                "hypothesis_engine",
            )

            # ---------------------------------------------------------
            # 6. VERIFY THREAT IS ACTIVE
            # ---------------------------------------------------------
            network_result = check_network_activity(
                self.environment,
                target_host_ip="10.0.0.15",
            )

            network_evidence = state.add_evidence(
                incident_id=incident_id,
                source="network",
                tool_used="check_network_activity",
                result=network_result,
                query_params={
                    "target_host_ip": "10.0.0.15"
                },
            )

            if not network_result["still_active"]:
                state.transition(
                    incident_id,
                    "RESOLVED",
                    f"No active suspicious network traffic. Evidence E{network_evidence.id}.",
                    "network_verifier",
                )

                return {
                    "incident_id": incident_id,
                    "status": "RESOLVED",
                    "reason": "No active threat detected.",
                }

            # ---------------------------------------------------------
            # 7. RESPONSE: FIREWALL BLOCK
            # ---------------------------------------------------------
            state.transition(
                incident_id,
                "RESPONDING",
                "Active threat verified; attempting source IP containment.",
                "controller",
            )

            action_1 = state.add_action(
                incident_id=incident_id,
                action_type="firewall_block",
                target="10.0.0.31",
                tool_call={
                    "tool": "firewall_block",
                    "ip": "10.0.0.31",
                },
                attempt_number=1,
            )

            firewall_result = firewall_block(
                self.environment,
                "10.0.0.31",
                "Contain confirmed malicious source",
            )

            # ---------------------------------------------------------
            # 8. DELIBERATE ENVIRONMENTAL CHANGE
            # ---------------------------------------------------------
            FaultInjector(self.environment).attacker_ip_rotation(
                old_ip="10.0.0.31",
                new_ip="10.0.0.44",
            )

            # ---------------------------------------------------------
            # 9. GOAL-LEVEL VERIFICATION
            # ---------------------------------------------------------
            containment_check = verify_containment(
                self.environment,
                "FILE-01",
            )

            verification_1 = state.add_verification(
                incident_id=incident_id,
                action_id=action_1.id,
                method="verify_containment",
                result=containment_check["status"],
                check=containment_check,
            )

            # ---------------------------------------------------------
            # 10. HANDLE FAILURE
            # ---------------------------------------------------------
            if containment_check["status"] == "FAILURE":
                state.transition(
                    incident_id,
                    "ADAPTING",
                    (
                        f"Containment failed. Verification V{verification_1.id}: "
                        f"{containment_check['reason']}"
                    ),
                    "verifier",
                )

                failure = self.failure_classifier.classify(
                    containment_check
                )

                state.transition(
                    incident_id,
                    "REPLANNING",
                    f"Failure classified as {failure['failure_class']}.",
                    "failure_classifier",
                )

                recovery_plan = self.replanner.create_recovery_plan(
                    failure=failure,
                    incident_state={
                        "target_host": "FILE-01"
                    },
                )

                # -----------------------------------------------------
                # 11. EXECUTE RECOVERY ACTION
                # -----------------------------------------------------
                if recovery_plan["action"] == "quarantine_host":
                    state.transition(
                        incident_id,
                        "RESPONDING",
                        (
                            "Replanning selected host quarantine because "
                            "the attacker rotated source IP."
                        ),
                        "replanner",
                    )

                    action_2 = state.add_action(
                        incident_id=incident_id,
                        action_type="quarantine_host",
                        target="FILE-01",
                        tool_call={
                            "tool": "quarantine_host",
                            "host_id": "FILE-01",
                        },
                        attempt_number=2,
                    )

                    quarantine_result = quarantine_host(
                        self.environment,
                        "FILE-01",
                        "Contain compromised host after IP rotation",
                    )

                    containment_check_2 = verify_host_isolation(
                        self.environment,
                        "FILE-01",
                    )

                    verification_2 = state.add_verification(
                        incident_id=incident_id,
                        action_id=action_2.id,
                        method="verify_host_isolation",
                        result=containment_check_2["status"],
                        check=containment_check_2,
                    )

                    if containment_check_2["status"] == "SUCCESS":
                        state.transition(
                            incident_id,
                            "RESOLVED",
                            (
                                f"Host isolation verified by V{verification_2.id}."
                            ),
                            "verifier",
                        )

                        return {
                            "incident_id": incident_id,
                            "status": "RESOLVED",
                            "initial_action": firewall_result,
                            "initial_verification": containment_check,
                            "failure": failure,
                            "recovery_plan": recovery_plan,
                            "recovery_action": quarantine_result,
                            "final_verification": containment_check_2,
                        }

                state.transition(
                    incident_id,
                    "FAILED",
                    "Recovery action did not achieve containment.",
                    "controller",
                )

                return {
                    "incident_id": incident_id,
                    "status": "FAILED",
                    "reason": "Recovery unsuccessful.",
                }

            # ---------------------------------------------------------
            # 12. NORMAL SUCCESS
            # ---------------------------------------------------------
            state.transition(
                incident_id,
                "RESOLVED",
                "Firewall containment verified successfully.",
                "verifier",
            )

            return {
                "incident_id": incident_id,
                "status": "RESOLVED",
                "initial_action": firewall_result,
                "initial_verification": containment_check,
            }

        finally:
            db.close()
