from datetime import datetime

from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import sessionmaker

from app.config.settings import settings
from app.memory.models import (
    Base,
    Incident,
    Evidence,
    Hypothesis,
    Action,
    Verification,
    StateTransition,
)

from pathlib import Path
import json


# ============================================================
# DATABASE DIRECTORY
# ============================================================

Path("database").mkdir(exist_ok=True)


# ============================================================
# ENGINE
# ============================================================

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
)


# ============================================================
# SESSION
# ============================================================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# ============================================================
# DEMO DATA
# ============================================================

DEMO_INCIDENT_ID = "LLM-DEMO-20260913-020652"


DEMO_GOAL = (
    "Investigate suspicious SMB activity against FILE-01 and "
    "determine whether there is a successful compromise, then "
    "contain the threat."
)


def seed_demo_incident() -> None:
    """
    Create a deterministic successful Sentinel SOC demo incident
    when the database is empty.

    This is used for hosted/demo environments such as Render where
    the local development SQLite database is not available.
    """

    with SessionLocal() as session:

        existing_count = session.scalar(
            select(func.count()).select_from(Incident)
        )

        if existing_count and existing_count > 0:
            return

        # ========================================================
        # INCIDENT
        # ========================================================

        incident = Incident(
            incident_id=DEMO_INCIDENT_ID,
            status="RESOLVED",
            trigger_alert_id="ALERT-1001",
            current_goal=DEMO_GOAL,
            current_plan_json=json.dumps(
                {
                    "initial_action": "firewall_block",
                    "fallback_action": "quarantine_host",
                    "final_state": "verified_containment",
                }
            ),
            created_at=datetime.utcnow(),
        )

        session.add(incident)
        session.flush()

        # ========================================================
        # EVIDENCE
        # ========================================================

        evidence_records = [
            Evidence(
                incident_id=DEMO_INCIDENT_ID,
                source="nids",
                tool_used="search_nids_alerts",
                query_params_json=json.dumps(
                    {
                        "alert_id": "ALERT-1001",
                        "host": "FILE-01",
                    }
                ),
                raw_result_json=json.dumps(
                    {
                        "severity": "HIGH",
                        "src_ip": "10.0.0.31",
                        "dst_ip": "10.0.0.15",
                        "dst_port": 445,
                        "protocol": "TCP",
                        "signature": "Suspicious SMB activity",
                    }
                ),
                collected_at=datetime.utcnow(),
            ),
            Evidence(
                incident_id=DEMO_INCIDENT_ID,
                source="server_logs",
                tool_used="search_server_logs",
                query_params_json=json.dumps(
                    {
                        "host": "FILE-01",
                    }
                ),
                raw_result_json=json.dumps(
                    {
                        "authentication": "SUCCESS",
                        "user": "admin",
                        "process": "suspicious_smb_process",
                        "host": "FILE-01",
                    }
                ),
                collected_at=datetime.utcnow(),
            ),
            Evidence(
                incident_id=DEMO_INCIDENT_ID,
                source="cve",
                tool_used="lookup_cve",
                query_params_json=json.dumps(
                    {
                        "service": "SMB 3.1.1",
                    }
                ),
                raw_result_json=json.dumps(
                    {
                        "cve": "CVE-DEMO-SMB",
                        "cvss": 9.1,
                        "exploit_available": True,
                        "service": "SMB 3.1.1",
                    }
                ),
                collected_at=datetime.utcnow(),
            ),
            Evidence(
                incident_id=DEMO_INCIDENT_ID,
                source="network",
                tool_used="check_network_activity",
                query_params_json=json.dumps(
                    {
                        "host": "FILE-01",
                    }
                ),
                raw_result_json=json.dumps(
                    {
                        "active": True,
                        "src_ip": "10.0.0.31",
                        "dst_ip": "10.0.0.15",
                        "dst_port": 445,
                        "protocol": "TCP",
                    }
                ),
                collected_at=datetime.utcnow(),
            ),
        ]

        session.add_all(evidence_records)
        session.flush()

        # ========================================================
        # HYPOTHESIS
        # ========================================================

        hypothesis = Hypothesis(
            incident_id=DEMO_INCIDENT_ID,
            statement=(
                "Likely active SMB compromise of FILE-01 supported by "
                "correlated network, authentication, vulnerability, "
                "and live-traffic evidence."
            ),
            confidence=0.94,
            supporting_evidence_ids_json=json.dumps(
                [
                    evidence_records[0].id,
                    evidence_records[1].id,
                    evidence_records[2].id,
                    evidence_records[3].id,
                ]
            ),
            status="CONFIRMED",
            formed_at=datetime.utcnow(),
        )

        session.add(hypothesis)
        session.flush()

        # ========================================================
        # ACTION 1 — FIREWALL
        # ========================================================

        firewall_action = Action(
            incident_id=DEMO_INCIDENT_ID,
            action_type="firewall_block",
            target="10.0.0.31",
            tool_call_json=json.dumps(
                {
                    "operation": "firewall_block",
                    "target": "10.0.0.31",
                }
            ),
            attempt_number=1,
            executed_at=datetime.utcnow(),
        )

        session.add(firewall_action)
        session.flush()

        # ========================================================
        # VERIFICATION 1 — FAILURE
        # ========================================================

        firewall_verification = Verification(
            incident_id=DEMO_INCIDENT_ID,
            action_id=firewall_action.id,
            method="verify_firewall_block",
            result="FAILURE",
            raw_check_json=json.dumps(
                {
                    "status": "ACTIVE_TRAFFIC_REMAINS",
                    "observed_source": "10.0.0.44",
                    "target": "FILE-01",
                    "reason": "IP_ROTATION",
                }
            ),
            verified_at=datetime.utcnow(),
        )

        session.add(firewall_verification)
        session.flush()

        # ========================================================
        # ACTION 2 — QUARANTINE
        # ========================================================

        quarantine_action = Action(
            incident_id=DEMO_INCIDENT_ID,
            action_type="quarantine_host",
            target="FILE-01",
            tool_call_json=json.dumps(
                {
                    "operation": "quarantine_host",
                    "target": "FILE-01",
                }
            ),
            attempt_number=2,
            executed_at=datetime.utcnow(),
        )

        session.add(quarantine_action)
        session.flush()

        # ========================================================
        # VERIFICATION 2 — SUCCESS
        # ========================================================

        quarantine_verification = Verification(
            incident_id=DEMO_INCIDENT_ID,
            action_id=quarantine_action.id,
            method="verify_host_isolation",
            result="SUCCESS",
            raw_check_json=json.dumps(
                {
                    "isolated": True,
                    "network_reachable": False,
                    "active_connections": [],
                    "host": "FILE-01",
                }
            ),
            verified_at=datetime.utcnow(),
        )

        session.add(quarantine_verification)
        session.flush()

        # ========================================================
        # STATE TRANSITIONS
        # ========================================================

        transitions = [
            StateTransition(
                incident_id=DEMO_INCIDENT_ID,
                from_state="OPEN",
                to_state="INVESTIGATING",
                reason="Incident received for investigation.",
                triggered_by="controller",
                at=datetime.utcnow(),
            ),
            StateTransition(
                incident_id=DEMO_INCIDENT_ID,
                from_state="INVESTIGATING",
                to_state="RESPONDING",
                reason="Evidence correlation indicates active compromise.",
                triggered_by="hypothesis",
                at=datetime.utcnow(),
            ),
            StateTransition(
                incident_id=DEMO_INCIDENT_ID,
                from_state="RESPONDING",
                to_state="ADAPTING",
                reason="Firewall verification failed because active traffic remained.",
                triggered_by="verifier",
                at=datetime.utcnow(),
            ),
            StateTransition(
                incident_id=DEMO_INCIDENT_ID,
                from_state="ADAPTING",
                to_state="REPLANNING",
                reason="Failure classified as IP_ROTATION.",
                triggered_by="failure_classifier",
                at=datetime.utcnow(),
            ),
            StateTransition(
                incident_id=DEMO_INCIDENT_ID,
                from_state="REPLANNING",
                to_state="RESPONDING",
                reason="Escalating containment from source blocking to host quarantine.",
                triggered_by="replanner",
                at=datetime.utcnow(),
            ),
            StateTransition(
                incident_id=DEMO_INCIDENT_ID,
                from_state="RESPONDING",
                to_state="RESOLVED",
                reason="Host isolation verified successfully.",
                triggered_by="verifier",
                at=datetime.utcnow(),
            ),
        ]

        session.add_all(transitions)

        session.commit()


# ============================================================
# INITIALIZATION
# ============================================================

def init_db() -> None:
    """
    Create database tables and seed the hosted demo state
    when no incidents exist.
    """

    Base.metadata.create_all(bind=engine)

    seed_demo_incident()