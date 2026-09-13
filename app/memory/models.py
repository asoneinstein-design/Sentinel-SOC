from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import declarative_base


Base = declarative_base()


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(100), unique=True, nullable=False, index=True)
    status = Column(String(50), default="OPEN", nullable=False)
    trigger_alert_id = Column(String(100), nullable=True)
    current_goal = Column(Text, nullable=False)
    current_plan_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(100), nullable=False, index=True)
    source = Column(String(100), nullable=False)
    tool_used = Column(String(100), nullable=False)
    query_params_json = Column(Text, nullable=True)
    raw_result_json = Column(Text, nullable=False)
    collected_at = Column(DateTime, default=datetime.utcnow)


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(100), nullable=False, index=True)
    statement = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False)
    supporting_evidence_ids_json = Column(Text, nullable=True)
    status = Column(String(50), default="PROPOSED", nullable=False)
    formed_at = Column(DateTime, default=datetime.utcnow)


class Action(Base):
    __tablename__ = "actions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(100), nullable=False, index=True)
    action_type = Column(String(100), nullable=False)
    target = Column(String(255), nullable=False)
    tool_call_json = Column(Text, nullable=True)
    attempt_number = Column(Integer, default=1)
    executed_at = Column(DateTime, default=datetime.utcnow)


class Verification(Base):
    __tablename__ = "verifications"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(100), nullable=False)
    action_id = Column(Integer, nullable=True)
    method = Column(String(100), nullable=False)
    result = Column(String(50), nullable=False)
    raw_check_json = Column(Text, nullable=False)
    verified_at = Column(DateTime, default=datetime.utcnow)


class StateTransition(Base):
    __tablename__ = "state_transitions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(100), nullable=False, index=True)
    from_state = Column(String(50), nullable=False)
    to_state = Column(String(50), nullable=False)
    reason = Column(Text, nullable=False)
    triggered_by = Column(String(100), nullable=False)
    at = Column(DateTime, default=datetime.utcnow)
