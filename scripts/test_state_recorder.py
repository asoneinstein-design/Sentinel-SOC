import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.agent.state_recorder import AgentStateRecorder


def main() -> None:
    incident_id = "LLM-TEST-001"

    recorder = AgentStateRecorder(incident_id)

    try:
        recorder.create_incident(
            goal="Test LLM agent state persistence."
        )

        recorder.transition(
            "INVESTIGATING",
            "LLM state persistence test started.",
            "llm_agent",
        )

        recorder.add_evidence(
            source="test",
            tool_used="test_tool",
            result={"message": "state recorder works"},
            query_params={},
        )

        print("STATE RECORDER OK")

    finally:
        recorder.close()


if __name__ == "__main__":
    main()
