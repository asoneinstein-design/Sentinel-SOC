import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------
# Make project root importable when running this script
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / ".env")

from app.agent.llm_agent import SOCInvestigationAgent


def main() -> None:
    # ---------------------------------------------------------
    # Create a unique incident ID for every test run
    # ---------------------------------------------------------
    incident_id = (
        "LLM-DEMO-"
        + datetime.now().strftime("%Y%m%d-%H%M%S")
    )

    print("========================================")
    print("       SENTINEL SOC LLM AGENT TEST")
    print("========================================")
    print(f"Incident ID: {incident_id}")
    print()

    # ---------------------------------------------------------
    # Create the autonomous SOC agent
    # ---------------------------------------------------------
    agent = SOCInvestigationAgent(
        incident_id=incident_id
    )

    # ---------------------------------------------------------
    # Run investigation + containment
    # ---------------------------------------------------------
    result = agent.investigate(
        incident_goal=(
            "Investigate suspicious SMB activity against FILE-01 "
            "and determine whether there is a successful compromise, "
            "then contain the threat."
        )
    )

    # ---------------------------------------------------------
    # Print high-level result
    # ---------------------------------------------------------
    print()
    print("========================================")
    print("          SOC AGENT RESULT")
    print("========================================")

    print(f"Incident : {result.get('incident_id')}")
    print(f"Status   : {result.get('status')}")
    print(f"Steps    : {result.get('steps')}")
    print(f"Provider : {result.get('provider')}")

    # ---------------------------------------------------------
    # Print final response if available
    # ---------------------------------------------------------
    final_response = result.get("final_response")

    if final_response:
        print()
        print("========================================")
        print("           FINAL RESPONSE")
        print("========================================")
        print(final_response)

    # ---------------------------------------------------------
    # Print detailed trace
    # ---------------------------------------------------------
    print()
    print("========================================")
    print("              TRACE")
    print("========================================")

    for index, item in enumerate(result.get("trace", []), start=1):
        print()
        print(f"--- TRACE EVENT {index} ---")
        print(item)

    # ---------------------------------------------------------
    # Print final environment state
    # ---------------------------------------------------------
    print()
    print("========================================")
    print("        FINAL ENVIRONMENT STATE")
    print("========================================")

    print(result.get("environment", {}))


if __name__ == "__main__":
    main()