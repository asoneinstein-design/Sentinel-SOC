import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.agent.tool_registry import ToolRegistry
from app.environment.simulator import SOCEnvironment


def main() -> None:
    environment = SOCEnvironment()
    registry = ToolRegistry(environment)

    print("AVAILABLE TOOLS:")
    for tool in registry.definitions():
        print("-", tool["function"]["name"])

    print("\nTEST NIDS TOOL:")

    result = registry.execute(
        "search_nids_alerts",
        {
            "source_ip": "10.0.0.31",
        },
    )

    print(result)


if __name__ == "__main__":
    main()
