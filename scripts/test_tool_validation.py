import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.agent.tool_registry import ToolRegistry
from app.environment.simulator import SOCEnvironment


def main() -> None:
    registry = ToolRegistry(SOCEnvironment())

    print("=== VALID NIDS CALL ===")

    result = registry.execute(
        "search_nids_alerts",
        {
            "source_ip": "10.0.0.31",
            "destination_ip": "10.0.0.15",
        },
    )

    print(result)

    print("\n=== INVALID NIDS CALL ===")

    result = registry.execute(
        "search_nids_alerts",
        {
            "source_ip": "10.0.0.31",
            "destination_ip": "10.0.0.15",
            "service": "SMB",
        },
    )

    print(result)

    print("\n=== VALID CVE CALL ===")

    result = registry.execute(
        "lookup_cve",
        {
            "service": "SMB",
            "version": "3.1.1",
        },
    )

    print(result)


if __name__ == "__main__":
    main()
