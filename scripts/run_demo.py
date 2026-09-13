import sys
from pathlib import Path

# Add the project root to Python's import path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.agent.controller import SOCController


def main() -> None:
    controller = SOCController()
    result = controller.run("DEMO-IP-ROTATION-001")

    print("\n" + "=" * 70)
    print("SENTINEL SOC — DEMO RESULT")
    print("=" * 70)

    print(result)

    print("=" * 70)


if __name__ == "__main__":
    main()
