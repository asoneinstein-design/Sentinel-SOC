import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.policy.gate import policy_gate


def main() -> None:
    print("=== VALID CONTAINMENT ===")

    result = policy_gate(
        action="firewall_block",
        target="10.0.0.31",
        evidence_confidence=0.99,
        threat_active=True,
    )

    print(result)

    print("\n=== INVALID ACTION ===")

    result = policy_gate(
        action="delete_files",
        target="FILE-01",
        evidence_confidence=0.99,
        threat_active=True,
    )

    print(result)

    print("\n=== NO ACTIVE THREAT ===")

    result = policy_gate(
        action="firewall_block",
        target="10.0.0.31",
        evidence_confidence=0.99,
        threat_active=False,
    )

    print(result)


if __name__ == "__main__":
    main()
