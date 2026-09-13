import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / ".env")

from app.agent.llm.router import LLMRouter


def main() -> None:
    router = LLMRouter()

    messages = [
        {
            "role": "user",
            "content": "Reply with exactly: ROUTER OK",
        }
    ]

    result = router.chat(messages)

    print("PROVIDER:", router.last_provider)
    print("MODEL:", result.get("model"))
    print("RESPONSE:", result["message"]["content"])


if __name__ == "__main__":
    main()
