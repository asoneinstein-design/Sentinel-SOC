import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.agent.llm.ollama_adapter import OllamaAdapter


def main() -> None:
    llm = OllamaAdapter()

    messages = [
        {
            "role": "user",
            "content": "Reply with exactly: SENTINEL OK",
        }
    ]

    result = llm.chat(messages)

    print("RAW RESPONSE:")
    print(result)

    print("\nMODEL RESPONSE:")
    print(result["message"]["content"])


if __name__ == "__main__":
    main()
