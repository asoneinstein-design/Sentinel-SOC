import json
from pathlib import Path
from typing import Any


AUTH_LOG_PATH = Path("data/logs/auth.json")
PROCESS_LOG_PATH = Path("data/logs/process.json")
SERVER_LOG_PATH = Path("data/logs/server.json")


def _load_json(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def search_server_logs(
    host: str | None = None,
    source_ip: str | None = None,
) -> dict[str, Any]:
    auth_logs = _load_json(AUTH_LOG_PATH)
    process_logs = _load_json(PROCESS_LOG_PATH)
    server_logs = _load_json(SERVER_LOG_PATH)

    if host:
        auth_logs = [
            entry for entry in auth_logs
            if entry.get("host") == host
        ]

        process_logs = [
            entry for entry in process_logs
            if entry.get("host") == host
        ]

        server_logs = [
            entry for entry in server_logs
            if entry.get("host") == host
        ]

    if source_ip:
        auth_logs = [
            entry for entry in auth_logs
            if entry.get("source_ip") == source_ip
        ]

    auth_failures = sum(
        1 for entry in auth_logs
        if entry.get("event") == "AUTH_FAILURE"
    )

    auth_successes = [
        entry for entry in auth_logs
        if entry.get("event") == "AUTH_SUCCESS"
    ]

    suspicious_processes = [
        entry for entry in process_logs
        if entry.get("suspicious") is True
    ]

    return {
        "tool": "search_server_logs",
        "host": host,
        "source_ip": source_ip,
        "authentication": {
            "total_events": len(auth_logs),
            "failed_attempts": auth_failures,
            "successful_authentication": auth_successes,
        },
        "suspicious_processes": suspicious_processes,
        "server_information": server_logs,
    }
