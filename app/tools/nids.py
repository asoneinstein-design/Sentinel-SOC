import json
from pathlib import Path
from typing import Any


NIDS_PATH = Path("data/nids/alerts.json")


def search_nids_alerts(
    incident_id: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
) -> dict[str, Any]:
    with NIDS_PATH.open("r", encoding="utf-8") as file:
        alerts = json.load(file)

    results = alerts

    if source_ip:
        results = [
            alert for alert in results
            if alert["src_ip"] == source_ip
        ]

    if destination_ip:
        results = [
            alert for alert in results
            if alert["dst_ip"] == destination_ip
        ]

    return {
        "tool": "search_nids_alerts",
        "count": len(results),
        "alerts": results,
    }
