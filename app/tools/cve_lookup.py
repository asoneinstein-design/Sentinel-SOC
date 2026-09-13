import json
from pathlib import Path
from typing import Any


CVE_PATH = Path("data/cve/cves.json")


def lookup_cve(
    service: str,
    version: str,
) -> dict[str, Any]:
    with CVE_PATH.open("r", encoding="utf-8") as file:
        cves = json.load(file)

    matches = [
        cve
        for cve in cves
        if cve.get("service", "").lower() == service.lower()
        and cve.get("version", "") == version
    ]

    return {
        "tool": "lookup_cve",
        "service": service,
        "version": version,
        "match_count": len(matches),
        "matches": matches,
    }
