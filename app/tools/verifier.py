from typing import Any

from app.environment.simulator import SOCEnvironment


def verify_firewall_rule(
    environment: SOCEnvironment,
    ip: str,
    target_host_ip: str | None = None,
) -> dict[str, Any]:
    blocked = environment.firewall.is_blocked(ip)

    active_connections = environment.network.get_active_connections()

    if target_host_ip:
        active_connections = [
            connection
            for connection in active_connections
            if connection.dst_ip == target_host_ip
        ]

    return {
        "tool": "verify_firewall_rule",
        "ip": ip,
        "blocked": blocked,
        "traffic_still_observed": len(active_connections) > 0,
        "active_connection_count": len(active_connections),
        "observed_sources": sorted(
            {connection.src_ip for connection in active_connections}
        ),
        "status": (
            "SUCCESS"
            if blocked and len(active_connections) == 0
            else "FAILURE"
        ),
    }


def verify_host_isolation(
    environment: SOCEnvironment,
    host_id: str,
) -> dict[str, Any]:
    isolated = environment.is_host_isolated(host_id)

    host = environment.hosts.get_host(host_id)

    return {
        "tool": "verify_host_isolation",
        "host_id": host_id,
        "isolated": isolated,
        "network_reachable": not isolated if host else None,
        "status": "SUCCESS" if isolated else "FAILURE",
    }


def verify_containment(
    environment: SOCEnvironment,
    target_host_id: str,
) -> dict[str, Any]:
    """
    Goal-level verification.

    The goal is not merely to confirm that a firewall rule exists.
    The goal is to determine whether the target host is actually
    free from active suspicious network traffic or isolated.
    """

    host = environment.hosts.get_host(target_host_id)

    if host is None:
        return {
            "tool": "verify_containment",
            "target_host_id": target_host_id,
            "status": "FAILURE",
            "reason": "TARGET_HOST_NOT_FOUND",
        }

    active_connections = [
        connection
        for connection in environment.network.get_active_connections()
        if connection.dst_ip == host.ip
    ]

    if host.isolated:
        return {
            "tool": "verify_containment",
            "target_host_id": target_host_id,
            "status": "SUCCESS",
            "containment": True,
            "reason": "HOST_ISOLATED",
            "observed_sources": [],
        }

    if active_connections:
        return {
            "tool": "verify_containment",
            "target_host_id": target_host_id,
            "status": "FAILURE",
            "containment": False,
            "reason": "ACTIVE_TRAFFIC_REMAINS",
            "observed_sources": sorted(
                {connection.src_ip for connection in active_connections}
            ),
        }

    return {
        "tool": "verify_containment",
        "target_host_id": target_host_id,
        "status": "SUCCESS",
        "containment": True,
        "reason": "NO_ACTIVE_TRAFFIC",
        "observed_sources": [],
    }
