from typing import Any

from app.environment.simulator import SOCEnvironment


def check_network_activity(
    environment: SOCEnvironment,
    target_ip: str | None = None,
    target_host_ip: str | None = None,
) -> dict[str, Any]:
    connections = environment.network.get_active_connections()

    if target_ip:
        connections = [
            connection
            for connection in connections
            if connection.src_ip == target_ip
        ]

    if target_host_ip:
        connections = [
            connection
            for connection in connections
            if connection.dst_ip == target_host_ip
        ]

    return {
        "tool": "check_network_activity",
        "still_active": len(connections) > 0,
        "connection_count": len(connections),
        "observed_sources": list(
            {connection.src_ip for connection in connections}
        ),
        "connections": [
            {
                "src_ip": connection.src_ip,
                "dst_ip": connection.dst_ip,
                "dst_port": connection.dst_port,
                "protocol": connection.protocol,
                "active": connection.active,
            }
            for connection in connections
        ],
    }
