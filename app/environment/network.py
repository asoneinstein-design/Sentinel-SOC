from dataclasses import dataclass


@dataclass
class NetworkConnection:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    active: bool = True


class NetworkSimulator:
    def __init__(self) -> None:
        self.connections: list[NetworkConnection] = []

    def add_connection(self, connection: NetworkConnection) -> None:
        self.connections.append(connection)

    def get_active_connections(self) -> list[NetworkConnection]:
        return [
            connection
            for connection in self.connections
            if connection.active
        ]

    def is_traffic_active(self, src_ip: str, dst_ip: str) -> bool:
        return any(
            connection.active
            and connection.src_ip == src_ip
            and connection.dst_ip == dst_ip
            for connection in self.connections
        )

    def stop_connections_from(self, src_ip: str) -> None:
        """Stop all active connections originating from a source IP."""
        for connection in self.connections:
            if connection.src_ip == src_ip:
                connection.active = False

    def stop_connections_to(self, target_ip: str) -> None:
        """Stop all active connections directed to a target IP."""
        for connection in self.connections:
            if connection.dst_ip == target_ip:
                connection.active = False