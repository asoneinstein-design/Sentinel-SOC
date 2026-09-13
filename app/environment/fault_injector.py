from app.environment.network import NetworkConnection
from app.environment.simulator import SOCEnvironment


class FaultInjector:
    """
    Introduces controlled environmental changes for reproducible
    agent-evaluation scenarios.
    """

    def __init__(self, environment: SOCEnvironment) -> None:
        self.environment = environment

    def attacker_ip_rotation(
        self,
        old_ip: str,
        new_ip: str,
        target_ip: str = "10.0.0.15",
        target_port: int = 445,
    ) -> NetworkConnection:
        """
        Simulate an attacker changing source IP after the original
        IP has been blocked.
        """

        # Make sure the old source is no longer active.
        self.environment.network.stop_connections_from(old_ip)

        # Create the new malicious connection.
        new_connection = NetworkConnection(
            src_ip=new_ip,
            dst_ip=target_ip,
            dst_port=target_port,
            protocol="TCP",
            active=True,
        )

        self.environment.network.add_connection(new_connection)

        return new_connection
