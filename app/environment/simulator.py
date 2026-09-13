from app.environment.firewall import Firewall
from app.environment.hosts import Host, HostManager
from app.environment.network import NetworkConnection, NetworkSimulator


class SOCEnvironment:
    def __init__(self) -> None:
        self.hosts = HostManager()
        self.network = NetworkSimulator()
        self.firewall = Firewall()

        self.load_initial_state()

    def load_initial_state(self) -> None:
        target = Host(
            host_id="FILE-01",
            ip="10.0.0.15",
            hostname="FILE-01",
            services=["SMB"],
            compromised=True,
        )

        self.hosts.add_host(target)

        connection = NetworkConnection(
            src_ip="10.0.0.31",
            dst_ip="10.0.0.15",
            dst_port=445,
            protocol="TCP",
            active=True,
        )

        self.network.add_connection(connection)

    def block_ip(self, ip: str, reason: str):
        rule = self.firewall.block_ip(ip, reason)

        # Simulated firewall enforcement:
        # terminate active connections from the blocked source.
        self.network.stop_connections_from(ip)

        return rule

    def quarantine_host(self, host_id: str) -> bool:
        """
        Isolate a host and terminate all active connections
        directed at that host.
        """
        host = self.hosts.get_host(host_id)

        if host is None:
            return False

        isolated = self.hosts.isolate_host(host_id)

        if isolated:
            self.network.stop_connections_to(host.ip)

        return isolated

    def is_host_isolated(self, host_id: str) -> bool:
        return self.hosts.is_isolated(host_id)