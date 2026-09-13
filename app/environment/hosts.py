from dataclasses import dataclass, field


@dataclass
class Host:
    host_id: str
    ip: str
    hostname: str
    services: list[str] = field(default_factory=list)
    isolated: bool = False
    compromised: bool = False


class HostManager:
    def __init__(self) -> None:
        self.hosts: dict[str, Host] = {}

    def add_host(self, host: Host) -> None:
        self.hosts[host.host_id] = host

    def get_host(self, host_id: str) -> Host | None:
        return self.hosts.get(host_id)

    def isolate_host(self, host_id: str) -> bool:
        host = self.get_host(host_id)

        if host is None:
            return False

        host.isolated = True
        return True

    def is_isolated(self, host_id: str) -> bool:
        host = self.get_host(host_id)

        if host is None:
            return False

        return host.isolated
