from dataclasses import dataclass
from datetime import datetime


@dataclass
class FirewallRule:
    rule_id: str
    ip: str
    blocked: bool
    reason: str
    created_at: str


class Firewall:
    def __init__(self) -> None:
        self.rules: dict[str, FirewallRule] = {}

    def block_ip(self, ip: str, reason: str) -> FirewallRule:
        rule_id = f"FW-{len(self.rules) + 1:04d}"

        rule = FirewallRule(
            rule_id=rule_id,
            ip=ip,
            blocked=True,
            reason=reason,
            created_at=datetime.utcnow().isoformat(),
        )

        self.rules[ip] = rule
        return rule

    def is_blocked(self, ip: str) -> bool:
        rule = self.rules.get(ip)
        return rule.blocked if rule else False

    def get_rule(self, ip: str) -> FirewallRule | None:
        return self.rules.get(ip)
