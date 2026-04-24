import sys
from azure.mgmt.network import NetworkManagementClient
from azure.core.exceptions import HttpResponseError
from scanner.base import BaseScanner, Category, Finding, Severity

_RISKY_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}


class AzureNetworkScanner(BaseScanner):
    provider = "azure"

    def __init__(self, credential, subscription_id: str):
        self.client = NetworkManagementClient(credential, subscription_id)

    def scan(self) -> list[Finding]:
        findings = []
        findings += self._check_nsgs()
        return findings

    def _check_nsgs(self) -> list[Finding]:
        findings = []
        try:
            for nsg in self.client.network_security_groups.list_all():
                for rule in (nsg.security_rules or []):
                    if rule.direction != "Inbound":
                        continue
                    if rule.access != "Allow":
                        continue
                    src = rule.source_address_prefix or ""
                    if src not in ("*", "Internet", "0.0.0.0/0", "Any"):
                        continue

                    dest_port = rule.destination_port_range or ""
                    dest_ports = rule.destination_port_ranges or []
                    all_ports = [dest_port] + list(dest_ports)

                    if "*" in all_ports or "0-65535" in all_ports:
                        findings.append(Finding(
                            provider="azure",
                            category=Category.NETWORK,
                            severity=Severity.CRITICAL,
                            resource_type="Azure NSG Rule",
                            resource_id=f"{nsg.id}/securityRules/{rule.name}",
                            title=f"NSG '{nsg.name}' rule '{rule.name}' allows ALL inbound from internet",
                            description=(
                                f"Rule '{rule.name}' allows all ports from Any/Internet source."
                            ),
                            recommendation=(
                                "Replace the catch-all rule with specific port ranges "
                                "and restrict sources to known CIDRs."
                            ),
                            region=nsg.location,
                        ))
                        continue

                    for port_range in all_ports:
                        if not port_range:
                            continue
                        for port, service in _RISKY_PORTS.items():
                            if self._port_in_range(port, port_range):
                                severity = (
                                    Severity.CRITICAL if port in (22, 3389) else Severity.HIGH
                                )
                                findings.append(Finding(
                                    provider="azure",
                                    category=Category.NETWORK,
                                    severity=severity,
                                    resource_type="Azure NSG Rule",
                                    resource_id=f"{nsg.id}/securityRules/{rule.name}",
                                    title=(
                                        f"NSG '{nsg.name}' exposes {service} (port {port}) to internet"
                                    ),
                                    description=(
                                        f"Rule '{rule.name}' allows {service} (TCP/{port}) from internet."
                                    ),
                                    recommendation=(
                                        f"Restrict {service} to specific trusted source IP ranges or "
                                        "use Azure Bastion for remote access."
                                    ),
                                    region=nsg.location,
                                    extra={"port": port, "service": service},
                                ))
        except HttpResponseError as e:
            print(f"[Azure/Network] Error: {e}", file=sys.stderr)
        return findings

    @staticmethod
    def _port_in_range(port: int, port_range: str) -> bool:
        if port_range == "*":
            return True
        if "-" in port_range:
            try:
                lo, hi = port_range.split("-", 1)
                return int(lo) <= port <= int(hi)
            except ValueError:
                return False
        try:
            return int(port_range) == port
        except ValueError:
            return False
