import sys
from google.cloud import compute_v1
from google.api_core.exceptions import GoogleAPIError
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


class GCPNetworkScanner(BaseScanner):
    provider = "gcp"

    def __init__(self, project: str):
        self.project = project
        self.fw_client = compute_v1.FirewallsClient()

    def scan(self) -> list[Finding]:
        findings = []
        findings += self._check_firewall_rules()
        findings += self._check_default_network()
        return findings

    def _check_firewall_rules(self) -> list[Finding]:
        findings = []
        try:
            for rule in self.fw_client.list(project=self.project):
                if rule.direction != "INGRESS":
                    continue
                if rule.disabled:
                    continue

                src_ranges = list(rule.source_ranges)
                if "0.0.0.0/0" not in src_ranges and "::/0" not in src_ranges:
                    continue

                for allowed in rule.allowed:
                    ports = list(allowed.ports)
                    protocol = allowed.I_p_protocol

                    # All traffic open
                    if protocol == "all" or (not ports and protocol in ("tcp", "udp")):
                        findings.append(Finding(
                            provider="gcp",
                            category=Category.NETWORK,
                            severity=Severity.CRITICAL,
                            resource_type="GCP Firewall Rule",
                            resource_id=rule.self_link or rule.name,
                            title=f"Firewall rule '{rule.name}' allows all inbound traffic from internet",
                            description=(
                                f"Rule '{rule.name}' allows protocol '{protocol}' with no port restriction "
                                "from 0.0.0.0/0."
                            ),
                            recommendation=(
                                "Delete or restrict this rule. Allow only specific ports from "
                                "known source ranges."
                            ),
                        ))
                        continue

                    for port_range in ports:
                        for port, service in _RISKY_PORTS.items():
                            if self._port_in_range(port, port_range):
                                severity = (
                                    Severity.CRITICAL if port in (22, 3389) else Severity.HIGH
                                )
                                findings.append(Finding(
                                    provider="gcp",
                                    category=Category.NETWORK,
                                    severity=severity,
                                    resource_type="GCP Firewall Rule",
                                    resource_id=rule.self_link or rule.name,
                                    title=(
                                        f"Firewall rule '{rule.name}' exposes {service} "
                                        f"(port {port}) to the internet"
                                    ),
                                    description=(
                                        f"Rule '{rule.name}' allows {protocol}/{port} ({service}) "
                                        "from 0.0.0.0/0."
                                    ),
                                    recommendation=(
                                        f"Restrict {service} to known source IPs. "
                                        "Use IAP (Identity-Aware Proxy) for SSH/RDP."
                                    ),
                                    extra={"port": port, "service": service},
                                ))
        except GoogleAPIError as e:
            print(f"[GCP/Network] Error: {e}", file=sys.stderr)
        return findings

    def _check_default_network(self) -> list[Finding]:
        findings = []
        try:
            networks_client = compute_v1.NetworksClient()
            for network in networks_client.list(project=self.project):
                if network.name == "default":
                    findings.append(Finding(
                        provider="gcp",
                        category=Category.NETWORK,
                        severity=Severity.MEDIUM,
                        resource_type="GCP VPC Network",
                        resource_id=network.self_link or "default",
                        title=f"Default VPC network exists in project '{self.project}'",
                        description=(
                            "The 'default' VPC network is pre-configured with permissive firewall rules "
                            "and should not be used for production workloads."
                        ),
                        recommendation=(
                            "Delete the default network and create custom VPC networks with "
                            "explicit, minimal firewall rules."
                        ),
                    ))
        except GoogleAPIError:
            pass
        return findings

    @staticmethod
    def _port_in_range(port: int, port_range: str) -> bool:
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
