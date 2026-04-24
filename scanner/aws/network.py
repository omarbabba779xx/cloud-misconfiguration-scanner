import sys
import boto3
from botocore.exceptions import ClientError
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
    445: "SMB",
    23: "Telnet",
}

_ANY_IPV4 = "0.0.0.0/0"
_ANY_IPV6 = "::/0"


class NetworkScanner(BaseScanner):
    provider = "aws"

    def __init__(self, session: boto3.Session):
        self.ec2 = session.client("ec2")

    def scan(self) -> list[Finding]:
        findings = []
        findings += self._check_security_groups()
        findings += self._check_default_vpc_sg()
        findings += self._check_nacl()
        return findings

    def _check_security_groups(self) -> list[Finding]:
        findings = []
        try:
            paginator = self.ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", sg_id)
                    region = self.ec2.meta.region_name

                    for perm in sg.get("IpPermissions", []):
                        findings += self._evaluate_ingress(sg_id, sg_name, perm, region)
        except ClientError as e:
            print(f"[AWS/Network] Error: {e}", file=sys.stderr)
        return findings

    def _evaluate_ingress(self, sg_id, sg_name, perm, region) -> list[Finding]:
        findings = []
        from_port = perm.get("FromPort", 0)
        to_port = perm.get("ToPort", 65535)
        protocol = perm.get("IpProtocol", "-1")

        all_open = protocol == "-1"
        ipv4_open = any(r.get("CidrIp") in (_ANY_IPV4,) for r in perm.get("IpRanges", []))
        ipv6_open = any(r.get("CidrIpv6") in (_ANY_IPV6,) for r in perm.get("Ipv6Ranges", []))

        if not (ipv4_open or ipv6_open):
            return findings

        if all_open:
            findings.append(Finding(
                provider="aws",
                category=Category.NETWORK,
                severity=Severity.CRITICAL,
                resource_type="Security Group",
                resource_id=sg_id,
                title=f"Security group '{sg_name}' allows ALL inbound traffic from the internet",
                description=(
                    f"Rule allows all protocols/ports from {'0.0.0.0/0 and/or ::/0'}. "
                    "This exposes every service on attached instances to the public internet."
                ),
                recommendation=(
                    "Remove the 0.0.0.0/0 and ::/0 rules. Allow only specific ports "
                    "from known CIDR ranges or other security groups."
                ),
                region=region,
            ))
            return findings

        for port, service in _RISKY_PORTS.items():
            if from_port <= port <= to_port:
                severity = Severity.CRITICAL if port in (22, 3389) else Severity.HIGH
                cidr_info = "0.0.0.0/0" if ipv4_open else "::/0"
                findings.append(Finding(
                    provider="aws",
                    category=Category.NETWORK,
                    severity=severity,
                    resource_type="Security Group",
                    resource_id=sg_id,
                    title=(
                        f"Security group '{sg_name}' exposes {service} (port {port}) to the internet"
                    ),
                    description=(
                        f"Inbound rule allows {service} (TCP/{port}) from {cidr_info}."
                    ),
                    recommendation=(
                        f"Restrict {service} access to specific trusted IPs or use a bastion host / VPN."
                    ),
                    region=region,
                    extra={"port": port, "service": service},
                ))
        return findings

    def _check_default_vpc_sg(self) -> list[Finding]:
        findings = []
        try:
            vpcs = self.ec2.describe_vpcs(
                Filters=[{"Name": "isDefault", "Values": ["true"]}]
            ).get("Vpcs", [])
            for vpc in vpcs:
                sgs = self.ec2.describe_security_groups(
                    Filters=[
                        {"Name": "vpc-id", "Values": [vpc["VpcId"]]},
                        {"Name": "group-name", "Values": ["default"]},
                    ]
                ).get("SecurityGroups", [])
                for sg in sgs:
                    if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                        findings.append(Finding(
                            provider="aws",
                            category=Category.NETWORK,
                            severity=Severity.MEDIUM,
                            resource_type="Security Group",
                            resource_id=sg["GroupId"],
                            title=f"Default VPC security group has inbound/outbound rules",
                            description=(
                                "The default security group should have no rules so that resources "
                                "accidentally associated with it are not exposed."
                            ),
                            recommendation=(
                                "Remove all inbound and outbound rules from the default VPC security group. "
                                "Use custom security groups instead."
                            ),
                            region=self.ec2.meta.region_name,
                        ))
        except ClientError:
            pass
        return findings

    def _check_nacl(self) -> list[Finding]:
        findings = []
        try:
            nacls = self.ec2.describe_network_acls().get("NetworkAcls", [])
            for nacl in nacls:
                nacl_id = nacl["NetworkAclId"]
                region = self.ec2.meta.region_name
                for entry in nacl.get("Entries", []):
                    if entry.get("Egress"):
                        continue
                    if entry.get("RuleAction") != "allow":
                        continue
                    cidr = entry.get("CidrBlock", "") or entry.get("Ipv6CidrBlock", "")
                    if cidr not in (_ANY_IPV4, _ANY_IPV6):
                        continue
                    protocol = entry.get("Protocol", "-1")
                    port_range = entry.get("PortRange", {})
                    from_p = port_range.get("From", 0)
                    to_p = port_range.get("To", 65535)
                    # All-traffic rule (protocol -1) or full port range
                    if protocol == "-1" or (from_p == 0 and to_p == 65535):
                        findings.append(Finding(
                            provider="aws",
                            category=Category.NETWORK,
                            severity=Severity.HIGH,
                            resource_type="Network ACL",
                            resource_id=nacl_id,
                            title=f"NACL '{nacl_id}' allows all inbound traffic from the internet",
                            description=(
                                f"A NACL rule (#{entry['RuleNumber']}) allows all traffic from {cidr}."
                            ),
                            recommendation=(
                                "Replace the catch-all allow rule with specific port/CIDR rules."
                            ),
                            region=region,
                        ))
                    else:
                        # Check for specific risky port exposure
                        for port, service in _RISKY_PORTS.items():
                            if from_p <= port <= to_p:
                                severity = (
                                    Severity.CRITICAL if port in (22, 3389) else Severity.HIGH
                                )
                                findings.append(Finding(
                                    provider="aws",
                                    category=Category.NETWORK,
                                    severity=severity,
                                    resource_type="Network ACL",
                                    resource_id=nacl_id,
                                    title=(
                                        f"NACL '{nacl_id}' allows {service} "
                                        f"(port {port}) from the internet"
                                    ),
                                    description=(
                                        f"NACL rule (#{entry['RuleNumber']}) allows {service} "
                                        f"(port {port}) from {cidr}."
                                    ),
                                    recommendation=(
                                        f"Restrict {service} to specific trusted CIDRs in the NACL."
                                    ),
                                    region=region,
                                    extra={"port": port, "service": service},
                                ))
        except ClientError:
            pass
        return findings
