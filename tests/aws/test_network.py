import pytest
from unittest.mock import MagicMock
from scanner.aws.network import NetworkScanner
from scanner.base import Severity
from tests.conftest import assert_finding, no_finding


def _make_scanner(ec2_mock):
    session = MagicMock()
    session.client.return_value = ec2_mock
    return NetworkScanner(session)


def _sg(sg_id, sg_name, perms):
    return {"GroupId": sg_id, "GroupName": sg_name, "IpPermissions": perms}


def _perm(from_port, to_port, protocol="tcp", cidr="0.0.0.0/0"):
    return {
        "FromPort": from_port,
        "ToPort": to_port,
        "IpProtocol": protocol,
        "IpRanges": [{"CidrIp": cidr}],
        "Ipv6Ranges": [],
    }


def _all_traffic_perm():
    return {
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [],
    }


def _basic_ec2(sgs, vpcs=None):
    ec2 = MagicMock()
    ec2.meta.region_name = "us-east-1"
    page = MagicMock()
    page.__iter__ = lambda self: iter([{"SecurityGroups": sgs}])
    ec2.get_paginator.return_value.paginate.return_value = page
    ec2.describe_vpcs.return_value = {"Vpcs": vpcs or []}
    ec2.describe_network_acls.return_value = {"NetworkAcls": []}
    return ec2


# ── All-open security group ───────────────────────────────────────────────────

class TestAllOpenSG:
    def test_all_traffic_from_internet_is_critical(self):
        ec2 = _basic_ec2([_sg("sg-1", "open-sg", [_all_traffic_perm()])])
        findings = _make_scanner(ec2).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="allows ALL inbound")

    def test_restricted_cidr_no_finding(self):
        ec2 = _basic_ec2([_sg("sg-2", "corp-sg", [_perm(22, 22, cidr="10.0.0.0/8")])])
        findings = _make_scanner(ec2).scan()
        no_finding(findings, title_contains="ssh")


# ── Specific risky ports ──────────────────────────────────────────────────────

class TestRiskyPorts:
    def test_ssh_open_is_critical(self):
        ec2 = _basic_ec2([_sg("sg-ssh", "ssh-open", [_perm(22, 22)])])
        findings = _make_scanner(ec2).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="SSH")

    def test_rdp_open_is_critical(self):
        ec2 = _basic_ec2([_sg("sg-rdp", "rdp-open", [_perm(3389, 3389)])])
        findings = _make_scanner(ec2).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="RDP")

    def test_mysql_open_is_high(self):
        ec2 = _basic_ec2([_sg("sg-db", "db-open", [_perm(3306, 3306)])])
        findings = _make_scanner(ec2).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="MySQL")

    def test_redis_open_is_high(self):
        ec2 = _basic_ec2([_sg("sg-redis", "redis-open", [_perm(6379, 6379)])])
        findings = _make_scanner(ec2).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="Redis")

    def test_port_in_range_is_detected(self):
        # Rule opens 0-65535 (catches all risky ports)
        ec2 = _basic_ec2([_sg("sg-wide", "wide-open", [_perm(0, 65535)])])
        findings = _make_scanner(ec2).scan()
        ssh_findings = [f for f in findings if "SSH" in f.title]
        assert ssh_findings, "Expected SSH finding for port range 0-65535"

    def test_non_risky_port_no_critical(self):
        ec2 = _basic_ec2([_sg("sg-http", "http-open", [_perm(80, 80)])])
        findings = _make_scanner(ec2).scan()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert not critical

    def test_ipv6_open_ssh_is_critical(self):
        ec2 = MagicMock()
        ec2.meta.region_name = "us-east-1"
        perm = {
            "FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
            "IpRanges": [],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
        page = MagicMock()
        page.__iter__ = lambda self: iter([{"SecurityGroups": [_sg("sg-v6", "ipv6-ssh", [perm])]}])
        ec2.get_paginator.return_value.paginate.return_value = page
        ec2.describe_vpcs.return_value = {"Vpcs": []}
        ec2.describe_network_acls.return_value = {"NetworkAcls": []}
        findings = _make_scanner(ec2).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="SSH")


# ── Default VPC SG ────────────────────────────────────────────────────────────

class TestDefaultVPCSG:
    def test_default_sg_with_rules_is_medium(self):
        ec2 = MagicMock()
        ec2.meta.region_name = "us-east-1"
        page = MagicMock()
        page.__iter__ = lambda self: iter([{"SecurityGroups": []}])
        ec2.get_paginator.return_value.paginate.return_value = page
        ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-default"}]}
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-default",
                "IpPermissions": [_perm(0, 65535)],
                "IpPermissionsEgress": [],
            }]
        }
        ec2.describe_network_acls.return_value = {"NetworkAcls": []}
        findings = _make_scanner(ec2).scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="Default VPC security group")
