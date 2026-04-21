"""
Integration tests for AWS Network scanner using moto.
Creates real (simulated) EC2 security groups and verifies scanner detects them.
"""
import boto3
import pytest
from moto import mock_aws
from scanner.aws.network import NetworkScanner
from scanner.base import Severity
from tests.conftest import assert_finding, no_finding


@pytest.fixture
def aws_session():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        # Create a VPC so security groups can be attached
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        yield session, vpc["Vpc"]["VpcId"]


def _create_sg(ec2, vpc_id, name, description="test"):
    sg = ec2.create_security_group(
        GroupName=name, Description=description, VpcId=vpc_id
    )
    return sg["GroupId"]


# ── SSH / RDP open to internet ────────────────────────────────────────────────

class TestOpenPortsIntegration:
    def test_ssh_open_to_internet_raises_critical(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")
        sg_id = _create_sg(ec2, vpc_id, "ssh-open-sg")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        findings = NetworkScanner(session).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="SSH")

    def test_rdp_open_to_internet_raises_critical(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")
        sg_id = _create_sg(ec2, vpc_id, "rdp-open-sg")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        findings = NetworkScanner(session).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="RDP")

    def test_mysql_open_to_internet_raises_high(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")
        sg_id = _create_sg(ec2, vpc_id, "mysql-open-sg")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        findings = NetworkScanner(session).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="MySQL")

    def test_all_traffic_open_raises_critical(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")
        sg_id = _create_sg(ec2, vpc_id, "all-open-sg")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        findings = NetworkScanner(session).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="allows ALL inbound")

    def test_redis_open_to_internet_raises_high(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")
        sg_id = _create_sg(ec2, vpc_id, "redis-open-sg")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 6379, "ToPort": 6379,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        findings = NetworkScanner(session).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="Redis")


# ── Restricted source — should NOT trigger ───────────────────────────────────

class TestRestrictedSourceIntegration:
    def test_ssh_from_private_cidr_no_finding(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")
        sg_id = _create_sg(ec2, vpc_id, "ssh-private-sg")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }],
        )
        findings = NetworkScanner(session).scan()
        ssh = [f for f in findings if "SSH" in f.title and sg_id in f.resource_id]
        assert not ssh, f"Should not flag private-CIDR SSH: {[f.title for f in ssh]}"

    def test_http_open_to_internet_no_critical(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")
        sg_id = _create_sg(ec2, vpc_id, "http-sg")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        findings = NetworkScanner(session).scan()
        critical = [f for f in findings if f.severity == Severity.CRITICAL and sg_id in f.resource_id]
        assert not critical

    def test_empty_security_group_no_findings(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")
        sg_id = _create_sg(ec2, vpc_id, "clean-sg")
        findings = NetworkScanner(session).scan()
        sg_findings = [f for f in findings if sg_id in f.resource_id]
        assert not sg_findings


# ── Multiple security groups ──────────────────────────────────────────────────

class TestMultipleSGsIntegration:
    def test_only_bad_sg_flagged(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")

        good_sg = _create_sg(ec2, vpc_id, "good-sg")
        ec2.authorize_security_group_ingress(
            GroupId=good_sg,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )

        bad_sg = _create_sg(ec2, vpc_id, "bad-sg")
        ec2.authorize_security_group_ingress(
            GroupId=bad_sg,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )

        findings = NetworkScanner(session).scan()
        bad_findings = [f for f in findings if bad_sg in f.resource_id and "SSH" in f.title]
        good_findings = [f for f in findings if good_sg in f.resource_id and "SSH" in f.title]

        assert bad_findings, "Expected SSH finding on bad-sg"
        assert not good_findings, "Should not flag good-sg for SSH"
