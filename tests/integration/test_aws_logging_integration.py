"""
Integration tests for AWS Logging scanner using moto.
Creates real (simulated) CloudTrail trails and Config recorders.
"""
import boto3
import pytest
from moto import mock_aws
from scanner.aws.logging import LoggingScanner
from scanner.base import Severity
from tests.conftest import assert_finding, no_finding


@pytest.fixture
def aws_session():
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


def _create_log_bucket(s3, name="audit-logs-bucket"):
    s3.create_bucket(Bucket=name)
    return name


# ── No CloudTrail ─────────────────────────────────────────────────────────────

class TestNoCloudTrailIntegration:
    def test_no_trails_raises_critical(self, aws_session):
        findings = LoggingScanner(aws_session).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="No CloudTrail trails")


# ── Single-region trail ───────────────────────────────────────────────────────

class TestSingleRegionTrailIntegration:
    def test_single_region_trail_raises_high(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        bucket = _create_log_bucket(s3)
        ct = aws_session.client("cloudtrail", region_name="us-east-1")
        ct.create_trail(Name="single-trail", S3BucketName=bucket, IsMultiRegionTrail=False)
        ct.start_logging(Name="single-trail")

        findings = LoggingScanner(aws_session).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="No multi-region CloudTrail")

    def test_single_region_trail_without_log_validation_raises_medium(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        bucket = _create_log_bucket(s3)
        ct = aws_session.client("cloudtrail", region_name="us-east-1")
        ct.create_trail(
            Name="noval-trail",
            S3BucketName=bucket,
            EnableLogFileValidation=False,
        )
        ct.start_logging(Name="noval-trail")

        findings = LoggingScanner(aws_session).scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="log file validation disabled")


# ── Multi-region trail ────────────────────────────────────────────────────────

class TestMultiRegionTrailIntegration:
    def test_multi_region_trail_no_critical(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        bucket = _create_log_bucket(s3)
        ct = aws_session.client("cloudtrail", region_name="us-east-1")
        ct.create_trail(
            Name="multi-trail",
            S3BucketName=bucket,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True,
        )
        ct.start_logging(Name="multi-trail")

        findings = LoggingScanner(aws_session).scan()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert not critical, f"Unexpected critical: {[f.title for f in critical]}"

    def test_trail_not_logging_raises_critical(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        bucket = _create_log_bucket(s3)
        ct = aws_session.client("cloudtrail", region_name="us-east-1")
        ct.create_trail(Name="stopped-trail", S3BucketName=bucket, IsMultiRegionTrail=True)
        # deliberately NOT calling start_logging

        findings = LoggingScanner(aws_session).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="not actively logging")


# ── AWS Config ────────────────────────────────────────────────────────────────

class TestConfigRecorderIntegration:
    def test_no_config_recorder_raises_high(self, aws_session):
        findings = LoggingScanner(aws_session).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="AWS Config recorder is not configured")

    def test_config_recorder_present_no_config_finding(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        _create_log_bucket(s3, "config-logs-bucket")
        iam = aws_session.client("iam")
        role = iam.create_role(
            RoleName="config-role",
            AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"config.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
        )
        cfg = aws_session.client("config", region_name="us-east-1")
        cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": "default",
                "roleARN": role["Role"]["Arn"],
                "recordingGroup": {"allSupported": True},
            }
        )
        cfg.put_delivery_channel(
            DeliveryChannel={"name": "default", "s3BucketName": "config-logs-bucket"}
        )
        cfg.start_configuration_recorder(ConfigurationRecorderName="default")

        findings = LoggingScanner(aws_session).scan()
        config_findings = [
            f for f in findings
            if "config recorder is not configured" in f.title.lower()
        ]
        assert not config_findings
