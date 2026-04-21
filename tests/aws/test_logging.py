import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from scanner.aws.logging import LoggingScanner
from scanner.base import Severity
from tests.conftest import assert_finding, no_finding


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


def _make_scanner(ct_mock=None, cfg_mock=None):
    session = MagicMock()
    clients = {"cloudtrail": ct_mock or MagicMock(), "config": cfg_mock or MagicMock()}
    session.client.side_effect = lambda svc: clients[svc]
    return LoggingScanner(session)


# ── CloudTrail ────────────────────────────────────────────────────────────────

class TestCloudTrail:
    def test_no_trails_is_critical(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": []}
        cfg = MagicMock()
        cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": [{"name": "r"}]}
        cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"name": "r", "recording": True}]
        }
        findings = _make_scanner(ct, cfg).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="No CloudTrail trails")

    def test_trail_not_logging_is_critical(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {
            "trailList": [{
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main",
                "Name": "main",
                "IsMultiRegionTrail": True,
                "HomeRegion": "us-east-1",
                "LogFileValidationEnabled": True,
            }]
        }
        ct.get_trail_status.return_value = {"IsLogging": False}
        cfg = MagicMock()
        cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": [{"name": "r"}]}
        cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"name": "r", "recording": True}]
        }
        findings = _make_scanner(ct, cfg).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="not actively logging")

    def test_single_region_trail_is_high(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {
            "trailList": [{
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/single",
                "Name": "single",
                "IsMultiRegionTrail": False,
                "LogFileValidationEnabled": True,
            }]
        }
        ct.get_trail_status.return_value = {"IsLogging": True}
        cfg = MagicMock()
        cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": [{"name": "r"}]}
        cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"name": "r", "recording": True}]
        }
        findings = _make_scanner(ct, cfg).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="No multi-region CloudTrail")

    def test_log_validation_disabled_is_medium(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {
            "trailList": [{
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/noval",
                "Name": "noval",
                "IsMultiRegionTrail": True,
                "HomeRegion": "us-east-1",
                "LogFileValidationEnabled": False,
            }]
        }
        ct.get_trail_status.return_value = {"IsLogging": True}
        cfg = MagicMock()
        cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": [{"name": "r"}]}
        cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"name": "r", "recording": True}]
        }
        findings = _make_scanner(ct, cfg).scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="log file validation disabled")

    def test_healthy_trail_no_critical_finding(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {
            "trailList": [{
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/healthy",
                "Name": "healthy",
                "IsMultiRegionTrail": True,
                "HomeRegion": "us-east-1",
                "LogFileValidationEnabled": True,
            }]
        }
        ct.get_trail_status.return_value = {"IsLogging": True}
        cfg = MagicMock()
        cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": [{"name": "r"}]}
        cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"name": "r", "recording": True}]
        }
        findings = _make_scanner(ct, cfg).scan()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert not critical, f"Unexpected critical findings: {[f.title for f in critical]}"


# ── AWS Config ────────────────────────────────────────────────────────────────

class TestAWSConfig:
    def test_no_recorder_is_high(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": []}
        cfg = MagicMock()
        cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}
        findings = _make_scanner(ct, cfg).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="AWS Config recorder is not configured")

    def test_stopped_recorder_is_high(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": []}
        cfg = MagicMock()
        cfg.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [{"name": "default"}]
        }
        cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"name": "default", "recording": False}]
        }
        findings = _make_scanner(ct, cfg).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="AWS Config recorder is stopped")
