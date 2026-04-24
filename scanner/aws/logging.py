import sys
import boto3
from botocore.exceptions import ClientError
from scanner.base import BaseScanner, Category, Finding, Severity


class LoggingScanner(BaseScanner):
    provider = "aws"

    def __init__(self, session: boto3.Session):
        self.session = session
        self.cloudtrail = session.client("cloudtrail")
        self.config = session.client("config")

    def scan(self) -> list[Finding]:
        findings = []
        findings += self._check_cloudtrail()
        findings += self._check_cloudtrail_log_validation()
        findings += self._check_config_recorder()
        return findings

    def _check_cloudtrail(self) -> list[Finding]:
        findings = []
        try:
            trails = self.cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
            if not trails:
                return [Finding(
                    provider="aws",
                    category=Category.LOGGING,
                    severity=Severity.CRITICAL,
                    resource_type="CloudTrail",
                    resource_id="account",
                    title="No CloudTrail trails are configured",
                    description=(
                        "CloudTrail is not enabled. API calls and user activity are not being logged, "
                        "making it impossible to audit or detect malicious activity."
                    ),
                    recommendation=(
                        "Create a multi-region CloudTrail trail that logs management events and "
                        "stores logs in a dedicated, access-controlled S3 bucket."
                    ),
                )]

            multi_region_active = False
            for trail in trails:
                trail_arn = trail["TrailARN"]
                name = trail["Name"]
                try:
                    status = self.cloudtrail.get_trail_status(Name=trail_arn)
                    is_logging = status.get("IsLogging", False)
                    if not is_logging:
                        findings.append(Finding(
                            provider="aws",
                            category=Category.LOGGING,
                            severity=Severity.CRITICAL,
                            resource_type="CloudTrail Trail",
                            resource_id=trail_arn,
                            title=f"CloudTrail trail '{name}' is not actively logging",
                            description="The trail exists but logging is currently disabled.",
                            recommendation="Enable logging on the trail via the Console or aws cloudtrail start-logging.",
                        ))
                except ClientError:
                    pass

                if trail.get("IsMultiRegionTrail") and is_logging:
                    multi_region_active = True

            if not multi_region_active:
                findings.append(Finding(
                    provider="aws",
                    category=Category.LOGGING,
                    severity=Severity.HIGH,
                    resource_type="CloudTrail",
                    resource_id="account",
                    title="No multi-region CloudTrail trail is configured",
                    description=(
                        "Existing trails are single-region. Activity in other regions "
                        "goes unlogged."
                    ),
                    recommendation=(
                        "Configure at least one multi-region trail to capture global API activity."
                    ),
                ))
        except ClientError as e:
            print(f"[AWS/CloudTrail] Error: {e}", file=sys.stderr)
        return findings

    def _check_cloudtrail_log_validation(self) -> list[Finding]:
        findings = []
        try:
            trails = self.cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
            for trail in trails:
                if not trail.get("LogFileValidationEnabled"):
                    findings.append(Finding(
                        provider="aws",
                        category=Category.LOGGING,
                        severity=Severity.MEDIUM,
                        resource_type="CloudTrail Trail",
                        resource_id=trail["TrailARN"],
                        title=f"CloudTrail trail '{trail['Name']}' has log file validation disabled",
                        description=(
                            "Without log file validation, tampering with log files cannot be detected."
                        ),
                        recommendation="Enable log file validation on the trail.",
                    ))
        except ClientError:
            pass
        return findings

    def _check_config_recorder(self) -> list[Finding]:
        findings = []
        try:
            recorders = self.config.describe_configuration_recorders().get("ConfigurationRecorders", [])
            if not recorders:
                findings.append(Finding(
                    provider="aws",
                    category=Category.LOGGING,
                    severity=Severity.HIGH,
                    resource_type="AWS Config",
                    resource_id="account",
                    title="AWS Config recorder is not configured",
                    description=(
                        "AWS Config is not recording resource configuration changes. "
                        "Compliance drift and resource history cannot be tracked."
                    ),
                    recommendation=(
                        "Enable AWS Config with a recorder that captures all resource types "
                        "and delivers snapshots to S3."
                    ),
                ))
            else:
                statuses = self.config.describe_configuration_recorder_status().get(
                    "ConfigurationRecordersStatus", []
                )
                for s in statuses:
                    if not s.get("recording"):
                        findings.append(Finding(
                            provider="aws",
                            category=Category.LOGGING,
                            severity=Severity.HIGH,
                            resource_type="AWS Config",
                            resource_id=s.get("name", "unknown"),
                            title="AWS Config recorder is stopped",
                            description="A Config recorder exists but is not currently recording.",
                            recommendation="Start the AWS Config recorder.",
                        ))
        except ClientError:
            pass
        return findings
