import sys
from google.cloud import logging as gcp_logging
from google.api_core.exceptions import GoogleAPIError
from scanner.base import BaseScanner, Category, Finding, Severity


class GCPLoggingScanner(BaseScanner):
    provider = "gcp"

    def __init__(self, project: str):
        self.project = project
        self.client = gcp_logging.Client(project=project)

    def scan(self) -> list[Finding]:
        findings = []
        findings += self._check_log_sinks()
        findings += self._check_audit_config()
        return findings

    def _check_log_sinks(self) -> list[Finding]:
        findings = []
        try:
            sinks = list(self.client.list_sinks())
            if not sinks:
                findings.append(Finding(
                    provider="gcp",
                    category=Category.LOGGING,
                    severity=Severity.HIGH,
                    resource_type="GCP Log Sink",
                    resource_id=self.project,
                    title=f"Project '{self.project}' has no log sinks configured",
                    description=(
                        "No log sinks exist; logs are only retained for the default period "
                        "(30 days for most log types) and not exported for long-term analysis."
                    ),
                    recommendation=(
                        "Create a log sink to Cloud Storage or BigQuery for audit log retention "
                        "and SIEM integration."
                    ),
                ))
            else:
                has_active = any(not getattr(s, "disabled", False) for s in sinks)
                if not has_active:
                    findings.append(Finding(
                        provider="gcp",
                        category=Category.LOGGING,
                        severity=Severity.HIGH,
                        resource_type="GCP Log Sink",
                        resource_id=self.project,
                        title=f"All log sinks in project '{self.project}' are disabled",
                        description="Log sinks exist but none are active; logs are not being exported.",
                        recommendation="Enable at least one log sink targeting a secure destination.",
                    ))
        except GoogleAPIError as e:
            print(f"[GCP/Logging] Error: {e}", file=sys.stderr)
        return findings

    def _check_audit_config(self) -> list[Finding]:
        """Check that Data Access audit logs are enabled for critical services."""
        findings = []
        try:
            from google.cloud import resourcemanager_v3
            from google.iam.v1 import iam_policy_pb2

            rm = resourcemanager_v3.ProjectsClient()
            request = iam_policy_pb2.GetIamPolicyRequest(
                resource=f"projects/{self.project}"
            )
            policy = rm.get_iam_policy(request=request)

            audit_configs = {ac.service: ac for ac in policy.audit_configs}
            critical_services = [
                "storage.googleapis.com",
                "iam.googleapis.com",
                "cloudresourcemanager.googleapis.com",
            ]

            for service in critical_services:
                if service not in audit_configs:
                    findings.append(Finding(
                        provider="gcp",
                        category=Category.LOGGING,
                        severity=Severity.MEDIUM,
                        resource_type="GCP Audit Config",
                        resource_id=f"{self.project}/{service}",
                        title=f"Data Access audit logs not configured for '{service}'",
                        description=(
                            f"Data Access audit logs (DATA_READ, DATA_WRITE) are not enabled for "
                            f"'{service}'. Sensitive operations on this service go unlogged."
                        ),
                        recommendation=(
                            f"Enable DATA_READ and DATA_WRITE audit log types for '{service}' "
                            "in the project's IAM audit configuration."
                        ),
                        extra={"service": service},
                    ))
        except (GoogleAPIError, Exception) as e:
            print(f"[GCP/Logging/AuditConfig] Error: {e}", file=sys.stderr)
        return findings
