from azure.mgmt.monitor import MonitorManagementClient
from azure.core.exceptions import HttpResponseError
from scanner.base import BaseScanner, Category, Finding, Severity


class AzureLoggingScanner(BaseScanner):
    provider = "azure"

    def __init__(self, credential, subscription_id: str):
        self.monitor = MonitorManagementClient(credential, subscription_id)
        self.sub_id = subscription_id

    def scan(self) -> list[Finding]:
        findings = []
        findings += self._check_activity_log_alerts()
        findings += self._check_diagnostic_settings()
        return findings

    def _check_activity_log_alerts(self) -> list[Finding]:
        findings = []
        required_operations = {
            "Microsoft.Authorization/policyAssignments/write": "Policy assignment created/modified",
            "Microsoft.Network/networkSecurityGroups/write": "NSG modified",
            "Microsoft.Network/networkSecurityGroups/delete": "NSG deleted",
            "Microsoft.Security/securityContact/write": "Security contact changed",
            "Microsoft.Sql/servers/firewallRules/write": "SQL firewall rule modified",
        }
        try:
            alerts = list(self.monitor.activity_log_alerts.list_by_subscription_id())
            covered_ops = set()
            for alert in alerts:
                if not alert.enabled:
                    continue
                condition = alert.condition
                if condition:
                    for all_of in (condition.all_of or []):
                        val = getattr(all_of, "equals", None) or ""
                        covered_ops.add(val.lower())

            for op, description in required_operations.items():
                if op.lower() not in covered_ops:
                    findings.append(Finding(
                        provider="azure",
                        category=Category.LOGGING,
                        severity=Severity.MEDIUM,
                        resource_type="Azure Activity Log Alert",
                        resource_id=f"subscriptions/{self.sub_id}",
                        title=f"No activity log alert for '{description}'",
                        description=(
                            f"Operation '{op}' is not covered by any enabled activity log alert. "
                            "Security-relevant changes may go undetected."
                        ),
                        recommendation=(
                            f"Create an activity log alert for '{op}' and send notifications "
                            "to a security team action group."
                        ),
                        extra={"missing_operation": op},
                    ))
        except HttpResponseError as e:
            print(f"[Azure/Logging] Error: {e}")
        return findings

    def _check_diagnostic_settings(self) -> list[Finding]:
        findings = []
        scope = f"/subscriptions/{self.sub_id}"
        try:
            settings = list(self.monitor.diagnostic_settings.list(scope))
            if not settings:
                findings.append(Finding(
                    provider="azure",
                    category=Category.LOGGING,
                    severity=Severity.HIGH,
                    resource_type="Azure Diagnostic Settings",
                    resource_id=scope,
                    title="No diagnostic settings configured for the subscription",
                    description=(
                        "Subscription-level diagnostic settings are not configured. "
                        "Activity logs may not be exported to a SIEM or Log Analytics workspace."
                    ),
                    recommendation=(
                        "Configure diagnostic settings to send Activity Log categories "
                        "(Administrative, Security, Alert, Policy) to a Log Analytics workspace."
                    ),
                ))
        except HttpResponseError:
            pass
        return findings
