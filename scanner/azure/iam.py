import sys
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.core.exceptions import HttpResponseError
from scanner.base import BaseScanner, Category, Finding, Severity

_OVERPRIVILEGED_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
}


class AzureIAMScanner(BaseScanner):
    provider = "azure"

    def __init__(self, credential, subscription_id: str):
        self.client = AuthorizationManagementClient(credential, subscription_id)
        self.sub_id = subscription_id

    def scan(self) -> list[Finding]:
        findings = []
        findings += self._check_subscription_owners()
        findings += self._check_custom_roles()
        return findings

    def _check_subscription_owners(self) -> list[Finding]:
        findings = []
        scope = f"/subscriptions/{self.sub_id}"
        try:
            assignments = list(self.client.role_assignments.list_for_scope(scope))
            owner_count = 0
            for a in assignments:
                role_def_id = a.role_definition_id.split("/")[-1]
                role_name = _OVERPRIVILEGED_ROLES.get(role_def_id)
                if not role_name:
                    continue

                if role_name == "Owner":
                    owner_count += 1

                if role_name in ("Owner", "Contributor") and a.scope == scope:
                    principal = a.principal_id or "unknown"
                    findings.append(Finding(
                        provider="azure",
                        category=Category.IAM_PERMISSIONS,
                        severity=Severity.HIGH if role_name == "Contributor" else Severity.CRITICAL,
                        resource_type="Azure Role Assignment",
                        resource_id=a.id or principal,
                        title=f"Principal '{principal}' has '{role_name}' at subscription scope",
                        description=(
                            f"The role '{role_name}' is assigned at the subscription level. "
                            "This grants broad access to all resources in the subscription."
                        ),
                        recommendation=(
                            "Apply least-privilege: assign roles at resource group or resource scope. "
                            "Use built-in roles with narrower permissions."
                        ),
                    ))

            if owner_count > 3:
                findings.append(Finding(
                    provider="azure",
                    category=Category.IAM_PERMISSIONS,
                    severity=Severity.MEDIUM,
                    resource_type="Azure Subscription",
                    resource_id=f"/subscriptions/{self.sub_id}",
                    title=f"Subscription has {owner_count} Owner assignments (>3 recommended max)",
                    description=(
                        f"There are {owner_count} Owner-level principals on the subscription. "
                        "Each is a potential blast radius for compromise."
                    ),
                    recommendation=(
                        "Reduce Owner assignments to ≤3. Use Contributor or custom roles for daily tasks."
                    ),
                    extra={"owner_count": owner_count},
                ))
        except HttpResponseError as e:
            print(f"[Azure/IAM] Error: {e}", file=sys.stderr)
        return findings

    def _check_custom_roles(self) -> list[Finding]:
        findings = []
        scope = f"/subscriptions/{self.sub_id}"
        try:
            for role in self.client.role_definitions.list(scope, filter="type eq 'CustomRole'"):
                permissions = role.permissions or []
                for perm in permissions:
                    actions = perm.actions or []
                    if "*" in actions:
                        findings.append(Finding(
                            provider="azure",
                            category=Category.IAM_PERMISSIONS,
                            severity=Severity.HIGH,
                            resource_type="Azure Custom Role",
                            resource_id=role.id or role.name,
                            title=f"Custom role '{role.role_name}' has wildcard (*) actions",
                            description=(
                                "The custom role includes '*' in its actions list, "
                                "granting permissions equivalent to built-in Owner."
                            ),
                            recommendation=(
                                "Replace the wildcard with explicit, minimal action lists."
                            ),
                        ))
        except HttpResponseError:
            pass
        return findings
