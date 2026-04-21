from scanner.base import BaseScanner, Category, Finding, Severity


class AzureMFAScanner(BaseScanner):
    """
    Checks per-user MFA enforcement via Microsoft Graph API.
    Requires: pip install msgraph-sdk
    App registration needs: UserAuthenticationMethod.Read.All (application permission)
    or Policy.Read.All for Conditional Access policies.
    """
    provider = "azure"

    def __init__(self, credential, tenant_id: str):
        self.credential = credential
        self.tenant_id = tenant_id

    def scan(self) -> list[Finding]:
        findings = []
        findings += self._check_conditional_access_mfa()
        findings += self._check_per_user_mfa()
        return findings

    def _check_conditional_access_mfa(self) -> list[Finding]:
        findings = []
        try:
            from msgraph import GraphServiceClient
            from msgraph.generated.identity.conditional_access.policies.policies_request_builder import (
                PoliciesRequestBuilder,
            )

            client = GraphServiceClient(self.credential)
            policies = client.identity.conditional_access.policies.get().value or []

            has_mfa_policy = False
            for policy in policies:
                if policy.state != "enabled":
                    continue
                grant_controls = policy.grant_controls
                if not grant_controls:
                    continue
                built_in = [str(c).lower() for c in (grant_controls.built_in_controls or [])]
                if "mfa" in built_in:
                    conditions = policy.conditions
                    users = conditions.users if conditions else None
                    # Policy must apply to all users (not scoped to a narrow group)
                    if users and getattr(users, "include_users", None) == ["All"]:
                        has_mfa_policy = True
                        break

            if not has_mfa_policy:
                findings.append(Finding(
                    provider="azure",
                    category=Category.MFA,
                    severity=Severity.CRITICAL,
                    resource_type="Azure Conditional Access Policy",
                    resource_id=f"tenants/{self.tenant_id}",
                    title="No Conditional Access policy enforces MFA for all users",
                    description=(
                        "No enabled Conditional Access policy requires MFA for all users. "
                        "Accounts can sign in with only a password."
                    ),
                    recommendation=(
                        "Create a Conditional Access policy that targets All Users, "
                        "All Cloud Apps, and grants access only when MFA is satisfied. "
                        "Exclude break-glass accounts with strong monitoring."
                    ),
                ))
        except ImportError:
            findings.append(Finding(
                provider="azure",
                category=Category.MFA,
                severity=Severity.INFO,
                resource_type="Azure MFA Check",
                resource_id=f"tenants/{self.tenant_id}",
                title="msgraph-sdk not installed — Conditional Access MFA check skipped",
                description="Install msgraph-sdk to enable per-policy MFA checks.",
                recommendation="pip install msgraph-sdk",
            ))
        except Exception as e:
            print(f"[Azure/MFA/ConditionalAccess] Error: {e}")
        return findings

    def _check_per_user_mfa(self) -> list[Finding]:
        """Check legacy per-user MFA state (still relevant for hybrid/legacy tenants)."""
        findings = []
        try:
            from msgraph import GraphServiceClient

            client = GraphServiceClient(self.credential)
            users_page = client.users.get(
                request_configuration=_users_select_config()
            ).value or []

            disabled_mfa_users = []
            for user in users_page:
                if getattr(user, "user_type", None) == "Guest":
                    continue
                auth_methods = _get_auth_methods(client, user.id)
                has_strong = any(
                    m for m in auth_methods
                    if _is_strong_method(m)
                )
                if not has_strong:
                    disabled_mfa_users.append(
                        getattr(user, "user_principal_name", user.id)
                    )

            if disabled_mfa_users:
                findings.append(Finding(
                    provider="azure",
                    category=Category.MFA,
                    severity=Severity.HIGH,
                    resource_type="Azure AD Users",
                    resource_id=f"tenants/{self.tenant_id}",
                    title=(
                        f"{len(disabled_mfa_users)} user(s) have no strong authentication method registered"
                    ),
                    description=(
                        f"{len(disabled_mfa_users)} member account(s) have no MFA method "
                        "(authenticator app, FIDO2, phone) registered: "
                        f"{', '.join(disabled_mfa_users[:10])}"
                        f"{'...' if len(disabled_mfa_users) > 10 else ''}."
                    ),
                    recommendation=(
                        "Require users to register MFA via the Azure AD combined registration "
                        "experience and enforce via Conditional Access."
                    ),
                    extra={"users_without_mfa": disabled_mfa_users},
                ))
        except ImportError:
            pass  # already reported above
        except Exception as e:
            print(f"[Azure/MFA/PerUser] Error: {e}")
        return findings


def _users_select_config():
    try:
        from msgraph.generated.users.users_request_builder import UsersRequestBuilder
        from kiota_abstractions.base_request_configuration import RequestConfiguration

        qp = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            select=["id", "userPrincipalName", "userType"],
            top=999,
        )
        return RequestConfiguration(query_parameters=qp)
    except Exception:
        return None


def _get_auth_methods(client, user_id: str) -> list:
    try:
        return client.users.by_user_id(user_id).authentication.methods.get().value or []
    except Exception:
        return []


def _is_strong_method(method) -> bool:
    weak_types = {
        "microsoft.graph.passwordAuthenticationMethod",
        "#microsoft.graph.passwordAuthenticationMethod",
    }
    odata_type = getattr(method, "odata_type", "") or ""
    return odata_type not in weak_types and odata_type != ""
