from scanner.base import BaseScanner, Category, Finding, Severity


class GCPMFAScanner(BaseScanner):
    """
    Checks 2-Step Verification (2SV) enforcement via Google Workspace Admin SDK.
    Requires: pip install google-api-python-client
    Service account needs domain-wide delegation with scope:
      https://www.googleapis.com/auth/admin.directory.user.readonly
    Set env var GOOGLE_ADMIN_EMAIL to an admin email for impersonation.
    """
    provider = "gcp"

    def __init__(self, project: str, admin_email: str | None = None):
        self.project = project
        self.admin_email = admin_email

    def scan(self) -> list[Finding]:
        findings = []
        findings += self._check_org_2sv_enforcement()
        findings += self._check_users_without_2sv()
        return findings

    def _check_org_2sv_enforcement(self) -> list[Finding]:
        findings = []
        try:
            service = self._build_admin_service()
            if service is None:
                return findings

            # Check organization-level 2SV policy via Admin Settings API
            # Uses the Reports/Admin SDK — org unit security settings
            orgunits = service.orgunits().list(customerId="my_customer", type="all").execute()
            units = orgunits.get("organizationUnits", [])

            # Root OU is the one with no parentOrgUnitId
            root_checked = False
            for ou in units:
                if "parentOrgUnitId" not in ou:
                    root_checked = True
                    # We can't read 2SV policy directly from this API;
                    # check via users below instead
                    break

            if not root_checked and not units:
                # Single-domain org — still check via user enumeration
                pass

        except ImportError:
            findings.append(Finding(
                provider="gcp",
                category=Category.MFA,
                severity=Severity.INFO,
                resource_type="GCP MFA Check",
                resource_id=self.project,
                title="google-api-python-client not installed — 2SV enforcement check skipped",
                description="Install google-api-python-client to enable per-user 2SV checks.",
                recommendation="pip install google-api-python-client google-auth-httplib2",
            ))
        except Exception as e:
            print(f"[GCP/MFA/OrgPolicy] Error: {e}")
        return findings

    def _check_users_without_2sv(self) -> list[Finding]:
        findings = []
        try:
            service = self._build_admin_service()
            if service is None:
                return findings

            no_2sv_users = []
            not_enrolled_users = []
            page_token = None

            while True:
                result = service.users().list(
                    customer="my_customer",
                    projection="full",
                    orderBy="email",
                    pageToken=page_token,
                    maxResults=500,
                ).execute()

                for user in result.get("users", []):
                    email = user.get("primaryEmail", user.get("id", "unknown"))
                    is_enrolled = user.get("isEnrolledIn2Sv", False)
                    is_enforced = user.get("isEnforcedIn2Sv", False)
                    is_suspended = user.get("suspended", False)
                    is_admin = user.get("isAdmin", False) or user.get("isDelegatedAdmin", False)

                    if is_suspended:
                        continue

                    if not is_enrolled:
                        not_enrolled_users.append(email)
                        if is_admin:
                            # Admins without 2SV are critical
                            findings.append(Finding(
                                provider="gcp",
                                category=Category.MFA,
                                severity=Severity.CRITICAL,
                                resource_type="Google Workspace Admin User",
                                resource_id=email,
                                title=f"Admin user '{email}' does not have 2-Step Verification enrolled",
                                description=(
                                    f"'{email}' is a Google Workspace admin but has not enrolled in 2SV. "
                                    "A compromised admin account gives full access to the organization."
                                ),
                                recommendation=(
                                    "Require 2SV immediately for all admin accounts. "
                                    "Enforce via Admin Console > Security > 2-Step Verification."
                                ),
                            ))

                    elif not is_enforced and is_admin:
                        findings.append(Finding(
                            provider="gcp",
                            category=Category.MFA,
                            severity=Severity.HIGH,
                            resource_type="Google Workspace Admin User",
                            resource_id=email,
                            title=f"Admin user '{email}' has 2SV enrolled but not enforced",
                            description=(
                                f"'{email}' has 2SV enrolled but policy enforcement is disabled, "
                                "so they could bypass it."
                            ),
                            recommendation=(
                                "Enable 2SV enforcement for admin accounts in the Admin Console."
                            ),
                        ))

                page_token = result.get("nextPageToken")
                if not page_token:
                    break

            if len(not_enrolled_users) > 0:
                non_admin_without_2sv = [
                    u for u in not_enrolled_users
                    if not any(f.resource_id == u for f in findings)
                ]
                if non_admin_without_2sv:
                    findings.append(Finding(
                        provider="gcp",
                        category=Category.MFA,
                        severity=Severity.HIGH,
                        resource_type="Google Workspace Users",
                        resource_id=self.project,
                        title=(
                            f"{len(non_admin_without_2sv)} non-admin user(s) without 2-Step Verification"
                        ),
                        description=(
                            f"{len(non_admin_without_2sv)} active users have not enrolled in 2SV: "
                            f"{', '.join(non_admin_without_2sv[:10])}"
                            f"{'...' if len(non_admin_without_2sv) > 10 else ''}."
                        ),
                        recommendation=(
                            "Enable 2SV enforcement for all users in Admin Console > Security > "
                            "2-Step Verification. Set an enrollment period and choose FIDO2/Passkey "
                            "as the preferred method."
                        ),
                        extra={"users_without_2sv": non_admin_without_2sv},
                    ))

        except ImportError:
            pass  # already reported above
        except Exception as e:
            print(f"[GCP/MFA/Users] Error: {e}")
        return findings

    def _build_admin_service(self):
        import os
        try:
            import googleapiclient.discovery as discovery
            import google.auth
            from google.oauth2 import service_account

            scopes = ["https://www.googleapis.com/auth/admin.directory.user.readonly"]
            admin_email = self.admin_email or os.environ.get("GOOGLE_ADMIN_EMAIL")

            creds_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            if creds_file and admin_email:
                creds = service_account.Credentials.from_service_account_file(
                    creds_file, scopes=scopes
                ).with_subject(admin_email)
            else:
                creds, _ = google.auth.default(scopes=scopes)

            return discovery.build("admin", "directory_v1", credentials=creds, cache_discovery=False)
        except Exception as e:
            print(f"[GCP/MFA] Could not build Admin SDK client: {e}")
            return None
