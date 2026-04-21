from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2
from google.api_core.exceptions import GoogleAPIError
from scanner.base import BaseScanner, Category, Finding, Severity

_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
_PRIMITIVE_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}
_HIGH_RISK_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/resourcemanager.projectIamAdmin",
}


class GCPIAMScanner(BaseScanner):
    provider = "gcp"

    def __init__(self, project: str):
        self.project = project
        self.rm_client = resourcemanager_v3.ProjectsClient()

    def scan(self) -> list[Finding]:
        findings = []
        findings += self._check_project_iam()
        return findings

    def _check_project_iam(self) -> list[Finding]:
        findings = []
        try:
            request = iam_policy_pb2.GetIamPolicyRequest(
                resource=f"projects/{self.project}"
            )
            policy = self.rm_client.get_iam_policy(request=request)

            owner_count = 0
            for binding in policy.bindings:
                role = binding.role
                members = list(binding.members)

                # Check public access to project-level roles
                public = [m for m in members if m in _PUBLIC_MEMBERS]
                if public:
                    findings.append(Finding(
                        provider="gcp",
                        category=Category.IAM_PERMISSIONS,
                        severity=Severity.CRITICAL,
                        resource_type="GCP Project IAM",
                        resource_id=self.project,
                        title=f"Project '{self.project}' grants '{role}' to public",
                        description=(
                            f"Role '{role}' is assigned to {public}. "
                            "Any unauthenticated internet user has this access."
                        ),
                        recommendation=(
                            "Remove allUsers and allAuthenticatedUsers from all project IAM bindings."
                        ),
                    ))

                # Count owners
                if role == "roles/owner":
                    owner_count += len(members)

                # Flag primitive roles on projects
                if role in _PRIMITIVE_ROLES and role != "roles/viewer":
                    for member in members:
                        if member in _PUBLIC_MEMBERS:
                            continue
                        findings.append(Finding(
                            provider="gcp",
                            category=Category.IAM_PERMISSIONS,
                            severity=Severity.HIGH if role == "roles/editor" else Severity.CRITICAL,
                            resource_type="GCP Project IAM",
                            resource_id=f"{self.project}/{member}",
                            title=f"Primitive role '{role}' granted to '{member}' at project level",
                            description=(
                                f"Primitive roles (owner/editor) grant broad access to all GCP services "
                                f"in the project. Member '{member}' has unrestricted {role.split('/')[-1]} access."
                            ),
                            recommendation=(
                                "Replace primitive roles with granular predefined or custom roles "
                                "scoped to specific resources."
                            ),
                        ))

            if owner_count > 3:
                findings.append(Finding(
                    provider="gcp",
                    category=Category.IAM_PERMISSIONS,
                    severity=Severity.MEDIUM,
                    resource_type="GCP Project IAM",
                    resource_id=self.project,
                    title=f"Project has {owner_count} Owner bindings (>3 recommended max)",
                    description=(
                        f"There are {owner_count} members with the Owner role. "
                        "Excess owners increase the blast radius of a compromised account."
                    ),
                    recommendation="Reduce Owner assignments to ≤3 and use roles/editor for routine tasks.",
                    extra={"owner_count": owner_count},
                ))

        except GoogleAPIError as e:
            print(f"[GCP/IAM] Error: {e}")
        return findings
