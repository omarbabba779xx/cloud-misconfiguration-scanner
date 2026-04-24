import sys
from google.cloud import storage as gcs
from google.api_core.exceptions import GoogleAPIError
from scanner.base import BaseScanner, Category, Finding, Severity

_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


class GCSScanner(BaseScanner):
    provider = "gcp"

    def __init__(self, project: str):
        self.client = gcs.Client(project=project)
        self.project = project

    def scan(self) -> list[Finding]:
        findings = []
        try:
            for bucket in self.client.list_buckets():
                findings += self._check_public_iam(bucket)
                findings += self._check_uniform_access(bucket)
                findings += self._check_versioning(bucket)
                findings += self._check_logging(bucket)
        except GoogleAPIError as e:
            print(f"[GCP/Storage] Error: {e}", file=sys.stderr)
        return findings

    def _check_public_iam(self, bucket) -> list[Finding]:
        findings = []
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                members = binding.get("members", [])
                role = binding.get("role", "")
                public = [m for m in members if m in _PUBLIC_MEMBERS]
                if public:
                    findings.append(Finding(
                        provider="gcp",
                        category=Category.PUBLIC_STORAGE,
                        severity=Severity.CRITICAL,
                        resource_type="GCS Bucket",
                        resource_id=bucket.name,
                        title=f"GCS bucket '{bucket.name}' is publicly accessible",
                        description=(
                            f"IAM binding grants '{role}' to {public}. "
                            "Any internet user can access this bucket."
                        ),
                        recommendation=(
                            "Remove allUsers/allAuthenticatedUsers from IAM bindings. "
                            "Use signed URLs for time-limited public sharing."
                        ),
                        region=bucket.location,
                    ))
        except GoogleAPIError:
            pass
        return findings

    def _check_uniform_access(self, bucket) -> list[Finding]:
        if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
            return [Finding(
                provider="gcp",
                category=Category.PUBLIC_STORAGE,
                severity=Severity.MEDIUM,
                resource_type="GCS Bucket",
                resource_id=bucket.name,
                title=f"GCS bucket '{bucket.name}' does not use uniform bucket-level access",
                description=(
                    "Object-level ACLs are enabled. Individual objects may be made public "
                    "without affecting the bucket IAM policy."
                ),
                recommendation=(
                    "Enable uniform bucket-level access to enforce IAM-only access control."
                ),
                region=bucket.location,
            )]
        return []

    def _check_versioning(self, bucket) -> list[Finding]:
        if not bucket.versioning_enabled:
            return [Finding(
                provider="gcp",
                category=Category.PUBLIC_STORAGE,
                severity=Severity.LOW,
                resource_type="GCS Bucket",
                resource_id=bucket.name,
                title=f"GCS bucket '{bucket.name}' does not have versioning enabled",
                description="Object versioning is off; accidental deletions are unrecoverable.",
                recommendation="Enable versioning and configure lifecycle rules to control version retention.",
                region=bucket.location,
            )]
        return []

    def _check_logging(self, bucket) -> list[Finding]:
        if not bucket.logging:
            return [Finding(
                provider="gcp",
                category=Category.LOGGING,
                severity=Severity.MEDIUM,
                resource_type="GCS Bucket",
                resource_id=bucket.name,
                title=f"GCS bucket '{bucket.name}' does not have access logging enabled",
                description="Access logs are not being written; read/write activity cannot be audited.",
                recommendation=(
                    "Enable access logs on the bucket and direct them to a separate logging bucket."
                ),
                region=bucket.location,
            )]
        return []
