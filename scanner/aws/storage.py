import boto3
from botocore.exceptions import ClientError
from scanner.base import BaseScanner, Category, Finding, Severity


class S3Scanner(BaseScanner):
    provider = "aws"

    def __init__(self, session: boto3.Session):
        self.s3 = session.client("s3")

    def scan(self) -> list[Finding]:
        findings = []
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
        except ClientError as e:
            print(f"[AWS/S3] Permission error: {e}")
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            findings += self._check_public_acl(name)
            findings += self._check_public_block(name)
            findings += self._check_encryption(name)
            findings += self._check_versioning(name)

        return findings

    def _check_public_acl(self, name: str) -> list[Finding]:
        findings = []
        try:
            acl = self.s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    audience = "Everyone" if "AllUsers" in uri else "All AWS authenticated users"
                    findings.append(Finding(
                        provider="aws",
                        category=Category.PUBLIC_STORAGE,
                        severity=Severity.CRITICAL,
                        resource_type="S3 Bucket",
                        resource_id=name,
                        title=f"S3 bucket '{name}' has a public ACL",
                        description=(
                            f"The bucket ACL grants {grant['Permission']} access to {audience}. "
                            "This exposes all objects in the bucket to the public internet."
                        ),
                        recommendation=(
                            "Remove public ACL grants and enable S3 Block Public Access at the "
                            "bucket and account level."
                        ),
                    ))
        except ClientError:
            pass
        return findings

    def _check_public_block(self, name: str) -> list[Finding]:
        findings = []
        try:
            cfg = self.s3.get_public_access_block(Bucket=name)
            block = cfg.get("PublicAccessBlockConfiguration", {})
            missing = [k for k, v in block.items() if not v]
            if missing:
                findings.append(Finding(
                    provider="aws",
                    category=Category.PUBLIC_STORAGE,
                    severity=Severity.HIGH,
                    resource_type="S3 Bucket",
                    resource_id=name,
                    title=f"S3 bucket '{name}' has incomplete Block Public Access settings",
                    description=f"The following Block Public Access settings are disabled: {', '.join(missing)}.",
                    recommendation=(
                        "Enable all four Block Public Access settings on the bucket and at "
                        "the AWS account level."
                    ),
                    extra={"disabled_settings": missing},
                ))
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                findings.append(Finding(
                    provider="aws",
                    category=Category.PUBLIC_STORAGE,
                    severity=Severity.HIGH,
                    resource_type="S3 Bucket",
                    resource_id=name,
                    title=f"S3 bucket '{name}' has no Block Public Access configuration",
                    description="Block Public Access is not configured on this bucket.",
                    recommendation="Enable all Block Public Access settings on the bucket.",
                ))
        return findings

    def _check_encryption(self, name: str) -> list[Finding]:
        findings = []
        try:
            self.s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(Finding(
                    provider="aws",
                    category=Category.PUBLIC_STORAGE,
                    severity=Severity.MEDIUM,
                    resource_type="S3 Bucket",
                    resource_id=name,
                    title=f"S3 bucket '{name}' has no default encryption",
                    description="Objects uploaded to this bucket are not encrypted by default.",
                    recommendation=(
                        "Enable SSE-S3 or SSE-KMS default encryption on the bucket."
                    ),
                ))
        return findings

    def _check_versioning(self, name: str) -> list[Finding]:
        findings = []
        try:
            v = self.s3.get_bucket_versioning(Bucket=name)
            if v.get("Status") != "Enabled":
                findings.append(Finding(
                    provider="aws",
                    category=Category.PUBLIC_STORAGE,
                    severity=Severity.LOW,
                    resource_type="S3 Bucket",
                    resource_id=name,
                    title=f"S3 bucket '{name}' does not have versioning enabled",
                    description="Versioning is disabled; accidental deletions cannot be recovered.",
                    recommendation="Enable versioning and consider MFA Delete for sensitive buckets.",
                ))
        except ClientError:
            pass
        return findings
