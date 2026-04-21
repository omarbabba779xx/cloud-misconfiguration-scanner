"""
Integration tests for AWS S3 scanner using moto.
moto intercepts all boto3 calls and simulates a real AWS environment locally —
no credentials or internet connection required.
"""
import boto3
import pytest
from moto import mock_aws
from scanner.aws.storage import S3Scanner
from scanner.base import Severity
from tests.conftest import assert_finding, no_finding


@pytest.fixture
def aws_session():
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


# ── Public ACL ────────────────────────────────────────────────────────────────

class TestS3PublicACLIntegration:
    def test_bucket_with_public_read_acl_raises_critical(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="public-bucket")
        s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

        findings = S3Scanner(aws_session).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="public-bucket")

    def test_private_bucket_no_public_acl_finding(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="private-bucket")
        s3.put_public_access_block(
            Bucket="private-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3.put_bucket_encryption(
            Bucket="private-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
        s3.put_bucket_versioning(
            Bucket="private-bucket",
            VersioningConfiguration={"Status": "Enabled"},
        )
        findings = S3Scanner(aws_session).scan()
        no_finding(findings, title_contains="public ACL")


# ── Block Public Access ───────────────────────────────────────────────────────

class TestBlockPublicAccessIntegration:
    def test_bucket_without_block_public_access_raises_high(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="no-bpa-bucket")
        findings = S3Scanner(aws_session).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="no-bpa-bucket")

    def test_bucket_with_full_block_public_access_no_bpa_finding(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="full-bpa-bucket")
        s3.put_public_access_block(
            Bucket="full-bpa-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        findings = S3Scanner(aws_session).scan()
        bpa_findings = [
            f for f in findings
            if "full-bpa-bucket" in f.resource_id
            and "Block Public Access" in f.title
        ]
        assert not bpa_findings, f"Unexpected BPA findings: {[f.title for f in bpa_findings]}"


# ── Encryption ────────────────────────────────────────────────────────────────

class TestEncryptionIntegration:
    def test_bucket_without_encryption_raises_medium(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="unencrypted-bucket")
        findings = S3Scanner(aws_session).scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="no default encryption")

    def test_bucket_with_aes256_encryption_no_finding(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="encrypted-bucket")
        s3.put_bucket_encryption(
            Bucket="encrypted-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
        findings = S3Scanner(aws_session).scan()
        enc_findings = [
            f for f in findings
            if "encrypted-bucket" in f.resource_id and "encryption" in f.title.lower()
        ]
        assert not enc_findings

    def test_bucket_with_kms_encryption_no_finding(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="kms-bucket")
        s3.put_bucket_encryption(
            Bucket="kms-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "alias/aws/s3",
                }}]
            },
        )
        findings = S3Scanner(aws_session).scan()
        enc_findings = [
            f for f in findings
            if "kms-bucket" in f.resource_id and "encryption" in f.title.lower()
        ]
        assert not enc_findings


# ── Versioning ────────────────────────────────────────────────────────────────

class TestVersioningIntegration:
    def test_bucket_without_versioning_raises_low(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="no-version-bucket")
        findings = S3Scanner(aws_session).scan()
        assert_finding(findings, severity=Severity.LOW, title_contains="versioning")

    def test_bucket_with_versioning_enabled_no_finding(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="versioned-bucket")
        s3.put_bucket_versioning(
            Bucket="versioned-bucket",
            VersioningConfiguration={"Status": "Enabled"},
        )
        findings = S3Scanner(aws_session).scan()
        ver_findings = [
            f for f in findings
            if "versioned-bucket" in f.resource_id and "versioning" in f.title.lower()
        ]
        assert not ver_findings

    def test_multiple_buckets_correct_count(self, aws_session):
        s3 = aws_session.client("s3", region_name="us-east-1")
        for name in ["bucket-a", "bucket-b", "bucket-c"]:
            s3.create_bucket(Bucket=name)
        findings = S3Scanner(aws_session).scan()
        # Each bucket should produce findings (at least versioning LOW)
        buckets_with_findings = {f.resource_id for f in findings}
        assert "bucket-a" in buckets_with_findings
        assert "bucket-b" in buckets_with_findings
        assert "bucket-c" in buckets_with_findings

    def test_no_buckets_no_findings(self, aws_session):
        findings = S3Scanner(aws_session).scan()
        assert findings == []
