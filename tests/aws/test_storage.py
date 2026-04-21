import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from scanner.aws.storage import S3Scanner
from scanner.base import Severity, Category
from tests.conftest import assert_finding, no_finding


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


def _make_scanner(s3_mock):
    session = MagicMock()
    session.client.return_value = s3_mock
    return S3Scanner(session)


# ── public ACL ───────────────────────────────────────────────────────────────

class TestS3PublicACL:
    def test_all_users_acl_is_critical(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "public-bucket"}]}
        s3.get_bucket_acl.return_value = {
            "Grants": [{
                "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ",
            }]
        }
        s3.get_public_access_block.side_effect = _client_error("NoSuchPublicAccessBlockConfiguration")
        s3.get_bucket_encryption.side_effect = _client_error("ServerSideEncryptionConfigurationNotFoundError")
        s3.get_bucket_versioning.return_value = {}

        findings = _make_scanner(s3).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="public-bucket")

    def test_authenticated_users_acl_is_critical(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "semi-public"}]}
        s3.get_bucket_acl.return_value = {
            "Grants": [{
                "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"},
                "Permission": "FULL_CONTROL",
            }]
        }
        s3.get_public_access_block.side_effect = _client_error("NoSuchPublicAccessBlockConfiguration")
        s3.get_bucket_encryption.side_effect = _client_error("ServerSideEncryptionConfigurationNotFoundError")
        s3.get_bucket_versioning.return_value = {}

        findings = _make_scanner(s3).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="semi-public")

    def test_private_acl_no_acl_finding(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "private-bucket"}]}
        s3.get_bucket_acl.return_value = {
            "Grants": [{"Grantee": {"Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}]
        }
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
        s3.get_bucket_versioning.return_value = {"Status": "Enabled"}

        findings = _make_scanner(s3).scan()
        no_finding(findings, title_contains="public ACL")


# ── Block Public Access ───────────────────────────────────────────────────────

class TestBlockPublicAccess:
    def test_missing_config_is_high(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "no-bpa"}]}
        s3.get_bucket_acl.return_value = {"Grants": []}
        s3.get_public_access_block.side_effect = _client_error("NoSuchPublicAccessBlockConfiguration")
        s3.get_bucket_encryption.side_effect = _client_error("ServerSideEncryptionConfigurationNotFoundError")
        s3.get_bucket_versioning.return_value = {}

        findings = _make_scanner(s3).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="no-bpa")

    def test_partial_block_is_high(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "partial-bpa"}]}
        s3.get_bucket_acl.return_value = {"Grants": []}
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": False,
            }
        }
        s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
        s3.get_bucket_versioning.return_value = {"Status": "Enabled"}

        findings = _make_scanner(s3).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="incomplete Block Public Access")


# ── Encryption ────────────────────────────────────────────────────────────────

class TestS3Encryption:
    def test_no_encryption_is_medium(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "unencrypted"}]}
        s3.get_bucket_acl.return_value = {"Grants": []}
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        s3.get_bucket_encryption.side_effect = _client_error("ServerSideEncryptionConfigurationNotFoundError")
        s3.get_bucket_versioning.return_value = {"Status": "Enabled"}

        findings = _make_scanner(s3).scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="no default encryption")


# ── Versioning ────────────────────────────────────────────────────────────────

class TestS3Versioning:
    def test_versioning_disabled_is_low(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "no-version"}]}
        s3.get_bucket_acl.return_value = {"Grants": []}
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
        s3.get_bucket_versioning.return_value = {"Status": "Suspended"}

        findings = _make_scanner(s3).scan()
        assert_finding(findings, severity=Severity.LOW, title_contains="versioning")

    def test_versioning_enabled_no_finding(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "versioned"}]}
        s3.get_bucket_acl.return_value = {"Grants": []}
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
        s3.get_bucket_versioning.return_value = {"Status": "Enabled"}

        findings = _make_scanner(s3).scan()
        no_finding(findings, title_contains="versioning")

    def test_empty_bucket_list_returns_no_findings(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": []}
        findings = _make_scanner(s3).scan()
        assert findings == []
