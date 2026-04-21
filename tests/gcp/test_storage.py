import pytest
from unittest.mock import MagicMock, patch
from scanner.gcp.storage import GCSScanner
from scanner.base import Severity
from tests.conftest import assert_finding, no_finding


def _bucket(name, public_members=None, uniform_access=True,
            versioning=True, logging=True, location="US"):
    b = MagicMock()
    b.name = name
    b.location = location
    b.versioning_enabled = versioning
    b.logging = {"logBucket": "log-bucket"} if logging else None

    # IAM policy
    policy = MagicMock()
    bindings = []
    if public_members:
        bindings.append({"role": "roles/storage.objectViewer", "members": public_members})
    policy.bindings = bindings
    b.get_iam_policy.return_value = policy

    # Uniform access config
    iam_cfg = MagicMock()
    iam_cfg.uniform_bucket_level_access_enabled = uniform_access
    b.iam_configuration = iam_cfg

    b.reload.return_value = None
    return b


def _make_scanner(buckets):
    with patch("scanner.gcp.storage.gcs.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = buckets
        mock_client_cls.return_value = mock_client
        scanner = GCSScanner.__new__(GCSScanner)
        scanner.client = mock_client
        scanner.project = "test-project"
        return scanner


# ── Public IAM ────────────────────────────────────────────────────────────────

class TestGCSPublicIAM:
    def test_all_users_is_critical(self):
        b = _bucket("public-bucket", public_members=["allUsers"])
        scanner = _make_scanner([b])
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="publicly accessible")

    def test_all_authenticated_users_is_critical(self):
        b = _bucket("semi-public", public_members=["allAuthenticatedUsers"])
        scanner = _make_scanner([b])
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="publicly accessible")

    def test_private_bucket_no_public_finding(self):
        b = _bucket("private-bucket")
        scanner = _make_scanner([b])
        findings = scanner.scan()
        no_finding(findings, title_contains="publicly accessible")


# ── Uniform bucket-level access ───────────────────────────────────────────────

class TestUniformAccess:
    def test_non_uniform_access_is_medium(self):
        b = _bucket("legacy-bucket", uniform_access=False)
        scanner = _make_scanner([b])
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="uniform bucket-level access")

    def test_uniform_access_enabled_no_finding(self):
        b = _bucket("modern-bucket", uniform_access=True)
        scanner = _make_scanner([b])
        findings = scanner.scan()
        no_finding(findings, title_contains="uniform bucket-level access")


# ── Versioning ────────────────────────────────────────────────────────────────

class TestGCSVersioning:
    def test_versioning_disabled_is_low(self):
        b = _bucket("no-version", versioning=False)
        scanner = _make_scanner([b])
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.LOW, title_contains="versioning")

    def test_versioning_enabled_no_finding(self):
        b = _bucket("versioned-bucket", versioning=True)
        scanner = _make_scanner([b])
        findings = scanner.scan()
        no_finding(findings, title_contains="versioning")


# ── Access logging ────────────────────────────────────────────────────────────

class TestGCSLogging:
    def test_no_logging_is_medium(self):
        b = _bucket("no-logs", logging=False)
        scanner = _make_scanner([b])
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="access logging")

    def test_logging_enabled_no_finding(self):
        b = _bucket("logged-bucket", logging=True)
        scanner = _make_scanner([b])
        findings = scanner.scan()
        no_finding(findings, title_contains="access logging")
