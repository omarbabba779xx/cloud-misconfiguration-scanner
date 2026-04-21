"""
Shared test fixtures.
SDK stubs must be registered in sys.modules BEFORE any scanner module is imported,
so they are declared here at module level (conftest.py is loaded first by pytest).
"""
import sys
from unittest.mock import MagicMock


# ── SDK stubs (avoids requiring azure / google-cloud installs to run tests) ───

class _AzureHttpResponseError(Exception):
    pass


class _GcpGoogleAPIError(Exception):
    pass


def _stub(*names):
    for name in names:
        sys.modules.setdefault(name, MagicMock())


# Azure
_azure_exc_stub = MagicMock()
_azure_exc_stub.HttpResponseError = _AzureHttpResponseError
_stub(
    "azure", "azure.identity",
    "azure.mgmt", "azure.mgmt.storage", "azure.mgmt.authorization",
    "azure.mgmt.monitor", "azure.mgmt.network",
    "azure.core", "azure.graphrbac",
)
sys.modules.setdefault("azure.core.exceptions", _azure_exc_stub)

# GCP
_gcp_exc_stub = MagicMock()
_gcp_exc_stub.GoogleAPIError = _GcpGoogleAPIError
_stub(
    "google", "google.cloud",
    "google.cloud.storage", "google.cloud.compute_v1", "google.cloud.logging",
    "google.cloud.resourcemanager_v3",
    "google.iam", "google.iam.v1", "google.iam.v1.iam_policy_pb2",
    "google.api_core", "google.auth",
    "google.oauth2", "google.oauth2.service_account",
    "googleapiclient", "googleapiclient.discovery",
)
sys.modules.setdefault("google.api_core.exceptions", _gcp_exc_stub)

# ── Imports (after stubs are registered) ─────────────────────────────────────

import pytest
from unittest.mock import MagicMock
from scanner.base import Finding, Severity, Category


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_finding(
    provider="aws",
    category=Category.PUBLIC_STORAGE,
    severity=Severity.HIGH,
    resource_type="S3 Bucket",
    resource_id="test-bucket",
    title="Test finding",
    description="desc",
    recommendation="rec",
) -> Finding:
    return Finding(
        provider=provider,
        category=category,
        severity=severity,
        resource_type=resource_type,
        resource_id=resource_id,
        title=title,
        description=description,
        recommendation=recommendation,
    )


def assert_finding(findings: list, *, severity: Severity, title_contains: str):
    matches = [
        f for f in findings
        if f.severity == severity and title_contains.lower() in f.title.lower()
    ]
    assert matches, (
        f"Expected finding with severity={severity.value} and title containing "
        f"'{title_contains}'. Got:\n"
        + "\n".join(f"  [{f.severity.value}] {f.title}" for f in findings)
    )


def no_finding(findings: list, *, title_contains: str):
    matches = [f for f in findings if title_contains.lower() in f.title.lower()]
    assert not matches, (
        f"Did not expect finding containing '{title_contains}'. Got:\n"
        + "\n".join(f"  [{f.severity.value}] {f.title}" for f in matches)
    )


@pytest.fixture
def mock_boto_session():
    return MagicMock()
