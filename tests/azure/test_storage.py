import pytest
from unittest.mock import MagicMock, PropertyMock, patch
from scanner.azure.storage import AzureStorageScanner
from scanner.base import Severity
from tests.conftest import assert_finding, no_finding


def _account(name="test-sa", location="eastus", allow_public=False,
             https_only=True, tls="TLS1_2", key_source="Microsoft.Keyvault"):
    acc = MagicMock()
    acc.name = name
    acc.location = location
    acc.id = f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{name}"
    acc.allow_blob_public_access = allow_public
    acc.enable_https_traffic_only = https_only
    acc.minimum_tls_version = tls
    enc = MagicMock()
    enc.key_source = key_source
    acc.encryption = enc
    return acc


def _make_scanner(accounts, containers_per_account=None):
    credential = MagicMock()
    scanner = AzureStorageScanner.__new__(AzureStorageScanner)
    client = MagicMock()
    client.storage_accounts.list.return_value = accounts
    if containers_per_account:
        client.blob_containers.list.side_effect = lambda rg, name: containers_per_account.get(name, [])
    else:
        client.blob_containers.list.return_value = []
    scanner.client = client
    scanner.sub_id = "sub"
    return scanner


# ── Public blob access ────────────────────────────────────────────────────────

class TestPublicBlobAccess:
    def test_public_access_enabled_is_critical(self):
        acc = _account(allow_public=True)
        scanner = _make_scanner([acc])
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="allows public blob access")

    def test_public_access_disabled_no_finding(self):
        acc = _account(allow_public=False)
        scanner = _make_scanner([acc])
        findings = scanner.scan()
        no_finding(findings, title_contains="allows public blob access")

    def test_public_container_is_critical(self):
        acc = _account(allow_public=True)
        container = MagicMock()
        container.name = "data"
        container.public_access = "blob"
        scanner = _make_scanner([acc], containers_per_account={"test-sa": [container]})
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="data")


# ── HTTPS only ────────────────────────────────────────────────────────────────

class TestHTTPSOnly:
    def test_http_allowed_is_high(self):
        acc = _account(https_only=False)
        scanner = _make_scanner([acc])
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="allows HTTP traffic")

    def test_https_only_no_finding(self):
        acc = _account(https_only=True)
        scanner = _make_scanner([acc])
        findings = scanner.scan()
        no_finding(findings, title_contains="allows HTTP traffic")


# ── TLS version ───────────────────────────────────────────────────────────────

class TestTLSVersion:
    def test_tls1_0_is_medium(self):
        acc = _account(tls="TLS1_0")
        scanner = _make_scanner([acc])
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="TLS1_0")

    def test_tls1_1_is_medium(self):
        acc = _account(tls="TLS1_1")
        scanner = _make_scanner([acc])
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="TLS1_1")

    def test_tls1_2_no_finding(self):
        acc = _account(tls="TLS1_2")
        scanner = _make_scanner([acc])
        findings = scanner.scan()
        no_finding(findings, title_contains="TLS")


# ── Encryption (CMK) ──────────────────────────────────────────────────────────

class TestEncryption:
    def test_microsoft_managed_keys_is_info(self):
        acc = _account(key_source="Microsoft.Storage")
        scanner = _make_scanner([acc])
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.INFO, title_contains="Microsoft-managed encryption keys")

    def test_cmk_no_finding(self):
        acc = _account(key_source="Microsoft.Keyvault")
        scanner = _make_scanner([acc])
        findings = scanner.scan()
        no_finding(findings, title_contains="Microsoft-managed encryption keys")
