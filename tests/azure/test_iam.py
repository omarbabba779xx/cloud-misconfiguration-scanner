import pytest
from unittest.mock import MagicMock
from scanner.azure.iam import AzureIAMScanner
from scanner.base import Severity
from tests.conftest import assert_finding, no_finding

_OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
_CONTRIB_ROLE = "b24988ac-6180-42a0-ab88-20f7382dd24c"
SUB = "00000000-0000-0000-0000-000000000000"


def _assignment(role_def_id, principal_id, scope=f"/subscriptions/{SUB}"):
    a = MagicMock()
    a.role_definition_id = (
        f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{role_def_id}"
    )
    a.principal_id = principal_id
    a.scope = scope
    a.id = f"/subscriptions/{SUB}/providers/.../roleAssignments/{principal_id}"
    return a


def _make_scanner(assignments, custom_roles=None):
    scanner = AzureIAMScanner.__new__(AzureIAMScanner)
    client = MagicMock()
    client.role_assignments.list_for_scope.return_value = assignments
    client.role_definitions.list.return_value = custom_roles or []
    scanner.client = client
    scanner.sub_id = SUB
    return scanner


# ── Subscription-level Owner ──────────────────────────────────────────────────

class TestSubscriptionOwner:
    def test_owner_at_sub_scope_is_critical(self):
        a = _assignment(_OWNER_ROLE, "user-aaa")
        findings = _make_scanner([a]).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="Owner")

    def test_contributor_at_sub_scope_is_high(self):
        a = _assignment(_CONTRIB_ROLE, "user-bbb")
        findings = _make_scanner([a]).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="Contributor")

    def test_owner_at_rg_scope_no_sub_finding(self):
        a = _assignment(_OWNER_ROLE, "user-ccc",
                        scope=f"/subscriptions/{SUB}/resourceGroups/my-rg")
        findings = _make_scanner([a]).scan()
        no_finding(findings, title_contains="subscription scope")

    def test_more_than_3_owners_is_medium(self):
        owners = [_assignment(_OWNER_ROLE, f"user-{i}") for i in range(4)]
        findings = _make_scanner(owners).scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="Owner assignments")


# ── Custom role wildcard ──────────────────────────────────────────────────────

class TestCustomRoles:
    def test_wildcard_action_is_high(self):
        role = MagicMock()
        role.id = "/subscriptions/.../roleDefinitions/custom-1"
        role.name = "custom-1"
        role.role_name = "MyCatchAllRole"
        perm = MagicMock()
        perm.actions = ["*"]
        role.permissions = [perm]

        scanner = _make_scanner([], custom_roles=[role])
        findings = scanner.scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="wildcard")

    def test_scoped_action_no_finding(self):
        role = MagicMock()
        role.id = "/subscriptions/.../roleDefinitions/custom-2"
        role.name = "custom-2"
        role.role_name = "ReadStorageRole"
        perm = MagicMock()
        perm.actions = ["Microsoft.Storage/storageAccounts/read"]
        role.permissions = [perm]

        scanner = _make_scanner([], custom_roles=[role])
        findings = scanner.scan()
        no_finding(findings, title_contains="wildcard")
