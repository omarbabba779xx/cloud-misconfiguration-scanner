import csv
import io
import pytest
from unittest.mock import MagicMock, patch, call
from botocore.exceptions import ClientError
from scanner.aws.iam import IAMScanner
from scanner.base import Severity, Category
from tests.conftest import assert_finding, no_finding


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


def _make_scanner(iam_mock):
    session = MagicMock()
    session.client.return_value = iam_mock
    return IAMScanner(session)


def _csv_report(**row_overrides) -> bytes:
    """Build a minimal credential report CSV."""
    defaults = {
        "user": "testuser",
        "arn": "arn:aws:iam::123456789012:user/testuser",
        "user_creation_time": "2020-01-01T00:00:00+00:00",
        "password_enabled": "true",
        "password_last_used": "2020-01-01T00:00:00+00:00",
        "password_last_changed": "2020-01-01T00:00:00+00:00",
        "password_next_rotation": "N/A",
        "mfa_active": "false",
        "access_key_1_active": "false",
        "access_key_1_last_rotated": "N/A",
        "access_key_1_last_used_date": "N/A",
        "access_key_1_last_used_region": "N/A",
        "access_key_1_last_used_service": "N/A",
        "access_key_2_active": "false",
        "access_key_2_last_rotated": "N/A",
        "access_key_2_last_used_date": "N/A",
        "access_key_2_last_used_region": "N/A",
        "access_key_2_last_used_service": "N/A",
        "cert_1_active": "false",
        "cert_2_active": "false",
    }
    row = {**defaults, **row_overrides}
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(row.keys()))
    writer.writeheader()
    writer.writerow(row)
    return buf.getvalue().encode()


# ── Root access keys ──────────────────────────────────────────────────────────

class TestRootAccessKeys:
    def test_active_root_key_is_critical(self):
        iam = MagicMock()
        iam.generate_credential_report.return_value = {}
        iam.get_credential_report.return_value = {
            "ReportFormat": "text/csv",
            "Content": _csv_report(user="<root_account>", access_key_1_active="true"),
        }
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_paginator.return_value.paginate.return_value = []
        iam.get_account_password_policy.side_effect = _client_error("NoSuchEntity")

        findings = _make_scanner(iam).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="Root account has active access keys")

    def test_no_root_key_no_finding(self):
        iam = MagicMock()
        iam.generate_credential_report.return_value = {}
        iam.get_credential_report.return_value = {
            "ReportFormat": "text/csv",
            "Content": _csv_report(user="<root_account>", access_key_1_active="false"),
        }
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_paginator.return_value.paginate.return_value = []
        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "ExpirePasswords": True,
                "PreventPasswordReuse": True,
            }
        }
        findings = _make_scanner(iam).scan()
        no_finding(findings, title_contains="Root account has active access keys")


# ── Root MFA ─────────────────────────────────────────────────────────────────

class TestRootMFA:
    def test_root_mfa_disabled_is_critical(self):
        iam = MagicMock()
        iam.generate_credential_report.return_value = {}
        iam.get_credential_report.return_value = {
            "ReportFormat": "text/csv",
            "Content": _csv_report(user="<root_account>"),
        }
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
        iam.get_paginator.return_value.paginate.return_value = []
        iam.get_account_password_policy.side_effect = _client_error("NoSuchEntity")

        findings = _make_scanner(iam).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="Root account does not have MFA")

    def test_root_mfa_enabled_no_finding(self):
        iam = MagicMock()
        iam.generate_credential_report.return_value = {}
        iam.get_credential_report.return_value = {
            "ReportFormat": "text/csv",
            "Content": _csv_report(user="<root_account>"),
        }
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_paginator.return_value.paginate.return_value = []
        iam.get_account_password_policy.side_effect = _client_error("NoSuchEntity")

        findings = _make_scanner(iam).scan()
        no_finding(findings, title_contains="Root account does not have MFA")


# ── User MFA ──────────────────────────────────────────────────────────────────

class TestUserMFA:
    def _iam_with_user(self, username: str, has_mfa: bool, has_console: bool):
        iam = MagicMock()
        iam.generate_credential_report.return_value = {}
        iam.get_credential_report.return_value = {
            "ReportFormat": "text/csv",
            "Content": _csv_report(user="<root_account>"),
        }
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_account_password_policy.side_effect = _client_error("NoSuchEntity")

        # Return different pages depending on the paginator type
        users_page = MagicMock()
        users_page.__iter__ = lambda self: iter([{"Users": [{"UserName": username}]}])
        policies_page = MagicMock()
        policies_page.__iter__ = lambda self: iter([{"Policies": []}])

        def _paginator(name):
            pag = MagicMock()
            if name == "list_users":
                pag.paginate.return_value = users_page
            else:
                pag.paginate.return_value = policies_page
            return pag

        iam.get_paginator.side_effect = _paginator

        iam.list_mfa_devices.return_value = {
            "MFADevices": [{"SerialNumber": "arn:..."}] if has_mfa else []
        }
        if has_console:
            iam.get_login_profile.return_value = {"LoginProfile": {"UserName": username}}
        else:
            iam.get_login_profile.side_effect = _client_error("NoSuchEntity")

        return iam

    def test_console_user_without_mfa_is_high(self):
        iam = self._iam_with_user("alice", has_mfa=False, has_console=True)
        findings = _make_scanner(iam).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="alice")

    def test_console_user_with_mfa_no_finding(self):
        iam = self._iam_with_user("bob", has_mfa=True, has_console=True)
        findings = _make_scanner(iam).scan()
        no_finding(findings, title_contains="bob")

    def test_no_console_user_no_mfa_finding(self):
        iam = self._iam_with_user("svc-account", has_mfa=False, has_console=False)
        findings = _make_scanner(iam).scan()
        no_finding(findings, title_contains="svc-account")


# ── Stale access keys ─────────────────────────────────────────────────────────

class TestStaleAccessKeys:
    def test_key_unused_90_days_is_medium(self):
        iam = MagicMock()
        iam.generate_credential_report.return_value = {}
        iam.get_credential_report.return_value = {
            "ReportFormat": "text/csv",
            "Content": _csv_report(
                user="stale-user",
                access_key_1_active="true",
                access_key_1_last_used_date="2020-01-01T00:00:00+00:00",
            ),
        }
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_paginator.return_value.paginate.return_value = []
        iam.get_account_password_policy.side_effect = _client_error("NoSuchEntity")

        findings = _make_scanner(iam).scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="stale-user")


# ── Password policy ───────────────────────────────────────────────────────────

class TestPasswordPolicy:
    def test_no_policy_is_high(self):
        iam = MagicMock()
        iam.generate_credential_report.return_value = {}
        iam.get_credential_report.return_value = {
            "ReportFormat": "text/csv",
            "Content": _csv_report(user="<root_account>"),
        }
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_paginator.return_value.paginate.return_value = []
        iam.get_account_password_policy.side_effect = _client_error("NoSuchEntity")

        findings = _make_scanner(iam).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="No IAM account password policy")

    def test_weak_policy_is_medium(self):
        iam = MagicMock()
        iam.generate_credential_report.return_value = {}
        iam.get_credential_report.return_value = {
            "ReportFormat": "text/csv",
            "Content": _csv_report(user="<root_account>"),
        }
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_paginator.return_value.paginate.return_value = []
        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 8,   # too short
                "RequireUppercaseCharacters": False,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
                "ExpirePasswords": False,
                "PreventPasswordReuse": False,
            }
        }
        findings = _make_scanner(iam).scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="Weak IAM account password policy")
