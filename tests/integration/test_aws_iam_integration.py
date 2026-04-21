"""
Integration tests for AWS IAM scanner using moto.
Creates real (simulated) IAM resources and verifies the scanner detects them.
"""
import boto3
import pytest
from moto import mock_aws
from scanner.aws.iam import IAMScanner
from scanner.base import Severity
from tests.conftest import assert_finding, no_finding


@pytest.fixture
def aws_session():
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


# ── Root MFA ──────────────────────────────────────────────────────────────────

class TestRootMFAIntegration:
    def test_root_mfa_disabled_raises_critical(self, aws_session):
        # moto returns AccountMFAEnabled=0 by default (no root MFA)
        findings = IAMScanner(aws_session).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="Root account does not have MFA")


# ── User MFA ──────────────────────────────────────────────────────────────────

class TestUserMFAIntegration:
    def test_console_user_without_mfa_raises_high(self, aws_session):
        iam = aws_session.client("iam")
        iam.create_user(UserName="alice")
        iam.create_login_profile(UserName="alice", Password="P@ssword123!")

        findings = IAMScanner(aws_session).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="alice")

    def test_programmatic_only_user_no_mfa_finding(self, aws_session):
        iam = aws_session.client("iam")
        iam.create_user(UserName="svc-account")
        # No login profile = programmatic access only

        findings = IAMScanner(aws_session).scan()
        no_finding(findings, title_contains="svc-account")

    def test_multiple_users_only_console_flagged(self, aws_session):
        iam = aws_session.client("iam")
        iam.create_user(UserName="console-user")
        iam.create_login_profile(UserName="console-user", Password="P@ssword123!")
        iam.create_user(UserName="api-user")
        # api-user has no login profile

        findings = IAMScanner(aws_session).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="console-user")
        no_finding(findings, title_contains="api-user")


# ── Password policy ───────────────────────────────────────────────────────────

class TestPasswordPolicyIntegration:
    def test_no_password_policy_raises_high(self, aws_session):
        findings = IAMScanner(aws_session).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="No IAM account password policy")

    def test_weak_password_policy_raises_medium(self, aws_session):
        iam = aws_session.client("iam")
        iam.update_account_password_policy(
            MinimumPasswordLength=6,
            RequireUppercaseCharacters=False,
            RequireLowercaseCharacters=False,
            RequireNumbers=False,
            RequireSymbols=False,
        )
        findings = IAMScanner(aws_session).scan()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="Weak IAM account password policy")

    def test_strong_password_policy_no_finding(self, aws_session):
        iam = aws_session.client("iam")
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            RequireNumbers=True,
            RequireSymbols=True,
            MaxPasswordAge=90,
            PasswordReusePrevention=24,
        )
        findings = IAMScanner(aws_session).scan()
        policy_findings = [
            f for f in findings if "password policy" in f.title.lower()
        ]
        assert not policy_findings, f"Unexpected: {[f.title for f in policy_findings]}"


# ── Overly permissive policies ────────────────────────────────────────────────

class TestPermissivePoliciesIntegration:
    def test_wildcard_policy_on_all_resources_raises_high(self, aws_session):
        import json
        iam = aws_session.client("iam")
        iam.create_policy(
            PolicyName="DangerousPolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["iam:*"],
                    "Resource": "*",
                }],
            }),
        )
        findings = IAMScanner(aws_session).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="DangerousPolicy")

    def test_scoped_policy_no_finding(self, aws_session):
        import json
        iam = aws_session.client("iam")
        iam.create_policy(
            PolicyName="ScopedPolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }],
            }),
        )
        findings = IAMScanner(aws_session).scan()
        no_finding(findings, title_contains="ScopedPolicy")
