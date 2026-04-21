import json
import boto3
from botocore.exceptions import ClientError
from scanner.base import BaseScanner, Category, Finding, Severity


_DANGEROUS_ACTIONS = {
    "*",
    "iam:*",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "sts:AssumeRole",
    "s3:*",
    "ec2:*",
    "lambda:*",
}


class IAMScanner(BaseScanner):
    provider = "aws"

    def __init__(self, session: boto3.Session):
        self.iam = session.client("iam")

    def scan(self) -> list[Finding]:
        findings = []
        findings += self._check_root_access_keys()
        findings += self._check_mfa_on_root()
        findings += self._check_users_without_mfa()
        findings += self._check_unused_credentials()
        findings += self._check_overly_permissive_policies()
        findings += self._check_password_policy()
        return findings

    def _check_root_access_keys(self) -> list[Finding]:
        findings = []
        try:
            report = self._get_credential_report()
            for row in report:
                if row.get("user") == "<root_account>":
                    ak1 = row.get("access_key_1_active", "false")
                    ak2 = row.get("access_key_2_active", "false")
                    if ak1 == "true" or ak2 == "true":
                        findings.append(Finding(
                            provider="aws",
                            category=Category.IAM_PERMISSIONS,
                            severity=Severity.CRITICAL,
                            resource_type="IAM Root Account",
                            resource_id="root",
                            title="Root account has active access keys",
                            description=(
                                "The root account has active programmatic access keys. "
                                "Root keys have unrestricted access and cannot be restricted by policies."
                            ),
                            recommendation=(
                                "Delete root account access keys immediately. "
                                "Use IAM users/roles with least-privilege for programmatic access."
                            ),
                        ))
        except ClientError:
            pass
        return findings

    def _check_mfa_on_root(self) -> list[Finding]:
        findings = []
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountMFAEnabled", 0) == 0:
                findings.append(Finding(
                    provider="aws",
                    category=Category.MFA,
                    severity=Severity.CRITICAL,
                    resource_type="IAM Root Account",
                    resource_id="root",
                    title="Root account does not have MFA enabled",
                    description=(
                        "The root account is not protected by MFA. "
                        "A compromised root password gives full, unrestricted access."
                    ),
                    recommendation=(
                        "Enable a hardware MFA device or virtual MFA on the root account immediately."
                    ),
                ))
        except ClientError:
            pass
        return findings

    def _check_users_without_mfa(self) -> list[Finding]:
        findings = []
        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    uname = user["UserName"]
                    mfa_devices = self.iam.list_mfa_devices(UserName=uname)["MFADevices"]
                    if not mfa_devices:
                        # Only flag console users (those with a login profile)
                        try:
                            self.iam.get_login_profile(UserName=uname)
                            has_console = True
                        except ClientError:
                            has_console = False
                        if has_console:
                            findings.append(Finding(
                                provider="aws",
                                category=Category.MFA,
                                severity=Severity.HIGH,
                                resource_type="IAM User",
                                resource_id=uname,
                                title=f"IAM user '{uname}' has console access without MFA",
                                description=(
                                    f"User '{uname}' can log into the AWS console but has no MFA device registered."
                                ),
                                recommendation=(
                                    "Enforce MFA via an IAM policy that denies all actions unless "
                                    "aws:MultiFactorAuthPresent is true."
                                ),
                            ))
        except ClientError:
            pass
        return findings

    def _check_unused_credentials(self) -> list[Finding]:
        import datetime
        findings = []
        try:
            report = self._get_credential_report()
            cutoff = datetime.timedelta(days=90)
            now = datetime.datetime.now(datetime.timezone.utc)
            for row in report:
                user = row.get("user", "")
                if user == "<root_account>":
                    continue
                for key_n in ("1", "2"):
                    active = row.get(f"access_key_{key_n}_active", "false") == "true"
                    last_used = row.get(f"access_key_{key_n}_last_used_date", "N/A")
                    if active and last_used not in ("N/A", "no_information"):
                        try:
                            lu_dt = datetime.datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                            if now - lu_dt > cutoff:
                                findings.append(Finding(
                                    provider="aws",
                                    category=Category.IAM_PERMISSIONS,
                                    severity=Severity.MEDIUM,
                                    resource_type="IAM Access Key",
                                    resource_id=f"{user}/key{key_n}",
                                    title=f"Stale access key for user '{user}'",
                                    description=(
                                        f"Access key {key_n} for '{user}' has not been used in over 90 days "
                                        f"(last used: {last_used[:10]})."
                                    ),
                                    recommendation=(
                                        "Rotate or deactivate unused access keys. "
                                        "Enforce key rotation via AWS Config rule access-keys-rotated."
                                    ),
                                    extra={"last_used": last_used},
                                ))
                        except ValueError:
                            pass
        except ClientError:
            pass
        return findings

    def _check_overly_permissive_policies(self) -> list[Finding]:
        findings = []
        try:
            paginator = self.iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    pid = policy["PolicyId"]
                    pname = policy["PolicyName"]
                    parn = policy["Arn"]
                    version_id = policy["DefaultVersionId"]
                    try:
                        doc = self.iam.get_policy_version(
                            PolicyArn=parn, VersionId=version_id
                        )["PolicyVersion"]["Document"]
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        for stmt in doc.get("Statement", []):
                            if stmt.get("Effect") != "Allow":
                                continue
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            resources = stmt.get("Resource", [])
                            if isinstance(resources, str):
                                resources = [resources]
                            dangerous = [a for a in actions if a in _DANGEROUS_ACTIONS]
                            if dangerous and "*" in resources:
                                findings.append(Finding(
                                    provider="aws",
                                    category=Category.IAM_PERMISSIONS,
                                    severity=Severity.HIGH,
                                    resource_type="IAM Policy",
                                    resource_id=parn,
                                    title=f"Policy '{pname}' grants broad permissions on all resources",
                                    description=(
                                        f"The policy allows {dangerous} on '*'. "
                                        "This violates the principle of least privilege."
                                    ),
                                    recommendation=(
                                        "Scope actions to specific resources and apply conditions "
                                        "such as aws:RequestedRegion or aws:SourceVpc."
                                    ),
                                    extra={"dangerous_actions": dangerous},
                                ))
                    except ClientError:
                        pass
        except ClientError:
            pass
        return findings

    def _check_password_policy(self) -> list[Finding]:
        findings = []
        try:
            policy = self.iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append("minimum length < 14")
            if not policy.get("RequireUppercaseCharacters"):
                issues.append("no uppercase requirement")
            if not policy.get("RequireLowercaseCharacters"):
                issues.append("no lowercase requirement")
            if not policy.get("RequireNumbers"):
                issues.append("no number requirement")
            if not policy.get("RequireSymbols"):
                issues.append("no symbol requirement")
            if not policy.get("ExpirePasswords"):
                issues.append("passwords never expire")
            if not policy.get("PasswordReusePrevention"):
                issues.append("no password reuse prevention")
            if issues:
                findings.append(Finding(
                    provider="aws",
                    category=Category.IAM_PERMISSIONS,
                    severity=Severity.MEDIUM,
                    resource_type="IAM Password Policy",
                    resource_id="account",
                    title="Weak IAM account password policy",
                    description=f"Password policy issues: {'; '.join(issues)}.",
                    recommendation=(
                        "Set minimum length ≥14, require uppercase/lowercase/numbers/symbols, "
                        "enable expiry (≤90 days), and prevent reuse of last 24 passwords."
                    ),
                    extra={"issues": issues},
                ))
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                findings.append(Finding(
                    provider="aws",
                    category=Category.IAM_PERMISSIONS,
                    severity=Severity.HIGH,
                    resource_type="IAM Password Policy",
                    resource_id="account",
                    title="No IAM account password policy is configured",
                    description="AWS is using its default (weak) password policy.",
                    recommendation="Configure a strong custom password policy for the account.",
                ))
        return findings

    def _get_credential_report(self) -> list[dict]:
        import csv
        import io
        import time
        self.iam.generate_credential_report()
        for _ in range(10):
            resp = self.iam.get_credential_report()
            if resp.get("ReportFormat") == "text/csv":
                content = resp["Content"].decode("utf-8")
                reader = csv.DictReader(io.StringIO(content))
                return list(reader)
            time.sleep(2)
        return []
