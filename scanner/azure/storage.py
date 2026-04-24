import sys
from azure.mgmt.storage import StorageManagementClient
from azure.core.exceptions import HttpResponseError
from scanner.base import BaseScanner, Category, Finding, Severity


class AzureStorageScanner(BaseScanner):
    provider = "azure"

    def __init__(self, credential, subscription_id: str):
        self.client = StorageManagementClient(credential, subscription_id)
        self.sub_id = subscription_id

    def scan(self) -> list[Finding]:
        findings = []
        try:
            for account in self.client.storage_accounts.list():
                findings += self._check_public_access(account)
                findings += self._check_https_only(account)
                findings += self._check_min_tls(account)
                findings += self._check_encryption(account)
        except HttpResponseError as e:
            print(f"[Azure/Storage] Error: {e}", file=sys.stderr)
        return findings

    def _check_public_access(self, account) -> list[Finding]:
        findings = []
        name = account.name
        rg = account.id.split("/")[4]
        if account.allow_blob_public_access:
            findings.append(Finding(
                provider="azure",
                category=Category.PUBLIC_STORAGE,
                severity=Severity.CRITICAL,
                resource_type="Azure Storage Account",
                resource_id=account.id,
                title=f"Storage account '{name}' allows public blob access",
                description=(
                    "AllowBlobPublicAccess is enabled. Any container with anonymous read "
                    "access exposes data to the internet."
                ),
                recommendation=(
                    "Set allowBlobPublicAccess to false on the storage account. "
                    "Access blobs via SAS tokens or Azure AD instead."
                ),
                region=account.location,
            ))

        # Check for containers with public access
        try:
            for container in self.client.blob_containers.list(rg, name):
                access = str(getattr(container, "public_access", "None") or "None")
                if access.lower() not in ("none", "null", ""):
                    findings.append(Finding(
                        provider="azure",
                        category=Category.PUBLIC_STORAGE,
                        severity=Severity.CRITICAL,
                        resource_type="Azure Blob Container",
                        resource_id=f"{account.id}/blobServices/default/containers/{container.name}",
                        title=f"Container '{container.name}' in '{name}' has public access level '{access}'",
                        description=(
                            f"The container's public access is set to '{access}', "
                            "exposing blobs anonymously."
                        ),
                        recommendation=(
                            "Set container access level to Private and use SAS tokens for sharing."
                        ),
                        region=account.location,
                    ))
        except HttpResponseError:
            pass
        return findings

    def _check_https_only(self, account) -> list[Finding]:
        if not account.enable_https_traffic_only:
            return [Finding(
                provider="azure",
                category=Category.PUBLIC_STORAGE,
                severity=Severity.HIGH,
                resource_type="Azure Storage Account",
                resource_id=account.id,
                title=f"Storage account '{account.name}' allows HTTP traffic",
                description="enableHttpsTrafficOnly is false; data can be transmitted unencrypted.",
                recommendation="Enable 'Secure transfer required' on the storage account.",
                region=account.location,
            )]
        return []

    def _check_min_tls(self, account) -> list[Finding]:
        tls = str(getattr(account, "minimum_tls_version", "TLS1_0") or "TLS1_0")
        if tls in ("TLS1_0", "TLS1_1"):
            return [Finding(
                provider="azure",
                category=Category.PUBLIC_STORAGE,
                severity=Severity.MEDIUM,
                resource_type="Azure Storage Account",
                resource_id=account.id,
                title=f"Storage account '{account.name}' uses outdated TLS version ({tls})",
                description=f"Minimum TLS version is {tls}, which has known vulnerabilities.",
                recommendation="Set minimum TLS version to TLS1_2 or higher.",
                region=account.location,
            )]
        return []

    def _check_encryption(self, account) -> list[Finding]:
        enc = account.encryption
        if enc and enc.key_source == "Microsoft.Storage":
            return [Finding(
                provider="azure",
                category=Category.PUBLIC_STORAGE,
                severity=Severity.INFO,
                resource_type="Azure Storage Account",
                resource_id=account.id,
                title=f"Storage account '{account.name}' uses Microsoft-managed encryption keys",
                description=(
                    "Data is encrypted but key management is handled by Microsoft. "
                    "Customer-managed keys provide stronger control for sensitive workloads."
                ),
                recommendation=(
                    "Consider using Customer-Managed Keys (CMK) with Azure Key Vault for "
                    "sensitive workloads requiring stricter key control."
                ),
                region=account.location,
            )]
        return []
