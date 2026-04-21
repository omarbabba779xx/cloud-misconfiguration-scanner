#!/usr/bin/env python3
"""Cloud Misconfiguration Scanner — AWS | Azure | GCP"""

import sys
import click
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.base import Finding, Severity


def _safe(label: str, fn) -> list[Finding]:
    """Run fn(), return its findings, print any exception without crashing."""
    try:
        return fn()
    except Exception as exc:
        click.echo(f"[{label}] Error: {exc}", err=True)
        return []


def _run_aws(regions: list[str], categories: list[str]) -> list[Finding]:
    try:
        import boto3
    except ImportError:
        click.echo("[AWS] boto3 not installed. Run: pip install boto3", err=True)
        return []

    from scanner.aws.storage import S3Scanner
    from scanner.aws.iam import IAMScanner
    from scanner.aws.logging import LoggingScanner
    from scanner.aws.network import NetworkScanner

    session = boto3.Session()

    tasks: dict[str, callable] = {}

    if "storage" in categories:
        click.echo("[AWS] Queuing S3 storage scan...")
        tasks["AWS/S3"] = lambda: S3Scanner(session).scan()

    if "iam" in categories or "mfa" in categories:
        click.echo("[AWS] Queuing IAM + MFA scan...")
        tasks["AWS/IAM"] = lambda: IAMScanner(session).scan()

    if "logging" in categories:
        click.echo("[AWS] Queuing CloudTrail / Config scan...")
        tasks["AWS/Logging"] = lambda: LoggingScanner(session).scan()

    if "network" in categories:
        for region in regions:
            click.echo(f"[AWS] Queuing network scan for {region}...")
            r = region  # capture loop var
            tasks[f"AWS/Network/{r}"] = (
                lambda r=r: NetworkScanner(boto3.Session(region_name=r)).scan()
            )

    return _parallel(tasks)


def _run_azure(subscription_id: str, tenant_id: str, categories: list[str]) -> list[Finding]:
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        click.echo("[Azure] azure-identity not installed.", err=True)
        return []

    from scanner.azure.storage import AzureStorageScanner
    from scanner.azure.iam import AzureIAMScanner
    from scanner.azure.logging import AzureLoggingScanner
    from scanner.azure.network import AzureNetworkScanner
    from scanner.azure.mfa import AzureMFAScanner

    credential = DefaultAzureCredential()
    tasks: dict[str, callable] = {}

    if "storage" in categories:
        click.echo("[Azure] Queuing storage scan...")
        tasks["Azure/Storage"] = lambda: AzureStorageScanner(credential, subscription_id).scan()

    if "iam" in categories:
        click.echo("[Azure] Queuing IAM / RBAC scan...")
        tasks["Azure/IAM"] = lambda: AzureIAMScanner(credential, subscription_id).scan()

    if "mfa" in categories:
        click.echo("[Azure] Queuing MFA / Conditional Access scan...")
        tasks["Azure/MFA"] = lambda: AzureMFAScanner(credential, tenant_id).scan()

    if "logging" in categories:
        click.echo("[Azure] Queuing Monitor / diagnostics scan...")
        tasks["Azure/Logging"] = lambda: AzureLoggingScanner(credential, subscription_id).scan()

    if "network" in categories:
        click.echo("[Azure] Queuing NSG / network scan...")
        tasks["Azure/Network"] = lambda: AzureNetworkScanner(credential, subscription_id).scan()

    return _parallel(tasks)


def _run_gcp(project: str, admin_email: str | None, categories: list[str]) -> list[Finding]:
    try:
        from google.cloud import storage as _  # noqa: F401
    except ImportError:
        click.echo("[GCP] google-cloud-storage not installed.", err=True)
        return []

    from scanner.gcp.storage import GCSScanner
    from scanner.gcp.iam import GCPIAMScanner
    from scanner.gcp.logging import GCPLoggingScanner
    from scanner.gcp.network import GCPNetworkScanner
    from scanner.gcp.mfa import GCPMFAScanner

    tasks: dict[str, callable] = {}

    if "storage" in categories:
        click.echo("[GCP] Queuing GCS bucket scan...")
        tasks["GCP/Storage"] = lambda: GCSScanner(project).scan()

    if "iam" in categories:
        click.echo("[GCP] Queuing project IAM scan...")
        tasks["GCP/IAM"] = lambda: GCPIAMScanner(project).scan()

    if "mfa" in categories:
        click.echo("[GCP] Queuing 2SV / Workspace Admin scan...")
        tasks["GCP/MFA"] = lambda: GCPMFAScanner(project, admin_email=admin_email).scan()

    if "logging" in categories:
        click.echo("[GCP] Queuing log sinks / audit config scan...")
        tasks["GCP/Logging"] = lambda: GCPLoggingScanner(project).scan()

    if "network" in categories:
        click.echo("[GCP] Queuing firewall rules scan...")
        tasks["GCP/Network"] = lambda: GCPNetworkScanner(project).scan()

    return _parallel(tasks)


def _parallel(tasks: dict[str, callable], max_workers: int = 10) -> list[Finding]:
    """Run all tasks concurrently and merge results."""
    findings: list[Finding] = []
    if not tasks:
        return findings

    with ThreadPoolExecutor(max_workers=min(len(tasks), max_workers)) as pool:
        futures = {pool.submit(_safe, label, fn): label for label, fn in tasks.items()}
        for future in as_completed(futures):
            label = futures[future]
            result = future.result()
            click.echo(f"  [{label}] {len(result)} finding(s)")
            findings.extend(result)

    return findings


@click.command()
@click.option(
    "--provider", "-p",
    type=click.Choice(["aws", "azure", "gcp", "all"], case_sensitive=False),
    default="all", show_default=True,
    help="Cloud provider to scan.",
)
@click.option(
    "--category", "-c",
    multiple=True,
    type=click.Choice(["storage", "iam", "logging", "mfa", "network", "all"], case_sensitive=False),
    default=["all"], show_default=True,
    help="Category/categories to scan (repeatable).",
)
@click.option("--aws-region", multiple=True, default=["us-east-1"], show_default=True,
              help="AWS region(s) for network checks (repeatable).")
@click.option("--azure-subscription", default=None, envvar="AZURE_SUBSCRIPTION_ID",
              help="Azure subscription ID (or AZURE_SUBSCRIPTION_ID env var).")
@click.option("--azure-tenant", default=None, envvar="AZURE_TENANT_ID",
              help="Azure tenant ID for MFA checks (or AZURE_TENANT_ID env var).")
@click.option("--gcp-project", default=None, envvar="GCP_PROJECT_ID",
              help="GCP project ID (or GCP_PROJECT_ID env var).")
@click.option("--gcp-admin-email", default=None, envvar="GOOGLE_ADMIN_EMAIL",
              help="Google Workspace admin email for 2SV checks (or GOOGLE_ADMIN_EMAIL env var).")
@click.option("--output", "-o",
              type=click.Choice(["console", "json", "html", "all"], case_sensitive=False),
              default="console", show_default=True, help="Output format.")
@click.option("--output-file", default="report", show_default=True,
              help="Base filename for json/html reports (no extension).")
@click.option("--min-severity",
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
              default="LOW", show_default=True,
              help="Only show findings at or above this severity.")
@click.option("--fail-on",
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"], case_sensitive=False),
              default="NONE", show_default=True,
              help="Exit code 1 if any finding at this severity or above exists.")
@click.option("--workers", default=10, show_default=True,
              help="Max parallel worker threads per provider.")
def main(provider, category, aws_region, azure_subscription, azure_tenant,
         gcp_project, gcp_admin_email, output, output_file, min_severity, fail_on, workers):
    """Cloud misconfiguration scanner for AWS, Azure, and GCP.

    \b
    Detects:
      - Public storage buckets/containers
      - Over-permissive IAM policies
      - Disabled audit logs
      - Missing MFA / 2SV
      - Over-exposed network rules

    \b
    Authentication (SDK defaults):
      AWS:   AWS_PROFILE / credentials file / IAM role
      Azure: az login / AZURE_CLIENT_ID + AZURE_CLIENT_SECRET + AZURE_TENANT_ID
      GCP:   gcloud auth application-default login / GOOGLE_APPLICATION_CREDENTIALS
    """
    categories = list(category)
    if "all" in categories:
        categories = ["storage", "iam", "logging", "mfa", "network"]

    providers = ["aws", "azure", "gcp"] if provider == "all" else [provider.lower()]

    # Build top-level provider tasks (run providers in parallel too)
    provider_tasks: dict[str, callable] = {}

    if "aws" in providers:
        r = list(aws_region)
        c = categories
        provider_tasks["AWS"] = lambda r=r, c=c: _run_aws(r, c)

    if "azure" in providers:
        if not azure_subscription:
            click.echo("[Azure] --azure-subscription or AZURE_SUBSCRIPTION_ID required.", err=True)
        else:
            if "mfa" in categories and not azure_tenant:
                click.echo("[Azure] --azure-tenant or AZURE_TENANT_ID required for MFA checks.", err=True)
            sub, tid, c = azure_subscription, azure_tenant or "", categories
            provider_tasks["Azure"] = lambda sub=sub, tid=tid, c=c: _run_azure(sub, tid, c)

    if "gcp" in providers:
        if not gcp_project:
            click.echo("[GCP] --gcp-project or GCP_PROJECT_ID required.", err=True)
        else:
            if "mfa" in categories and not gcp_admin_email:
                click.echo("[GCP] --gcp-admin-email or GOOGLE_ADMIN_EMAIL recommended for 2SV.", err=True)
            proj, email, c = gcp_project, gcp_admin_email, categories
            provider_tasks["GCP"] = lambda proj=proj, email=email, c=c: _run_gcp(proj, email, c)

    click.echo(f"\nStarting scan: {len(provider_tasks)} provider(s), {len(categories)} category/ies\n")
    all_findings = _parallel(provider_tasks, max_workers=workers)

    # Severity filter
    _sev_rank = {s: i for i, s in enumerate(
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    )}
    min_rank = _sev_rank[Severity(min_severity.upper())]
    filtered = [f for f in all_findings if _sev_rank[f.severity] <= min_rank]

    from reports.renderer import print_console, save_json, save_html

    if output in ("console", "all"):
        print_console(filtered)
    if output in ("json", "all"):
        save_json(filtered, f"{output_file}.json")
    if output in ("html", "all"):
        save_html(filtered, f"{output_file}.html")

    if fail_on != "NONE":
        fail_rank = _sev_rank[Severity(fail_on.upper())]
        if any(_sev_rank[f.severity] <= fail_rank for f in filtered):
            sys.exit(1)


if __name__ == "__main__":
    main()
