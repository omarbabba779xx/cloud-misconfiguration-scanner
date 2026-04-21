# CloudHawk 🦅

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Providers](https://img.shields.io/badge/Providers-AWS%20%7C%20Azure%20%7C%20GCP-orange)
![Tests](https://img.shields.io/badge/Tests-156%20passed-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

**CloudHawk** is a modular, multi-cloud security scanner that detects misconfigurations across **AWS**, **Azure**, and **GCP** — in parallel, with no cloud credentials hard-coded.

---

## What It Detects

| Category | AWS | Azure | GCP |
|---|---|---|---|
| **Public Storage** | S3 public ACLs, Block Public Access, encryption, versioning | Blob public access, containers, HTTPS, TLS version | GCS `allUsers` IAM, uniform access, versioning, logging |
| **IAM / Permissions** | Root access keys, stale keys, wildcard policies, password policy | Owner/Contributor at subscription scope, wildcard custom roles | Primitive roles (`owner`/`editor`), public project IAM |
| **Logging** | CloudTrail (multi-region, log validation), AWS Config recorder | Activity log alerts, diagnostic settings | Log sinks, data access audit configs |
| **MFA / 2SV** | Root MFA, per-user MFA enforcement | Conditional Access MFA policy, per-user enrollment (MS Graph) | Per-user 2-Step Verification (Workspace Admin SDK) |
| **Network Exposure** | Security groups (SSH/RDP/DB), NACLs, default VPC SG | NSG rules, direct public IPs on NICs | Firewall rules open to `0.0.0.0/0`, default VPC network |

---

## Architecture

```
cloud-misconfiguration-scanner/
├── main.py                      # CLI entry point (Click)
├── requirements.txt
├── pytest.ini
├── scanner/
│   ├── base.py                  # Finding, Severity, Category, BaseScanner
│   ├── aws/
│   │   ├── storage.py           # S3 checks
│   │   ├── iam.py               # IAM + MFA checks
│   │   ├── logging.py           # CloudTrail + Config checks
│   │   └── network.py           # Security groups + NACLs
│   ├── azure/
│   │   ├── storage.py           # Storage account checks
│   │   ├── iam.py               # RBAC checks
│   │   ├── mfa.py               # Conditional Access + per-user MFA
│   │   ├── logging.py           # Monitor + diagnostic settings
│   │   └── network.py           # NSG rules
│   └── gcp/
│       ├── storage.py           # GCS bucket checks
│       ├── iam.py               # Project IAM checks
│       ├── mfa.py               # 2SV via Workspace Admin SDK
│       ├── logging.py           # Log sinks + audit config
│       └── network.py           # Firewall rules
├── reports/
│   └── renderer.py              # Console (Rich), JSON, HTML output
└── tests/                       # 120 unit tests (no cloud credentials needed)
    ├── conftest.py
    ├── aws/
    ├── azure/
    ├── gcp/
    ├── test_renderer.py
    └── test_cli.py
```

**Execution model:** providers run in parallel, and within each provider every category scanner runs concurrently via `ThreadPoolExecutor`.

---

## Installation

```bash
git clone https://github.com/omarbabba779xx/cloudhawk.git
cd cloud-misconfiguration-scanner
pip install -r requirements.txt
```

> Install only the SDKs you need:
> ```bash
> pip install boto3                          # AWS only
> pip install azure-identity azure-mgmt-*   # Azure only
> pip install google-cloud-*               # GCP only
> ```

---

## Authentication

The scanner uses each SDK's default credential chain — no credentials are ever hard-coded.

### AWS
```bash
# Option 1 — named profile
export AWS_PROFILE=my-profile

# Option 2 — environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

# Option 3 — IAM role (EC2 / Lambda / ECS — automatic)
```

Minimum IAM permissions required:
```json
{
  "Effect": "Allow",
  "Action": [
    "s3:ListAllMyBuckets", "s3:GetBucketAcl", "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketEncryption", "s3:GetBucketVersioning",
    "iam:GenerateCredentialReport", "iam:GetCredentialReport",
    "iam:GetAccountSummary", "iam:ListUsers", "iam:ListMFADevices",
    "iam:GetLoginProfile", "iam:ListPolicies", "iam:GetPolicyVersion",
    "iam:GetAccountPasswordPolicy",
    "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
    "config:DescribeConfigurationRecorders",
    "config:DescribeConfigurationRecorderStatus",
    "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs",
    "ec2:DescribeNetworkAcls"
  ],
  "Resource": "*"
}
```

### Azure
```bash
# Option 1 — Azure CLI
az login

# Option 2 — service principal
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_TENANT_ID=...
export AZURE_SUBSCRIPTION_ID=...
```

Required roles: **Reader** at subscription scope.  
For MFA checks: **Security Reader** + Microsoft Graph `Policy.Read.All` (application permission).

### GCP
```bash
# Option 1 — application default credentials
gcloud auth application-default login

# Option 2 — service account key file
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
export GCP_PROJECT_ID=my-project
```

Required roles: `roles/viewer` + `roles/iam.securityReviewer`.  
For 2SV checks: service account with domain-wide delegation and scope `admin.directory.user.readonly`.

---

## Usage

### Scan all providers

```bash
python main.py \
  --provider all \
  --azure-subscription $AZURE_SUBSCRIPTION_ID \
  --azure-tenant $AZURE_TENANT_ID \
  --gcp-project $GCP_PROJECT_ID
```

### Scan AWS only, multiple regions

```bash
python main.py \
  --provider aws \
  --aws-region us-east-1 \
  --aws-region eu-west-1 \
  --aws-region ap-southeast-1
```

### Scan specific categories

```bash
python main.py --provider aws -c storage -c network
```

### Generate JSON + HTML reports

```bash
python main.py \
  --provider aws \
  --output all \
  --output-file results/scan-$(date +%Y%m%d)
```

### Filter by minimum severity

```bash
# Only show CRITICAL and HIGH findings
python main.py --provider aws --min-severity HIGH
```

### CI/CD integration — fail the pipeline on critical findings

```bash
python main.py --provider aws --fail-on CRITICAL
echo "Exit code: $?"   # 1 = critical findings found, 0 = clean
```

---

## CLI Reference

```
Usage: main.py [OPTIONS]

Options:
  -p, --provider [aws|azure|gcp|all]          Cloud provider to scan.
  -c, --category [storage|iam|logging|mfa|network|all]
                                              Category to scan (repeatable).
  --aws-region TEXT                           AWS region for network checks (repeatable).
  --azure-subscription TEXT                   Azure subscription ID.
  --azure-tenant TEXT                         Azure tenant ID (required for MFA checks).
  --gcp-project TEXT                          GCP project ID.
  --gcp-admin-email TEXT                      Workspace admin email for 2SV checks.
  -o, --output [console|json|html|all]        Output format.
  --output-file TEXT                          Base filename for reports (no extension).
  --min-severity [CRITICAL|HIGH|MEDIUM|LOW|INFO]
                                              Minimum severity to display.
  --fail-on [CRITICAL|HIGH|MEDIUM|LOW|NONE]   Exit code 1 if findings at this level exist.
  --workers INTEGER                           Max parallel threads per provider.
  --help                                      Show this message and exit.
```

All options can also be set via environment variables:

| Option | Environment Variable |
|---|---|
| `--azure-subscription` | `AZURE_SUBSCRIPTION_ID` |
| `--azure-tenant` | `AZURE_TENANT_ID` |
| `--gcp-project` | `GCP_PROJECT_ID` |
| `--gcp-admin-email` | `GOOGLE_ADMIN_EMAIL` |

---

## Output Formats

### Console (default)

```
Cloud Misconfiguration Scanner
Scan completed at 2025-01-15 14:32:01

CRITICAL: 3   HIGH: 7   MEDIUM: 12   LOW: 5   Total: 27

╭──────────┬──────────┬──────────────────────┬──────────────────┬──────────────────────────────────────────╮
│ Severity │ Provider │ Category             │ Resource         │ Title                                    │
├──────────┼──────────┼──────────────────────┼──────────────────┼──────────────────────────────────────────┤
│ CRITICAL │ AWS      │ Network Exposure      │ sg-0abc123       │ Security group 'open-sg' exposes SSH ... │
│ CRITICAL │ AWS      │ MFA / Authentication  │ root             │ Root account does not have MFA enabled   │
│ HIGH     │ AZURE    │ IAM Permissions       │ user-aaa         │ Principal has 'Owner' at subscription... │
╰──────────┴──────────┴──────────────────────┴──────────────────┴──────────────────────────────────────────╯
```

### JSON

```json
{
  "scan_time": "2025-01-15T14:32:01",
  "total": 27,
  "findings": [
    {
      "provider": "aws",
      "category": "Network Exposure",
      "severity": "CRITICAL",
      "resource_type": "Security Group",
      "resource_id": "sg-0abc123",
      "title": "Security group 'open-sg' exposes SSH (port 22) to the internet",
      "description": "...",
      "recommendation": "..."
    }
  ]
}
```

### HTML

A self-contained HTML report with a severity summary dashboard and a searchable findings table.

---

## Running Tests

```bash
pip install pytest
pytest
```

```
========================= 120 passed in 2.34s =========================
```

All 120 tests run without any cloud credentials — SDK calls are fully mocked.

---

## GitHub Actions Example

```yaml
name: Cloud Security Scan

on:
  schedule:
    - cron: "0 6 * * *"   # daily at 06:00 UTC
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Run scanner
        run: |
          python main.py \
            --provider aws \
            --output all \
            --output-file scan-report \
            --fail-on CRITICAL

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: scan-report
          path: |
            scan-report.json
            scan-report.html
```

---

## Severity Levels

| Level | Description |
|---|---|
| **CRITICAL** | Immediate risk of data breach or full account compromise (e.g. root without MFA, SSH open to internet) |
| **HIGH** | Significant exposure that should be remediated within 24–48 hours |
| **MEDIUM** | Security weakness that increases attack surface; remediate within 30 days |
| **LOW** | Defense-in-depth gap; low direct risk but recommended to fix |
| **INFO** | Informational — missing optional capability |

---

## License

MIT — see [LICENSE](LICENSE) for details.
