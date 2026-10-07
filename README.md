# CloudSec Lite 

A lightweight Python security scanner that detects common cloud misconfigurations in Terraform files.

The project is intentionally dependency-light and easy to understand. It demonstrates practical security automation, Python scripting, Infrastructure-as-Code analysis, testing, and CI/CD.

## What it detects

| Rule | Misconfiguration | Severity |
|---|---|---|
| AWS-S3-001 | Public S3 ACL | Critical |
| AWS-SG-001 | SSH exposed to `0.0.0.0/0` | High |
| AWS-SG-002 | RDP exposed to `0.0.0.0/0` | High |
| AWS-IAM-001 | Wildcard IAM actions | Critical |
| AWS-RDS-001 | Publicly accessible RDS | High |
| AWS-EBS-001 | EBS encryption disabled | Medium |

## Quick start

Requires Python 3.10+.

```bash
git clone <your-repository-url>
cd cloudsec-lite

python scanner.py examples/insecure.tf
```

JSON output:

```bash
python scanner.py examples/insecure.tf --json
```

Fail a CI pipeline when a high-severity issue is detected:

```bash
python scanner.py . --fail-on HIGH
```

## Example output

```text
CloudSec Lite found 5 issue(s)
========================================================================
[CRITICAL] AWS-S3-001 — S3 bucket allows public-read ACL
[HIGH] AWS-SG-001 — Security group exposes SSH to the internet
[HIGH] AWS-RDS-001 — RDS instance is publicly accessible
[MEDIUM] AWS-EBS-001 — EBS encryption explicitly disabled
[CRITICAL] AWS-IAM-001 — IAM policy grants wildcard actions

Risk score: 37/100
```

## Run tests

```bash
python -m pip install -r requirements-dev.txt
pytest -q
```

## Why this project exists

Cloud configuration mistakes are a common security risk. CloudSec Lite explores how simple automated checks can identify risky Infrastructure-as-Code patterns before infrastructure is deployed.

This is an educational static-analysis project, not a replacement for production tools such as Checkov, tfsec, or cloud-provider security services.

## Project structure

```text
cloudsec-lite/
├── scanner.py
├── rules.py
├── examples/
│   ├── insecure.tf
│   └── secure.tf
├── tests/
│   └── test_scanner.py
├── .github/
│   └── workflows/
│       └── test.yml
├── requirements-dev.txt
├── .gitignore
├── LICENSE
└── README.md
```

## Next improvements

- Parse Terraform HCL rather than relying only on pattern matching
- Add Azure and Google Cloud rules
- Export SARIF for GitHub Code Scanning
- Add HTML reports
- Add configuration suppression rules
- Package as a CLI with `pipx`

## Skills demonstrated

Python · Cloud Security · AWS · Terraform · Static Analysis · CI/CD · GitHub Actions · Automated Testing
