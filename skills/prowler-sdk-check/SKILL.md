---
name: prowler-sdk-check
description: >
  Creates Prowler security checks following SDK architecture patterns.
  Trigger: When user asks to create a new security check for any provider (AWS, Azure, GCP, K8s, GitHub, etc.)
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
---

## Check Structure

```
prowler/providers/{provider}/services/{service}/{check_name}/
├── __init__.py
├── {check_name}.py
└── {check_name}.metadata.json
```

---

## Step-by-Step Creation Process

### 1. Prerequisites

- **Verify check doesn't exist**: Search `prowler/providers/{provider}/services/{service}/`
- **Ensure provider and service exist** - create them first if not
- **Confirm service has required methods** - may need to add/modify service methods to get data

### 2. Create Check Files

```bash
mkdir -p prowler/providers/{provider}/services/{service}/{check_name}
touch prowler/providers/{provider}/services/{service}/{check_name}/__init__.py
touch prowler/providers/{provider}/services/{service}/{check_name}/{check_name}.py
touch prowler/providers/{provider}/services/{service}/{check_name}/{check_name}.metadata.json
```

### 3. Implement Check Logic

```python
from prowler.lib.check.models import Check, Check_Report_{Provider}
from prowler.providers.{provider}.services.{service}.{service}_client import {service}_client

class {check_name}(Check):
    """Ensure that {resource} meets {security_requirement}."""
    def execute(self) -> list[Check_Report_{Provider}]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for resource in {service}_client.{resources}:
            report = Check_Report_{Provider}(metadata=self.metadata(), resource=resource)
            report.status = "PASS" if resource.is_compliant else "FAIL"
            report.status_extended = f"Resource {resource.name} compliance status."
            findings.append(report)
        return findings
```

### 4. Create Metadata File

See complete schema below.

### 5. Verify Check Detection

```bash
poetry run python prowler-cli.py {provider} --list-checks | grep {check_name}
```

### 6. Run Check Locally

```bash
poetry run python prowler-cli.py {provider} --log-level ERROR --verbose --check {check_name}
```

### 7. Create Tests

See `prowler-test-sdk` skill for test patterns (PASS, FAIL, no resources, error handling).

---

## Check Naming Convention

```
{service}_{resource}_{security_control}
```

Examples:
- `ec2_instance_public_ip_disabled`
- `s3_bucket_encryption_enabled`
- `iam_user_mfa_enabled`

---

## Metadata Schema (COMPLETE)

```json
{
  "Provider": "aws",
  "CheckID": "{check_name}",
  "CheckTitle": "Human-readable title",
  "CheckType": [
    "Software and Configuration Checks/AWS Security Best Practices",
    "Software and Configuration Checks/Industry and Regulatory Standards/AWS Foundational Security Best Practices"
  ],
  "ServiceName": "{service}",
  "SubServiceName": "",
  "ResourceIdTemplate": "",
  "Severity": "low|medium|high|critical",
  "ResourceType": "AwsEc2Instance|Other",
  "ResourceGroup": "security|compute|storage|network",
  "Description": "**Bold resource name**. Detailed explanation of what this check evaluates and why it matters.",
  "Risk": "What happens if non-compliant. Explain attack vectors, data exposure risks, compliance impact.",
  "RelatedUrl": "",
  "AdditionalURLs": [
    "https://docs.aws.amazon.com/..."
  ],
  "Remediation": {
    "Code": {
      "CLI": "aws {service} {command} --option value",
      "NativeIaC": "```yaml\nResources:\n  Resource:\n    Type: AWS::{Service}::{Resource}\n    Properties:\n      Key: value  # This line fixes the issue\n```",
      "Other": "1. Console steps\n2. Step by step",
      "Terraform": "```hcl\nresource \"aws_{service}_{resource}\" \"example\" {\n  key = \"value\"  # This line fixes the issue\n}\n```"
    },
    "Recommendation": {
      "Text": "Detailed recommendation for remediation.",
      "Url": "https://hub.prowler.com/check/{check_name}"
    }
  },
  "Categories": [
    "identity-access",
    "encryption",
    "logging",
    "forensics-ready",
    "internet-exposed",
    "trust-boundaries"
  ],
  "DependsOn": [],
  "RelatedTo": [],
  "Notes": ""
}
```

### Required Fields

| Field | Description |
|-------|-------------|
| `Provider` | Provider name: aws, azure, gcp, kubernetes, github, m365 |
| `CheckID` | Must match class name and folder name |
| `CheckTitle` | Human-readable title |
| `Severity` | `low`, `medium`, `high`, `critical` |
| `ServiceName` | Service being checked |
| `Description` | What the check evaluates |
| `Risk` | Security impact of non-compliance |
| `Remediation.Code.CLI` | CLI fix command |
| `Remediation.Recommendation.Text` | How to fix |

### Severity Guidelines

| Severity | When to Use |
|----------|-------------|
| `critical` | Direct data exposure, RCE, privilege escalation |
| `high` | Significant security risk, compliance violation |
| `medium` | Defense-in-depth, best practice |
| `low` | Informational, minor hardening |

---

## Check Report Statuses

| Status | When to Use |
|--------|-------------|
| `PASS` | Resource is compliant |
| `FAIL` | Resource is non-compliant |
| `MANUAL` | Requires human verification |

---

## Common Patterns

### AWS Check with Regional Resources

```python
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client

class s3_bucket_encryption_enabled(Check):
    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            if bucket.encryption:
                report.status = "PASS"
                report.status_extended = f"S3 bucket {bucket.name} has encryption enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"S3 bucket {bucket.name} does not have encryption enabled."
            findings.append(report)
        return findings
```

### Check with Multiple Conditions

```python
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client

class ec2_instance_hardened(Check):
    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for instance in ec2_client.instances:
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)

            issues = []
            if instance.public_ip:
                issues.append("has public IP")
            if not instance.metadata_options.http_tokens == "required":
                issues.append("IMDSv2 not enforced")

            if issues:
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.id} {', '.join(issues)}."
            else:
                report.status = "PASS"
                report.status_extended = f"Instance {instance.id} is properly hardened."

            findings.append(report)
        return findings
```

---

## Commands

```bash
# Verify detection
poetry run python prowler-cli.py {provider} --list-checks | grep {check_name}

# Run check
poetry run python prowler-cli.py {provider} --log-level ERROR --verbose --check {check_name}

# Run with specific profile/credentials
poetry run python prowler-cli.py aws --profile myprofile --check {check_name}

# Run multiple checks
poetry run python prowler-cli.py {provider} --check {check1} {check2} {check3}
```

## Keywords
prowler check, security check, aws check, azure check, gcp check, kubernetes check, create check
