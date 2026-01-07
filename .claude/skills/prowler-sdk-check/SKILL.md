---
name: prowler-sdk-check
description: >
  Creates Prowler security checks following SDK architecture patterns.
  Trigger: When user asks to create a new security check for any provider (AWS, Azure, GCP, K8s, GitHub, etc.)
---

## Check Structure

```
prowler/providers/{provider}/services/{service}/{check_name}/
├── __init__.py
├── {check_name}.py
└── {check_name}.metadata.json
```

## Check Template

```python
from prowler.lib.check.models import Check, CheckReport{Provider}
from prowler.providers.{provider}.services.{service}.{service}_client import {service}_client

class {check_name}(Check):
    def execute(self) -> list[CheckReport{Provider}]:
        findings = []
        for resource in {service}_client.{resources}:
            report = CheckReport{Provider}(metadata=self.metadata(), resource=resource)
            report.status = "PASS" if resource.is_compliant else "FAIL"
            report.status_extended = f"Resource {resource.name} compliance status."
            findings.append(report)
        return findings
```

## Metadata Template

```json
{
  "Provider": "{provider}",
  "CheckID": "{check_name}",
  "CheckTitle": "Title",
  "Severity": "low|medium|high|critical",
  "Description": "What this check verifies.",
  "Risk": "What happens if check fails.",
  "Remediation": {
    "Code": { "CLI": "fix command" },
    "Recommendation": { "Text": "How to fix." }
  }
}
```

## Commands

```bash
# Verify detection
poetry run python prowler-cli.py {provider} --list-checks | grep {check_name}

# Test check
poetry run python prowler-cli.py {provider} --log-level ERROR --check {check_name}
```
