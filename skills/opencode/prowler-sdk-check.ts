
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: prowler-sdk-check
description: Creates a new Prowler security check following the SDK architecture patterns. Generates the check class, metadata JSON, and test file structure.
license: Apache 2.0
---

## When to use this skill

Use this skill when you need to create a new security check for any Prowler provider (AWS, Azure, GCP, Kubernetes, GitHub, etc.). This ensures the check follows all SDK conventions.

## Architecture Pattern

Every check MUST follow this structure:
\`\`\`
prowler/providers/{provider}/services/{service}/{check_name}/
├── __init__.py
├── {check_name}.py           # Check class implementation
└── {check_name}.metadata.json # Check metadata
\`\`\`

## Check Implementation Template

\`\`\`python
from prowler.lib.check.models import Check, CheckReport{Provider}
from prowler.providers.{provider}.services.{service}.{service}_client import {service}_client

class {check_name}(Check):
    """Ensure that {resource} meets {security_requirement}."""
    def execute(self) -> list[CheckReport{Provider}]:
        findings = []
        for resource in {service}_client.{resources}:
            report = CheckReport{Provider}(metadata=self.metadata(), resource=resource)
            # Security validation logic
            if resource.is_compliant:
                report.status = "PASS"
                report.status_extended = f"Resource {resource.name} is compliant."
            else:
                report.status = "FAIL"
                report.status_extended = f"Resource {resource.name} is NOT compliant."
            findings.append(report)
        return findings
\`\`\`

## Metadata JSON Structure

\`\`\`json
{
  "Provider": "{provider}",
  "CheckID": "{check_name}",
  "CheckTitle": "Descriptive title",
  "CheckType": ["Security Best Practices"],
  "ServiceName": "{service}",
  "SubServiceName": "",
  "ResourceIdTemplate": "{arn/id pattern}",
  "Severity": "low|medium|high|critical",
  "ResourceType": "Resource",
  "Description": "Full description of what this check verifies.",
  "Risk": "What could happen if this check fails.",
  "RelatedUrl": "https://documentation.url",
  "Remediation": {
    "Code": {
      "CLI": "command to fix",
      "NativeIaC": "",
      "Other": "",
      "Terraform": ""
    },
    "Recommendation": {
      "Text": "Step by step remediation.",
      "Url": "https://remediation.docs.url"
    }
  },
  "Categories": [],
  "DependsOn": [],
  "RelatedTo": [],
  "Notes": ""
}
\`\`\`

## Commands

\`\`\`bash
# Verify check is detected
poetry run python prowler-cli.py {provider} --list-checks | grep {check_name}

# Test the check
poetry run python prowler-cli.py {provider} --log-level ERROR --verbose --check {check_name}

# Run check tests
poetry run pytest tests/providers/{provider}/services/{service}/{check_name}/ -v
\`\`\`

## Keywords
prowler, security check, sdk, aws, azure, gcp, kubernetes, compliance, check implementation
`;

export default tool({
  description: SKILL,
  args: {
    provider: tool.schema.string().describe("Cloud provider: aws, azure, gcp, kubernetes, github, m365, oci, alibabacloud"),
    service: tool.schema.string().describe("Service name within the provider (e.g., iam, ec2, storage)"),
    check_name: tool.schema.string().describe("Name of the check following convention: {service}_{resource}_{validation}"),
  },
  async execute(args) {
    const result = await Bun.$`echo "Creating Prowler SDK check skeleton for ${args.provider}/${args.service}/${args.check_name}"`.text()
    return `
Check Creation Guide for: ${args.provider}/${args.service}/${args.check_name}

1. Create directory structure:
   mkdir -p prowler/providers/${args.provider}/services/${args.service}/${args.check_name}
   touch prowler/providers/${args.provider}/services/${args.service}/${args.check_name}/__init__.py

2. Required files to create:
   - prowler/providers/${args.provider}/services/${args.service}/${args.check_name}/${args.check_name}.py
   - prowler/providers/${args.provider}/services/${args.service}/${args.check_name}/${args.check_name}.metadata.json

3. Test file:
   - tests/providers/${args.provider}/services/${args.service}/${args.check_name}/${args.check_name}_test.py

4. Verify:
   poetry run python prowler-cli.py ${args.provider} --list-checks | grep ${args.check_name}

${result.trim()}
    `.trim()
  },
})
