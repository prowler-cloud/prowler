---
name: prowler-compliance
description: >
  Creates and manages Prowler compliance frameworks.
  Trigger: When working with compliance frameworks (CIS, NIST, PCI-DSS, SOC2, GDPR).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

## When to Use

Use this skill when:
- Creating a new compliance framework for any provider
- Adding requirements to existing frameworks
- Mapping checks to compliance controls

## Compliance Framework Structure

Frameworks are JSON files in: `prowler/compliance/{provider}/{framework}.json`

```json
{
  "Framework": "CIS",
  "Name": "CIS Amazon Web Services Foundations Benchmark v2.0.0",
  "Version": "2.0",
  "Provider": "AWS",
  "Description": "The CIS Amazon Web Services Foundations Benchmark provides prescriptive guidance...",
  "Requirements": [
    {
      "Id": "1.1",
      "Name": "Requirement name",
      "Description": "Detailed description of the requirement",
      "Attributes": [
        {
          "Section": "1. Identity and Access Management",
          "Profile": "Level 1",
          "AssessmentStatus": "Automated",
          "Description": "Attribute description"
        }
      ],
      "Checks": ["check_name_1", "check_name_2"]
    }
  ]
}
```

## Supported Frameworks

**Industry standards:**
- CIS (Center for Internet Security)
- NIST 800-53, NIST CSF
- CISA

**Regulatory compliance:**
- PCI-DSS
- HIPAA
- GDPR
- FedRAMP
- SOC2

**Cloud-specific:**
- AWS Well-Architected Framework (Security Pillar)
- AWS Foundational Technical Review (FTR)
- Azure Security Benchmark
- GCP Security Best Practices

## Framework Requirement Mapping

Each requirement maps to one or more checks:

```json
{
  "Id": "2.1.1",
  "Name": "Ensure MFA is enabled for all IAM users",
  "Description": "Multi-Factor Authentication adds an extra layer of protection...",
  "Checks": [
    "iam_user_mfa_enabled",
    "iam_root_mfa_enabled",
    "iam_user_hardware_mfa_enabled"
  ]
}
```

## Best Practices

1. **Requirement IDs**: Follow the original framework numbering (e.g., "1.1", "2.3.4")
2. **Check Mapping**: Map to existing checks when possible, create new checks only if needed
3. **Completeness**: Include all framework requirements, even if no check exists (document as manual)
4. **Version Control**: Include framework version in the name and file

## Commands

```bash
# List available frameworks for a provider
poetry run python prowler-cli.py {provider} --list-compliance

# Run scan with specific compliance framework
poetry run python prowler-cli.py {provider} --compliance {framework}

# Run scan with multiple frameworks
poetry run python prowler-cli.py {provider} --compliance cis_aws_benchmark_v2 pci_dss_3.2.1

# Output compliance report
poetry run python prowler-cli.py {provider} --compliance {framework} -M csv json html
```

## Keywords
prowler compliance, cis, nist, pci-dss, soc2, gdpr, hipaa, security frameworks, audit
