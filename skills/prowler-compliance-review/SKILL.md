---
name: prowler-compliance-review
description: >
  Reviews Pull Requests that add or modify compliance frameworks.
  Trigger: When reviewing PRs with compliance framework changes, CIS/NIST/PCI-DSS additions, or compliance JSON files.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, sdk]
  auto_invoke: "Reviewing compliance framework PRs"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## When to Use

- Reviewing PRs that add new compliance frameworks
- Reviewing PRs that modify existing compliance frameworks
- Validating compliance framework JSON structure before merge

---

## Review Checklist (Critical)

| Check | Command/Method | Pass Criteria |
|-------|----------------|---------------|
| JSON Valid | `python3 -m json.tool file.json` | No syntax errors |
| All Checks Exist | Run validation script | 0 missing checks |
| No Duplicate IDs | Run validation script | 0 duplicate requirement IDs |
| CHANGELOG Entry | Manual review | Present under correct version |
| Dashboard File | Compare with existing | Follows established pattern |
| Framework Metadata | Manual review | All required fields populated |

---

## Commands

```bash
# 1. Validate JSON syntax
python3 -m json.tool prowler/compliance/{provider}/{framework}.json > /dev/null \
  && echo "Valid JSON" || echo "INVALID JSON"

# 2. Run full validation script
python3 skills/prowler-compliance-review/assets/validate_compliance.py \
  prowler/compliance/{provider}/{framework}.json

# 3. Compare dashboard with existing (find similar framework)
diff dashboard/compliance/{new_framework}.py \
     dashboard/compliance/{existing_framework}.py
```

---

## Decision Tree

```
JSON Valid?
├── No → FAIL: Fix JSON syntax errors
└── Yes ↓
    All Checks Exist in Codebase?
    ├── Missing checks → FAIL: Add missing checks or remove from framework
    └── All exist ↓
        Duplicate Requirement IDs?
        ├── Yes → FAIL: Fix duplicate IDs
        └── No ↓
            CHANGELOG Entry Present?
            ├── No → REQUEST CHANGES: Add CHANGELOG entry
            └── Yes ↓
                Dashboard File Follows Pattern?
                ├── No → REQUEST CHANGES: Fix dashboard pattern
                └── Yes ↓
                    Framework Metadata Complete?
                    ├── No → REQUEST CHANGES: Add missing metadata
                    └── Yes → APPROVE
```

---

## Framework Structure Reference

Compliance frameworks are JSON files in: `prowler/compliance/{provider}/{framework}.json`

```json
{
  "Framework": "CIS",
  "Name": "CIS Provider Benchmark vX.Y.Z",
  "Version": "X.Y",
  "Provider": "AWS|Azure|GCP|...",
  "Description": "Framework description...",
  "Requirements": [
    {
      "Id": "1.1",
      "Description": "Requirement description",
      "Checks": ["check_name_1", "check_name_2"],
      "Attributes": [
        {
          "Section": "1 Section Name",
          "SubSection": "1.1 Subsection (optional)",
          "Profile": "Level 1|Level 2",
          "AssessmentStatus": "Automated|Manual",
          "Description": "...",
          "RationaleStatement": "...",
          "ImpactStatement": "...",
          "RemediationProcedure": "...",
          "AuditProcedure": "...",
          "AdditionalInformation": "...",
          "References": "...",
          "DefaultValue": "..."
        }
      ]
    }
  ]
}
```

---

## Common Issues

| Issue | How to Detect | Resolution |
|-------|---------------|------------|
| Missing checks | Validation script reports missing | Add check implementation or remove from Checks array |
| Duplicate IDs | Validation script reports duplicates | Ensure each requirement has unique ID |
| Empty Checks for Automated | AssessmentStatus is Automated but Checks is empty | Add checks or change to Manual |
| Wrong file location | Framework not in `prowler/compliance/{provider}/` | Move to correct directory |
| Missing dashboard file | No corresponding `dashboard/compliance/{framework}.py` | Create dashboard file following pattern |
| CHANGELOG missing | Not under correct version section | Add entry to prowler/CHANGELOG.md |

---

## Dashboard File Pattern

Dashboard files must be in `dashboard/compliance/` and follow this exact pattern:

```python
import warnings

from dashboard.common_methods import get_section_containers_cis

warnings.filterwarnings("ignore")


def get_table(data):

    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_DESCRIPTION",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ].copy()

    return get_section_containers_cis(
        aux, "REQUIREMENTS_ID", "REQUIREMENTS_ATTRIBUTES_SECTION"
    )
```

---

## Testing the Compliance Framework

After validation passes, test the framework with Prowler:

```bash
# Verify framework is detected
poetry run python prowler-cli.py {provider} --list-compliance | grep {framework}

# Run a quick test with a single check from the framework
poetry run python prowler-cli.py {provider} --compliance {framework} --check {check_name}

# Run full compliance scan (dry-run with limited checks)
poetry run python prowler-cli.py {provider} --compliance {framework} --checks-limit 5

# Generate compliance report in multiple formats
poetry run python prowler-cli.py {provider} --compliance {framework} -M csv json html
```

---

## Resources

- **Validation Script**: See [assets/validate_compliance.py](assets/validate_compliance.py)
- **Related Skills**: See [prowler-compliance](../prowler-compliance/SKILL.md) for creating frameworks
- **Documentation**: See [references/review-checklist.md](references/review-checklist.md)
