# Renaming Checks in Prowler

Sometimes it's necessary to rename a check in Prowler, whether to align with other Check IDs structure, fix a typo, or because the logic of the check has changed and requires a new name.

In all these cases, when the Check ID is changed, it's necessary to update the following files:

## Check Folder

First, you need to rename the check folder with the new check name.

**Path:** `prowler/providers/<provider>/services/<service>/<check_name>`

**Example:**
```
# Before
prowler/providers/aws/services/inspector2/inspector2_findings_exist/

# After
prowler/providers/aws/services/inspector2/inspector2_active_findings_exist/
```

After that, you need to rename the file that contains the check logic. Inside that file, you also need to rename the class name to match the new check name.

**Path:** `prowler/providers/<provider>/services/<service>/<check_name>/<check_name>.py`

**Example:**
```python
# Before
class inspector2_findings_exist(Check):
    def execute(self):
        findings = []
        # ... check logic ...

# After
class inspector2_active_findings_exist(Check):
    def execute(self):
        findings = []
        # ... check logic ...
```

Then, rename the file that contains the check metadata. Inside that file, you need to add the old check name as an alias in the `CheckAliases` field and modify the `CheckID` to the new check name.

**Path:** `prowler/providers/<provider>/services/<service>/<check_name>/<check_name>.metadata.json`

**Example:**
```json
{
  "Provider": "aws",
  "CheckID": "inspector2_active_findings_exist",
  "CheckTitle": "Check if Inspector2 active findings exist",
  "CheckAliases": [
    "inspector2_findings_exist"
  ],
  "CheckType": [],
  "ServiceName": "inspector2",
  "SubServiceName": "",
  "ResourceIdTemplate": "arn:aws:inspector2:region:account-id/detector-id",
  "Severity": "medium",
  "ResourceType": "Other",
  "Description": "This check determines if there are any active findings in your AWS account that have been detected by AWS Inspector2.",
  "Risk": "Without using AWS Inspector, you may not be aware of all the security vulnerabilities in your AWS resources.",
  "RelatedUrl": "https://docs.aws.amazon.com/inspector/latest/user/findings-understanding.html",
  "Remediation": {
    "Code": {
      "CLI": "",
      "NativeIaC": "",
      "Other": "https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/Inspector/amazon-inspector-findings.html",
      "Terraform": ""
    },
    "Recommendation": {
      "Text": "Review the active findings from Inspector2",
      "Url": "https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html"
    }
  },
  "Categories": [],
  "DependsOn": [],
  "RelatedTo": [],
  "Notes": ""
}
```

## Tests Folder

Second, you need to rename the tests folder with the new check name.

**Path:** `tests/providers/<provider>/services/<service>/<check_name>`

**Example:**
```
# Before
tests/providers/aws/services/inspector2/inspector2_findings_exist/

# After
tests/providers/aws/services/inspector2/inspector2_active_findings_exist/
```

After that, you need to rename the test file that contains all the unit tests. Inside that file, you need to rename all appearances of the old check name to the new check name.

**Path:** `tests/providers/<provider>/services/<service>/<check_name>/<check_name>_test.py`

**Example:**
```python
# Before
from prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist import (
    inspector2_findings_exist,
)

class Test_inspector2_findings_exist:
    def test_inspector2_no_findings(self):
        # ... test logic ...

    def test_inspector2_with_findings(self):
        # ... test logic ...

# After
from prowler.providers.aws.services.inspector2.inspector2_active_findings_exist.inspector2_active_findings_exist import (
    inspector2_active_findings_exist,
)

class Test_inspector2_active_findings_exist:
    def test_inspector2_no_findings(self):
        # ... test logic ...

    def test_inspector2_with_findings(self):
        # ... test logic ...
```

**Important:** You need to update all references to the old check name in the test file, including:
- Import statements at the top of the file
- Class name in the test class
- Any function calls to the check
- Any string references to the check name
- Mock patches that reference the check

**Complete example of all changes needed in test files:**
```python
# Before
from prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist import (
    inspector2_findings_exist,
)

class Test_inspector2_findings_exist:
    def test_inspector2_no_findings(self):
        # Mock setup
        with mock.patch(
            "prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist.inspector2_client",
            inspector2_client,
        ):
            check = inspector2_findings_exist()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "No active findings found" in result[0].status_extended

# After
from prowler.providers.aws.services.inspector2.inspector2_active_findings_exist.inspector2_active_findings_exist import (
    inspector2_active_findings_exist,
)

class Test_inspector2_active_findings_exist:
    def test_inspector2_no_findings(self):
        # Mock setup
        with mock.patch(
            "prowler.providers.aws.services.inspector2.inspector2_active_findings_exist.inspector2_active_findings_exist.inspector2_client",
            inspector2_client,
        ):
            check = inspector2_active_findings_exist()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "No active findings found" in result[0].status_extended
```

## Compliance Folder

Finally, it's needed to rename all the appearances of the old check name to the new check name inside any type of compliance where the check is mapped.

- `prowler/compliance/<service>/<compliance_where_the_check_is_mapped>.json`

**Example:**
```json
{
  "Framework": "CIS",
  "Version": "2.0",
  "Provider": "AWS",
  "Description": "The CIS Amazon Web Services Foundations Benchmark provides prescriptive guidance for configuring security options for a subset of Amazon Web Services.",
  "Requirements": [
    {
      "Id": "4.1",
      "Description": "Ensure a log metric filter and alarm exist for unauthorized API calls",
      "Checks": [
        "inspector2_active_findings_exist"
      ],
      "Attributes": [
        {
          "Section": "4 Logging and Monitoring",
          "Profile": "Level 1",
          "AssessmentStatus": "Automated",
          "Description": "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms."
        }
      ]
    }
  ]
}
```

Maybe the dev compliance file that contains examples of compliance could have an example of the check that you are renaming, if that is the case it's needed to modify this file too.

- `api/src/backend/api/fixtures/dev/7_dev_compliance.json`
