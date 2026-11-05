---
name: prowler-sdk-check
description: >
  Creates and updates Prowler SDK security checks (implementation, metadata, fixers, configurable checks).
  Trigger: When creating or updating a Prowler SDK security check or its metadata.json for any provider (AWS, Azure, GCP, Kubernetes, GitHub, M365, etc.), adding a check fixer, or making a check configurable via audit_config.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, sdk]
  auto_invoke:
    - "Creating new checks"
    - "Updating existing checks and metadata"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Check Structure

```text
prowler/providers/{provider}/services/{service}/{check_name}/
├── __init__.py
├── {check_name}.py               # class {check_name}(Check)
├── {check_name}.metadata.json
└── {check_name}_fixer.py         # optional, see Fixers
```

Naming: `{service}_{resource}_{security_control}` (e.g. `s3_bucket_object_versioning`). Tests go in `tests/providers/{provider}/services/{service}/{check_name}/{check_name}_test.py` (see `prowler-test-sdk`).

## Hard Rules (enforced in code)

`Check.__init__` and `CheckMetadata` (`prowler/lib/check/models.py`) reject the check at load time if any of these fail:

| Rule | Enforced by |
|------|-------------|
| `CheckID` == class name == file name (without `.py`) | `Check.__init__` |
| `CheckID` has no `-` | `valid_check_id` |
| `ServiceName` == `CheckID.split("_")[0]` and lowercase (so the AWS Lambda service is `awslambda`) | `validate_service_name` |
| `CheckTitle` <= 150 chars and does not start with `Ensure` | `validate_check_title` |
| `Description` and `Risk` <= 400 chars each | `validate_description`, `validate_risk` |
| `CheckType` is `[]` for every provider except AWS; AWS values must be paths in `prowler/providers/aws/config/check_types.json` | `validate_check_type` |
| `RelatedUrl` is `""` (deprecated, use `AdditionalURLs`) | `validate_related_url` |
| `Remediation.Recommendation.Url` is empty or starts with `https://hub.prowler.com/` (use `https://hub.prowler.com/check/{check_id}`) | `validate_recommendation_url` |
| `Remediation.Code.CLI` is not a URL | `valid_cli_command` |
| `ResourceType` non-empty | `valid_resource_type` |
| `ResourceGroup` in `VALID_RESOURCE_GROUPS` (or `""`) | `validate_resource_group` |
| Every `Categories` item in `VALID_CATEGORIES` | `valid_category` |
| `AdditionalURLs` has no empty or duplicate items | `validate_additional_urls` |
| `Severity` in `critical`, `high`, `medium`, `low`, `informational` | `Severity` enum |

Tool-wrapper providers (`iac`, `llm`, `image`, or plug-ins with `is_external_tool_provider = True`) skip most of these.

Validate a metadata file without running a scan:

```bash
uv run python -c "import sys; from prowler.lib.check.models import CheckMetadata; CheckMetadata.parse_file(sys.argv[1]); print('OK')" prowler/providers/{provider}/services/{service}/{check_name}/{check_name}.metadata.json
```

## Check Implementation

```python
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_object_versioning(Check):
    """S3 buckets have object versioning enabled."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            if not bucket.versioning_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Cannot evaluate versioning for S3 Bucket {bucket.name}: the versioning configuration could not be retrieved. Verify that the scanning credentials are allowed to call s3:GetBucketVersioning."
            elif bucket.versioning:
                report.status = "PASS"
                report.status_extended = f"S3 Bucket {bucket.name} has versioning enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} has versioning disabled."
            findings.append(report)
        return findings
```

- Only use the service client (`{service}_client`); never call the provider SDK from a check. If data is missing, extend the service (see `prowler-provider`).
- `execute()` returns a list (empty if there are no resources), one report per audited resource.
- `status_extended` must end with a period and identify the resource.
- `resource=` accepts a dict, a Pydantic model, a dataclass or an object with `to_dict()`; anything else becomes `{}` and logs an error.
- Severity can be adjusted per finding with `report.check_metadata.Severity = "..."` when the risk depends on the scenario.
- Secret-scanning checks use a dedicated batched structure: read `docs/developer-guide/secret-scanning-checks.mdx` first.

### Report Class per Provider (`prowler/lib/check/models.py`)

| Provider | Class | Fields set from `resource` |
|----------|-------|----------------------------|
| aws | `Check_Report_AWS` | `resource_id` (`id` or `name`), `resource_arn`, `region` |
| azure | `Check_Report_Azure` | `resource_name`, `resource_id`, `location`; set `report.subscription` yourself |
| gcp | `Check_Report_GCP` | `resource_id`, `resource_name`, `project_id`, `location`; also accepts `location=`, `resource_name=`, `resource_id=`, `project_id=` kwargs |
| kubernetes | `Check_Report_Kubernetes` | `resource_id` (`uid`), `resource_name`, `namespace` |
| oraclecloud | `Check_Report_OCI` | `resource_id`, `resource_name`, `compartment_id`, `region` |
| all others | `CheckReport<Name>` (e.g. `CheckReportGithub`, `CheckReportM365`, `CheckReportStackIT`, `CheckReportMongoDBAtlas`, `CheckReportAlibabaCloud`) | grep `^class CheckReport` in `models.py` for the exact name and constructor kwargs |

## Statuses

| Status | When |
|--------|------|
| `PASS` | Resource is compliant |
| `FAIL` | An insecure condition was actually detected |
| `MANUAL` | Human verification needed, or the data could not be retrieved |

### Permission / availability errors are NOT findings

Never `FAIL` because an API call failed (missing permission or scope, API not enabled, feature not licensed). The service must expose the failure distinctly from an empty result (`None` instead of `[]`, a `*_retrieved` / `*_unavailable` flag, an `*_error` attribute or a `*_lookup_failed` set). A `404`/not-found usually means "not configured" and IS a legitimate `FAIL`; a definitively disabled API is a legitimate `FAIL` only when enabling that API is the audited control (e.g. GCP Access Approval).

When a whole dataset is missing, emit ONE account/tenant/project-level `MANUAL` finding naming the required permission, and leave `Severity` untouched:

```python
if {service}_client.{data} is None:
    report = CheckReport{Provider}(metadata=self.metadata(), resource={})
    report.resource_name = "<Tenant-level resource>"
    report.resource_id = "<stable-id>"
    report.status = "MANUAL"
    report.status_extended = "Cannot evaluate <requirement>: <data> could not be retrieved. Verify that <permission> is granted to the scanning identity."
    return [report]
```

## Metadata

Complete, validated examples live in [assets/](assets/). Writing style: `docs/developer-guide/check-metadata-guidelines.mdx`.

| Field | Rule |
|-------|------|
| `CheckTitle` | Declarative compliant state, starts with the resource, no "Check/Verify/Ensure". Singular when one report per resource ("S3 bucket has object versioning enabled") |
| `CheckType` | AWS only, e.g. `"Software and Configuration Checks/AWS Security Best Practices"`, `"Effects/Data Exposure"`, `"TTPs/Initial Access"`; partial paths allowed. `[]` elsewhere |
| `SubServiceName`, `ResourceIdTemplate` | Being deprecated: `""` |
| `ResourceType` | AWS: Security Hub type (`AwsS3Bucket`) or `Other`. Azure: Resource Graph type. GCP: Cloud Asset type (`storage.googleapis.com/Bucket`). Kubernetes: `KIND`. Providers without a standard: `NotDefined` |
| `ResourceGroup` | `compute`, `container`, `serverless`, `database`, `storage`, `network`, `IAM`, `messaging`, `security`, `monitoring`, `api_gateway`, `ai_ml`, `governance`, `collaboration`, `devops`, `analytics`. Chosen by the audited resource, not the service (EC2 security group -> `network`) |
| `Description` | What the finding means, Markdown allowed, no risk talk, no "pass/fail" words |
| `Risk` | Concrete CIA impact and attack paths, not generic "security issues" |
| `Remediation.Code.CLI` | One raw command that flips FAIL to PASS, or `""` |
| `Remediation.Code.NativeIaC` | AWS: CloudFormation YAML code block. Azure: Bicep. Minimal, comment the fixing line |
| `Remediation.Code.Terraform` | Minimal HCL code block, comment the fixing line |
| `Remediation.Code.Other` | Numbered console steps |
| `Remediation.Recommendation.Text` | Principle-based guidance (least privilege, defense in depth), <= 400 chars |
| `Categories` | Only values from `VALID_CATEGORIES` (e.g. `encryption`, `internet-exposed`, `logging`, `secrets`, `resilience`, `threat-detection`, `trust-boundaries`, `vulnerabilities`, `identity-access`, `forensics-ready`, `privilege-escalation`, `gen-ai`, `ci-cd`). A new category needs a validator change plus a docs update |
| `DependsOn`, `RelatedTo` | Lists of CheckIDs, usually `[]` |

## Configurable Checks

```python
max_rules = ec2_client.audit_config.get("max_security_group_rules", 50)  # always pass a default
```

Adding a new variable requires ALL of:

1. Default value under the provider key in `prowler/config/config.yaml`.
2. Typed `Optional[...] = None` field in `prowler/config/schema/{provider}.py` (providers are registered in `prowler/config/schema/registry.py`). Values that fail validation are dropped with a warning; misspelled keys pass through silently.
3. `tests/config/fixtures/config.yaml` if tests depend on it.
4. Docs: `docs/user-guide/cli/tutorials/configuration_file.mdx`.

In tests pass the value with `set_mocked_aws_provider(audit_config={...})` (or the provider fixture equivalent).

## Fixers

- File `{check_name}_fixer.py` next to the check with a module-level `def fixer(...) -> bool` (True on success; log and return False on error). Docstring lists the permissions needed.
- `run_fixer` (`prowler/lib/check/check.py`) picks the arguments by parameter name: `resource_id` + `region`, `region` only, `resource_arn`, or `resource_id`.
- Fixer settings come from `prowler/config/fixer_config.yaml` (override with `--fixer-config`) through `{service}_client.fixer_config`.
- The `--fixer` flag is only registered for AWS (`prowler/providers/aws/lib/arguments/arguments.py`); nearly all fixers are AWS, one is M365.
- Test it in `{check_name}_fixer_test.py`, patching `...{check_name}.{check_name}_fixer.{service}_client`.

## External Checks (plug-ins)

Checks can ship in another package through the entry-point group `prowler.checks.{provider}`; the value is the module path `pkg.services.{service}.{check}.{check}` (same layout as built-ins). A built-in check wins on CheckID collision (`prowler/lib/check/check.py`, `prowler/lib/check/utils.py`). For a quick local custom check without packaging use `--checks-folder` / `-x`.

## Commands

```bash
# Verify detection
uv run python prowler-cli.py {provider} --list-checks | grep {check_name}

# Run one or more checks
uv run python prowler-cli.py {provider} --log-level ERROR --verbose --check {check_name} [{check2} ...]

# AWS profile, fixers
uv run python prowler-cli.py aws --profile myprofile --check {check_name} --fixer
uv run python prowler-cli.py aws --list-fixers

# Metadata validation for a whole provider (test exists for aws, azure, gcp, kubernetes, github, m365, ...)
uv run pytest tests/lib/check/check_test.py -k "{provider}_checks_metadata_is_valid"

# Check tests
uv run pytest -n auto tests/providers/{provider}/services/{service}/{check_name}/
```

## Before Opening the PR

- [ ] Metadata validates (command above) and the Hub URL is `https://hub.prowler.com/check/{check_name}`
- [ ] Tests cover PASS, FAIL, no resources and, if applicable, MANUAL (`prowler-test-sdk`)
- [ ] AWS: if the check imports another service's client, update the `dependents` table in `.github/workflows/sdk-tests.yml` and in `docs/developer-guide/unit-testing.mdx`
- [ ] Changelog fragment in `prowler/changelog.d/` (`prowler-changelog` skill), not a direct `CHANGELOG.md` edit
- [ ] Compliance mapping if the check covers a framework requirement (`prowler-compliance` skill)

## Resources

- **Templates**: [assets/](assets/) has current, validated check + metadata pairs for AWS, Azure and GCP
- **Documentation**: [references/metadata-docs.md](references/metadata-docs.md)
