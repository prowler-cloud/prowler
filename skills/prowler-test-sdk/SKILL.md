---
name: prowler-test-sdk
description: >
  Testing patterns for the Prowler SDK (Python): checks, services, fixers and providers.
  Trigger: When writing or fixing tests for the Prowler SDK (checks/services/fixers/providers under tests/), including AWS mocking with moto or botocore and MagicMock-based mocking for the other providers.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, sdk]
  auto_invoke:
    - "Writing Prowler SDK tests"
    - "Mocking AWS with moto in tests"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

> **Generic Patterns**: For base pytest patterns (fixtures, mocking, parametrize), see the `pytest` skill.
> This skill covers **Prowler-specific** conventions only. Full guide: `docs/developer-guide/unit-testing.mdx`.

## Mocking Approach by Provider

| Provider | Approach |
|----------|----------|
| AWS, API covered by moto | `@mock_aws`, create real resources with `boto3.client(...)`, instantiate the real service class |
| AWS, API not or partially covered by moto | Patch `botocore.client.BaseClient._make_api_call` (wrap responses with `mocked_api_response`), or inject a `MagicMock` service client in check tests |
| Every other provider | `MagicMock()` service client with Pydantic models from `{service}_service.py` |

**Never use moto for non-AWS providers.** For AWS, prefer moto and fall back to botocore/MagicMock only when moto lacks the API (check moto's `IMPLEMENTATION_COVERAGE.md`).

## Critical Rules

- Import the check **inside** the `mock.patch` context, otherwise the real `{service}_client` singleton is built at import time.
- Patch `prowler.providers.common.provider.Provider.get_global_provider` and the client **where the check imports it**: `prowler.providers.{provider}.services.{service}.{check_name}.{check_name}.{service}_client`.
- Prefer `mock.MagicMock()` (an instance). Older tests assign attributes on the class (`client = mock.MagicMock`); `tests/conftest.py` resets those after every test, but new tests should use instances.
- Tests run in random order (`pytest-randomly`) and in parallel (`-n auto`): no shared state between tests.
- Test file basenames must be unique across `tests/` (no `__init__.py`; the `SDK: Check Duplicate Test Names` workflow fails on duplicates). Prefix with the provider if needed: `stackit_objectstorage_service_test.py`.
- Do not create `__init__.py` files in test folders.

## AWS Check Test (moto)

```python
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_s3_bucket_object_versioning:
    @mock_aws
    def test_bucket_no_versioning(self):
        s3 = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3.create_bucket(Bucket="bucket-test")

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_object_versioning.s3_bucket_object_versioning.s3_client",
                new=S3(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.s3.s3_bucket_object_versioning.s3_bucket_object_versioning import (
                s3_bucket_object_versioning,
            )

            result = s3_bucket_object_versioning().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "S3 Bucket bucket-test has versioning disabled."
            assert result[0].resource_id == "bucket-test"
            assert result[0].region == AWS_REGION_US_EAST_1
```

`set_mocked_aws_provider()` (`tests/providers/aws/utils.py`) takes `audited_regions` (a list, never `None`), `audit_config={...}` for configurable checks, `fixer_config`, `scan_unused_services`, `expected_checks`, and more; read its signature.

## AWS: API Not Covered by moto

```python
import botocore
from unittest.mock import patch

from tests.providers.aws.utils import mocked_api_response

orig = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, api_params):
    if operation_name == "DescribeOrganizationConfiguration":
        # mocked_api_response fails the test if the dict does not match the real API output shape
        return mocked_api_response(
            "guardduty", operation_name, {"AutoEnableOrganizationMembers": "ALL", "MemberAccountLimitReached": False}
        )
    return orig(self, operation_name, api_params)


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@mock_aws
def test_...(self): ...
```

## Other Providers (MagicMock)

```python
from unittest import mock

from prowler.providers.azure.services.storage.storage_service import Account
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


def test_no_storage_accounts():
    storage_client = mock.MagicMock()
    storage_client.storage_accounts = {}
    storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        mock.patch(
            "prowler.providers.azure.services.storage.{check_name}.{check_name}.storage_client",
            new=storage_client,
        ),
    ):
        from prowler.providers.azure.services.storage.{check_name}.{check_name} import {check_name}

        assert len({check_name}().execute()) == 0
```

Set **every** attribute the check reads on the mock (e.g. Azure checks read `storage_client.subscriptions`); a missing one silently returns a `MagicMock`, or raises `AttributeError` on a bare-class mock.

## Provider Fixtures

| Provider | File | Function | Key constants |
|----------|------|----------|---------------|
| AWS | `tests/providers/aws/utils.py` | `set_mocked_aws_provider` | `AWS_REGION_US_EAST_1`, `AWS_ACCOUNT_NUMBER`, `AWS_COMMERCIAL_PARTITION` |
| Azure | `tests/providers/azure/azure_fixtures.py` | `set_mocked_azure_provider` | `AZURE_SUBSCRIPTION_ID`, `AZURE_SUBSCRIPTION_NAME`, `AZURE_SUBSCRIPTION_DISPLAY` |
| GCP | `tests/providers/gcp/gcp_fixtures.py` | `set_mocked_gcp_provider` | `GCP_PROJECT_ID`, `GCP_EU1_LOCATION` |
| Kubernetes | `tests/providers/kubernetes/kubernetes_fixtures.py` | `set_mocked_kubernetes_provider` | `KUBERNETES_CLUSTER_NAME`, `KUBERNETES_NAMESPACE` |
| M365 | `tests/providers/m365/m365_fixtures.py` | `set_mocked_m365_provider` | `TENANT_ID`, `DOMAIN` |
| GitHub | `tests/providers/github/github_fixtures.py` | `set_mocked_github_provider` | `ACCOUNT_NAME`, `ACCOUNT_ID` |
| Oracle Cloud | `tests/providers/oraclecloud/oci_fixtures.py` | `set_mocked_oraclecloud_provider` | `OCI_TENANCY_ID`, `OCI_COMPARTMENT_ID` |
| Others | `tests/providers/{provider}/{provider}_fixtures.py` | `set_mocked_{provider}_provider` | read the file |

`iac` and `image` fixtures expose sample tool outputs instead of a mocked provider.

## Test Layout

```text
tests/providers/{provider}/
├── {provider}_fixtures.py
├── {provider}_provider_test.py
└── services/{service}/
    ├── {service}_service_test.py          # service fetch logic
    └── {check_name}/
        ├── {check_name}_test.py           # check logic
        └── {check_name}_fixer_test.py     # if the check has a fixer
```

## Required Scenarios per Check

| Scenario | Expected |
|----------|----------|
| No resources | `len(result) == 0` |
| Compliant resource | `status == "PASS"` |
| Non-compliant resource | `status == "FAIL"` |
| Data could not be retrieved (if the check handles it) | `status == "MANUAL"`, single finding |
| Multiple resources | correct count, one finding per resource |

Assert `status_extended` (exact string), `resource_id`, `resource_name`/`resource_arn`, and the location field (`region`, `subscription`/`location`, `project_id`/`location`, `namespace`).

## CI Notes

- `.github/workflows/sdk-tests.yml` runs each provider's tests only when its files change. For AWS, a service's tests also run when a service it depends on changes: update the `dependents` table there (and in `unit-testing.mdx`) when a check imports another service's client.
- `tests/lib/check/check_test.py` validates all metadata files per provider (`test_{provider}_checks_metadata_is_valid`).

## Commands

```bash
uv run pytest -n auto tests/providers/{provider}/services/{service}/{check_name}/   # one check
uv run pytest -n auto tests/providers/{provider}/                                  # one provider
uv run pytest tests/path/file_test.py -k "test_name" -vv                           # one test
uv run pytest -p no:randomly tests/path/                                           # reproduce order-dependent failures
uv run pytest -n auto tests/                                                       # full SDK suite (slow)
```

## Resources

- **Templates**: [assets/](assets/) has passing tests copied from the repo: AWS with moto, Azure and GCP with MagicMock
- **Documentation**: [references/testing-docs.md](references/testing-docs.md)
