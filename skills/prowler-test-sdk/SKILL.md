---
name: prowler-test-sdk
description: >
  Testing patterns for Prowler SDK (Python).
  Trigger: When writing tests for checks, services, or providers.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
---

> **Generic Patterns**: For base pytest patterns (fixtures, mocking, parametrize, markers), see the `pytest` skill.
> This skill covers **Prowler-specific** conventions only.
>
> **Full Documentation**: `docs/developer-guide/unit-testing.mdx`

## CRITICAL: Provider-Specific Testing

| Provider | Mocking Approach | Decorator |
|----------|------------------|-----------|
| **AWS** | `moto` library | `@mock_aws` |
| **Azure, GCP, K8s, others** | `MagicMock` | None |

**NEVER use moto for non-AWS providers. NEVER use MagicMock for AWS.**

---

## AWS Check Test Pattern

```python
from unittest import mock
from boto3 import client
from moto import mock_aws
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_{check_name}:
    @mock_aws
    def test_no_resources(self):
        from prowler.providers.aws.services.{service}.{service}_service import {ServiceClass}

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.{service}.{check_name}.{check_name}.{service}_client",
                new={ServiceClass}(aws_provider),
            ):
                from prowler.providers.aws.services.{service}.{check_name}.{check_name} import (
                    {check_name},
                )

                check = {check_name}()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_{check_name}_pass(self):
        # Setup AWS resources with moto
        {service}_client = client("{service}", region_name=AWS_REGION_US_EAST_1)
        # Create compliant resource...

        from prowler.providers.aws.services.{service}.{service}_service import {ServiceClass}

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.{service}.{check_name}.{check_name}.{service}_client",
                new={ServiceClass}(aws_provider),
            ):
                from prowler.providers.aws.services.{service}.{check_name}.{check_name} import (
                    {check_name},
                )

                check = {check_name}()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"

    @mock_aws
    def test_{check_name}_fail(self):
        # Setup AWS resources with moto
        {service}_client = client("{service}", region_name=AWS_REGION_US_EAST_1)
        # Create non-compliant resource...

        from prowler.providers.aws.services.{service}.{service}_service import {ServiceClass}

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.{service}.{check_name}.{check_name}.{service}_client",
                new={ServiceClass}(aws_provider),
            ):
                from prowler.providers.aws.services.{service}.{check_name}.{check_name} import (
                    {check_name},
                )

                check = {check_name}()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
```

> **Critical**: Always import the check INSIDE the mock.patch context to ensure proper client mocking.

---

## Azure Check Test Pattern

**NO moto decorator. Use MagicMock to mock the service client directly.**

```python
from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.{service}.{service}_service import {ResourceModel}
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_{check_name}:
    def test_no_resources(self):
        {service}_client = mock.MagicMock
        {service}_client.{resources} = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.{service}.{check_name}.{check_name}.{service}_client",
                new={service}_client,
            ),
        ):
            from prowler.providers.azure.services.{service}.{check_name}.{check_name} import (
                {check_name},
            )

            check = {check_name}()
            result = check.execute()
            assert len(result) == 0

    def test_{check_name}_pass(self):
        resource_id = str(uuid4())
        resource_name = "Test Resource"

        {service}_client = mock.MagicMock
        {service}_client.{resources} = {
            AZURE_SUBSCRIPTION_ID: {
                resource_id: {ResourceModel}(
                    id=resource_id,
                    name=resource_name,
                    location="westeurope",
                    # ... compliant attributes
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.{service}.{check_name}.{check_name}.{service}_client",
                new={service}_client,
            ),
        ):
            from prowler.providers.azure.services.{service}.{check_name}.{check_name} import (
                {check_name},
            )

            check = {check_name}()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == resource_name

    def test_{check_name}_fail(self):
        resource_id = str(uuid4())
        resource_name = "Test Resource"

        {service}_client = mock.MagicMock
        {service}_client.{resources} = {
            AZURE_SUBSCRIPTION_ID: {
                resource_id: {ResourceModel}(
                    id=resource_id,
                    name=resource_name,
                    location="westeurope",
                    # ... non-compliant attributes
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.{service}.{check_name}.{check_name}.{service}_client",
                new={service}_client,
            ),
        ):
            from prowler.providers.azure.services.{service}.{check_name}.{check_name} import (
                {check_name},
            )

            check = {check_name}()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
```

---

## GCP/Kubernetes/Other Providers

Follow the same MagicMock pattern as Azure:

```python
from tests.providers.gcp.gcp_fixtures import set_mocked_gcp_provider, GCP_PROJECT_ID
from tests.providers.kubernetes.kubernetes_fixtures import set_mocked_kubernetes_provider
```

**Key difference**: Each provider has its own fixtures file with `set_mocked_{provider}_provider`.

---

## Provider Fixtures Reference

| Provider | Fixtures File | Key Constants |
|----------|---------------|---------------|
| AWS | `tests/providers/aws/utils.py` | `AWS_REGION_US_EAST_1`, `AWS_ACCOUNT_NUMBER` |
| Azure | `tests/providers/azure/azure_fixtures.py` | `AZURE_SUBSCRIPTION_ID` |
| GCP | `tests/providers/gcp/gcp_fixtures.py` | `GCP_PROJECT_ID` |
| K8s | `tests/providers/kubernetes/kubernetes_fixtures.py` | - |

---

## Test File Structure

```
tests/providers/{provider}/services/{service}/
├── {service}_service_test.py      # Service tests
└── {check_name}/
    └── {check_name}_test.py       # Check tests
```

---

## Required Test Scenarios

Every check MUST test:

| Scenario | Expected |
|----------|----------|
| Resource compliant | `status == "PASS"` |
| Resource non-compliant | `status == "FAIL"` |
| No resources | `len(results) == 0` |

---

## Assertions to Include

```python
# Always verify these
assert result[0].status == "PASS"  # or "FAIL"
assert result[0].status_extended == "Expected message..."
assert result[0].resource_id == expected_id
assert result[0].resource_name == expected_name

# Provider-specific
assert result[0].region == "us-east-1"           # AWS
assert result[0].subscription == AZURE_SUBSCRIPTION_ID  # Azure
assert result[0].project_id == GCP_PROJECT_ID    # GCP
```

---

## Commands

```bash
# All SDK tests
poetry run pytest -n auto -vvv tests/

# Specific provider
poetry run pytest tests/providers/{provider}/ -v

# Specific check
poetry run pytest tests/providers/{provider}/services/{service}/{check_name}/ -v

# Stop on first failure
poetry run pytest -x tests/
```

## Keywords
prowler sdk test, pytest, moto, mock, unit test, check test, aws, azure, gcp, magicmock
