---
name: prowler-test-sdk
description: >
  Testing patterns for Prowler SDK (Python).
  Trigger: When writing tests for checks, services, or providers.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

> **Generic Patterns**: For base pytest patterns (fixtures, mocking, parametrize, markers), see the `pytest` skill.
> This skill covers **Prowler-specific** conventions only.

## Check Test Pattern (AWS)

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

## Mocking AWS with moto

**CRITICAL: Use `@mock_aws` for AWS service tests + `set_mocked_aws_provider`.**

```python
from unittest import mock
from boto3 import client
from moto import mock_aws
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class TestS3Service:
    @mock_aws
    def test_fetch_buckets(self):
        # Setup mock AWS resources
        s3 = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3.create_bucket(Bucket="test-bucket")

        # Create mocked provider
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        # Import service AFTER moto decorator is active
        from prowler.providers.aws.services.s3.s3_service import S3

        service = S3(aws_provider)
        assert len(service.buckets) == 1
```

### Key Utilities from `tests/providers/aws/utils.py`

```python
from tests.providers.aws.utils import (
    AWS_REGION_US_EAST_1,
    AWS_REGION_EU_WEST_1,
    AWS_ACCOUNT_NUMBER,
    set_mocked_aws_provider,
)
```

---

## Service Test Pattern

```python
class TestServiceName:
    @mock_aws
    def test_fetch_resources(self):
        # Setup mock resources
        client = boto3.client("service", region_name="us-east-1")
        client.create_resource(...)

        # Initialize service
        service = ServiceName(provider)

        # Verify resources fetched
        assert len(service.resources) == 1
        assert service.resources[0].id == "expected-id"

    @mock_aws
    def test_fetch_resources_empty(self):
        service = ServiceName(provider)
        assert len(service.resources) == 0

    @mock_aws
    def test_fetch_resources_error_handling(self):
        # Test graceful error handling
        with patch.object(service, '_fetch', side_effect=Exception("API Error")):
            service = ServiceName(provider)
            assert len(service.resources) == 0  # Should not crash
```

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
| Error during fetch | Graceful handling |

---

## Best Practices

1. **Mock at the client level** - Don't mock individual API calls
2. **Test status_extended** - Verify meaningful messages
3. **Use meaningful resource IDs** - Helps debugging
4. **Isolate tests** - Each test independent
5. **Use region consistently** - Usually `us-east-1` for AWS

---

## Commands

```bash
# All SDK tests
poetry run pytest -n auto -vvv tests/

# Specific provider
poetry run pytest tests/providers/{provider}/ -v

# Specific service
poetry run pytest tests/providers/{provider}/services/{service}/ -v

# Specific check
poetry run pytest tests/providers/{provider}/services/{service}/{check_name}/ -v

# With coverage
poetry run pytest --cov=prowler tests/

# Stop on first failure
poetry run pytest -x tests/
```

## Keywords
prowler sdk test, pytest, moto, mock, unit test, check test, aws, azure, gcp
