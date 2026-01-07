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

## Check Test Pattern

```python
import pytest
from unittest.mock import patch, MagicMock
from prowler.providers.{provider}.services.{service}.{check_name}.{check_name} import {check_name}

class Test{CheckName}:
    @pytest.fixture
    def mock_{service}_client(self):
        with patch(
            "prowler.providers.{provider}.services.{service}.{check_name}.{check_name}.{service}_client"
        ) as mock:
            mock.{resources} = [
                MagicMock(
                    id="resource-1",
                    name="compliant-resource",
                    region="us-east-1",
                    is_compliant=True,
                )
            ]
            yield mock

    def test_{check_name}_pass(self, mock_{service}_client):
        check = {check_name}()
        results = check.execute()

        assert len(results) == 1
        assert results[0].status == "PASS"
        assert "compliant" in results[0].status_extended.lower()

    def test_{check_name}_fail(self, mock_{service}_client):
        mock_{service}_client.{resources}[0].is_compliant = False

        check = {check_name}()
        results = check.execute()

        assert len(results) == 1
        assert results[0].status == "FAIL"

    def test_{check_name}_no_resources(self, mock_{service}_client):
        mock_{service}_client.{resources} = []

        check = {check_name}()
        results = check.execute()

        assert len(results) == 0
```

---

## Mocking AWS with moto

**CRITICAL: Use `@mock_aws` for AWS service tests.**

```python
import boto3
from moto import mock_aws

@mock_aws
def test_aws_resource():
    # Setup mock AWS environment
    client = boto3.client("ec2", region_name="us-east-1")
    client.create_vpc(CidrBlock="10.0.0.0/16")

    # The service will use the mocked AWS
    service = EC2Service(provider)
    assert len(service.vpcs) == 1
```

### Common moto Patterns

```python
@mock_aws
class TestEC2Service:
    def test_fetch_instances(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(ImageId="ami-12345", MinCount=1, MaxCount=1)

        service = EC2Service(provider)
        assert len(service.instances) == 1

    def test_fetch_security_groups(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.create_security_group(GroupName="test-sg", Description="Test")

        service = EC2Service(provider)
        # Default SG + created SG
        assert len(service.security_groups) >= 1
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
