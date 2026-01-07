import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: prowler-test-sdk
description: Testing patterns for Prowler SDK (Python).
license: Apache 2.0
---

> **Generic Patterns**: For base pytest patterns (fixtures, mocking, parametrize, markers), see the \`pytest\` skill.
> This skill covers **Prowler-specific** conventions only.

## Check Test Pattern

\`\`\`python
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
\`\`\`

## Mocking AWS with moto

\`\`\`python
import boto3
from moto import mock_aws

@mock_aws
def test_aws_resource():
    client = boto3.client("ec2", region_name="us-east-1")
    client.create_vpc(CidrBlock="10.0.0.0/16")
    # Service will use mocked AWS
    service = EC2Service(provider)
    assert len(service.vpcs) == 1
\`\`\`

## Required Test Scenarios

| Scenario | Expected |
|----------|----------|
| Resource compliant | \`status == "PASS"\` |
| Resource non-compliant | \`status == "FAIL"\` |
| No resources | \`len(results) == 0\` |
| Error during fetch | Graceful handling |

## Test File Structure

\`\`\`
tests/providers/{provider}/services/{service}/
├── {service}_service_test.py
└── {check_name}/
    └── {check_name}_test.py
\`\`\`

## Commands

\`\`\`bash
poetry run pytest -n auto -vvv tests/                    # All
poetry run pytest tests/providers/{provider}/ -v         # Provider
poetry run pytest tests/providers/{provider}/services/{service}/{check_name}/ -v  # Check
poetry run pytest --cov=prowler tests/                   # Coverage
\`\`\`

## Keywords
prowler sdk test, pytest, moto, mock, check test, aws, azure, gcp
`;

export default tool({
  description: SKILL,
  args: {
    provider: tool.schema.string().describe("Provider: aws, azure, gcp, kubernetes, github"),
    service: tool.schema.string().describe("Service name: ec2, iam, s3, etc."),
    check_name: tool.schema.string().describe("Check name: ec2_instance_public_ip"),
  },
  async execute(args) {
    const provider = args.provider.toLowerCase();
    const service = args.service.toLowerCase();
    const checkName = args.check_name.toLowerCase();
    const checkClass = checkName.split("_").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join("");

    return `
Check Test for ${checkName}

## Test File: tests/providers/${provider}/services/${service}/${checkName}/${checkName}_test.py

\`\`\`python
import pytest
from unittest.mock import patch, MagicMock
from prowler.providers.${provider}.services.${service}.${checkName}.${checkName} import ${checkName}


class Test${checkClass}:
    @pytest.fixture
    def mock_${service}_client(self):
        with patch(
            "prowler.providers.${provider}.services.${service}.${checkName}.${checkName}.${service}_client"
        ) as mock:
            mock.resources = [
                MagicMock(
                    id="resource-1",
                    name="test-resource",
                    region="us-east-1",
                    is_compliant=True,
                )
            ]
            yield mock

    def test_${checkName}_pass(self, mock_${service}_client):
        """Test PASS when resource is compliant."""
        check = ${checkName}()
        results = check.execute()

        assert len(results) == 1
        assert results[0].status == "PASS"
        assert "compliant" in results[0].status_extended.lower()

    def test_${checkName}_fail(self, mock_${service}_client):
        """Test FAIL when resource is non-compliant."""
        mock_${service}_client.resources[0].is_compliant = False

        check = ${checkName}()
        results = check.execute()

        assert len(results) == 1
        assert results[0].status == "FAIL"

    def test_${checkName}_no_resources(self, mock_${service}_client):
        """Test empty results when no resources exist."""
        mock_${service}_client.resources = []

        check = ${checkName}()
        results = check.execute()

        assert len(results) == 0
\`\`\`

## Run Command
poetry run pytest tests/providers/${provider}/services/${service}/${checkName}/ -v
    `.trim();
  },
})
