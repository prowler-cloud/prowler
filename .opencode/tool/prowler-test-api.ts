import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: prowler-test-api
description: Testing patterns for Prowler API (Django/DRF).
license: Apache 2.0
---

> **Generic Patterns**: For base pytest patterns (fixtures, mocking, markers), see the \`pytest\` skill.
> For Django/DRF patterns (ViewSets, serializers), see the \`django-drf\` skill.
> This skill covers **Prowler-specific** conventions only.

## Critical: JSON:API Format

All API tests MUST use JSON:API format:

\`\`\`python
# Content-Type header
content_type="application/vnd.api+json"

# Request payload structure
payload = {
    "data": {
        "type": "providers",
        "id": str(resource.id),  # Required for PATCH
        "attributes": {
            "alias": "updated-alias",
        },
    }
}

# Response structure
response.data["data"]["attributes"]["alias"]
\`\`\`

## Critical: RLS Testing

**ALWAYS test Row-Level Security isolation:**

\`\`\`python
@pytest.mark.django_db
class TestRLSIsolation:
    def test_list_excludes_other_tenant_data(
        self, authenticated_client, other_tenant_provider
    ):
        response = authenticated_client.get(reverse("provider-list"))
        provider_ids = [p["id"] for p in response.data["data"]]
        assert str(other_tenant_provider.id) not in provider_ids

    def test_detail_returns_404_for_other_tenant(
        self, authenticated_client, other_tenant_provider
    ):
        response = authenticated_client.get(
            reverse("provider-detail", args=[other_tenant_provider.id])
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
\`\`\`

## ViewSet Test Pattern

\`\`\`python
@pytest.mark.django_db
class TestProviderViewSet:
    def test_list_success(self, authenticated_client, providers_fixture):
        response = authenticated_client.get(reverse("provider-list"))
        assert response.status_code == status.HTTP_200_OK

    def test_create_success(self, authenticated_client):
        payload = {
            "data": {
                "type": "providers",
                "attributes": {
                    "provider_type": "aws",
                    "uid": "123456789012",
                    "alias": "test-provider",
                },
            }
        }
        response = authenticated_client.post(
            reverse("provider-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
\`\`\`

## Celery Task Test Pattern

\`\`\`python
@pytest.mark.django_db
class TestProcessScanTask:
    def test_task_success(self, tenant_fixture, scan_fixture):
        with patch("tasks.jobs.scan.run_prowler_scan") as mock_scan:
            mock_scan.return_value = {"findings": []}
            result = process_scan_task(str(tenant_fixture.id), str(scan_fixture.id))
            assert result["status"] == "completed"
\`\`\`

## Test File Structure

\`\`\`
api/src/backend/api/tests/
├── conftest.py          # Shared fixtures
├── test_providers.py    # Provider ViewSet tests
├── test_scans.py        # Scan ViewSet tests
└── test_findings.py     # Finding ViewSet tests
\`\`\`

## Commands

\`\`\`bash
cd api && poetry run pytest                    # All tests
cd api && poetry run pytest -x --tb=short      # Stop on first failure
cd api && poetry run pytest -k "test_provider" # By name
cd api && poetry run pytest --cov=api          # With coverage
\`\`\`

## Keywords
prowler api test, pytest, django, drf, json:api, rls, celery
`;

export default tool({
  description: SKILL,
  args: {
    entity: tool.schema.string().describe("Entity name: provider, scan, finding, compliance"),
    operation: tool.schema.string().optional().describe("Operation: list, create, update, delete, rls"),
  },
  async execute(args) {
    const entity = args.entity.toLowerCase();
    const entityClass = entity.charAt(0).toUpperCase() + entity.slice(1);
    const operation = args.operation?.toLowerCase() || "crud";

    if (operation === "rls") {
      return `
RLS Test for ${entityClass}

\`\`\`python
@pytest.mark.django_db
class TestRLSIsolation:
    def test_list_excludes_other_tenant_${entity}(
        self, authenticated_client, other_tenant_${entity}
    ):
        """Verify list endpoint filters by tenant."""
        response = authenticated_client.get(reverse("${entity}-list"))
        ${entity}_ids = [item["id"] for item in response.data["data"]]
        assert str(other_tenant_${entity}.id) not in ${entity}_ids

    def test_detail_returns_404_for_other_tenant_${entity}(
        self, authenticated_client, other_tenant_${entity}
    ):
        """Verify direct access to other tenant's data returns 404."""
        response = authenticated_client.get(
            reverse("${entity}-detail", args=[other_tenant_${entity}.id])
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
\`\`\`

## Required Fixtures (conftest.py)

\`\`\`python
@pytest.fixture
def other_tenant_${entity}(other_tenant_fixture):
    return ${entityClass}.objects.create(
        tenant_id=other_tenant_fixture.id,
        # Add required fields
    )
\`\`\`
      `.trim();
    }

    return `
ViewSet Test for ${entityClass}

\`\`\`python
import pytest
from django.urls import reverse
from rest_framework import status

@pytest.mark.django_db
class Test${entityClass}ViewSet:
    def test_list_success(self, authenticated_client, ${entity}_fixture):
        response = authenticated_client.get(reverse("${entity}-list"))
        assert response.status_code == status.HTTP_200_OK

    def test_create_success(self, authenticated_client):
        payload = {
            "data": {
                "type": "${entity}s",
                "attributes": {
                    # Add required attributes
                },
            }
        }
        response = authenticated_client.post(
            reverse("${entity}-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

    def test_update_success(self, authenticated_client, ${entity}_fixture):
        payload = {
            "data": {
                "type": "${entity}s",
                "id": str(${entity}_fixture.id),
                "attributes": {"alias": "updated"},
            }
        }
        response = authenticated_client.patch(
            reverse("${entity}-detail", args=[${entity}_fixture.id]),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK

    def test_delete_success(self, authenticated_client, ${entity}_fixture):
        response = authenticated_client.delete(
            reverse("${entity}-detail", args=[${entity}_fixture.id])
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_cannot_access_other_tenant_${entity}(
        self, authenticated_client, other_tenant_${entity}
    ):
        response = authenticated_client.get(
            reverse("${entity}-detail", args=[other_tenant_${entity}.id])
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
\`\`\`

## Run Command
cd api && poetry run pytest -k "Test${entityClass}ViewSet"
    `.trim();
  },
})
