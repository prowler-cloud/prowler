---
name: prowler-test-api
description: >
  Testing patterns for Prowler API (Django/DRF).
  Trigger: When writing tests for viewsets, serializers, or Celery tasks.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

> **Generic Patterns**: For base pytest patterns (fixtures, mocking, markers), see the `pytest` skill.
> For Django/DRF patterns (ViewSets, serializers), see the `django-drf` skill.
> This skill covers **Prowler-specific** conventions only.

## Critical: JSON:API Format

All API tests MUST use JSON:API format:

```python
# Content-Type header
content_type="application/vnd.api+json"

# Request payload structure
payload = {
    "data": {
        "type": "providers",  # Resource type (plural)
        "id": str(resource.id),  # Required for PATCH
        "attributes": {
            "alias": "updated-alias",
        },
        "relationships": {  # Optional
            "tenant": {"data": {"type": "tenants", "id": str(tenant.id)}}
        }
    }
}

# Response structure
response.data["data"]["attributes"]["alias"]
response.data["data"]["id"]
```

---

## Critical: RLS Testing

**ALWAYS test Row-Level Security isolation:**

```python
@pytest.mark.django_db
class TestRLSIsolation:
    def test_list_excludes_other_tenant_data(
        self, authenticated_client, other_tenant_provider
    ):
        """Verify list endpoint filters by tenant."""
        response = authenticated_client.get(reverse("provider-list"))
        provider_ids = [p["id"] for p in response.data["data"]]
        assert str(other_tenant_provider.id) not in provider_ids

    def test_detail_returns_404_for_other_tenant(
        self, authenticated_client, other_tenant_provider
    ):
        """Verify direct access to other tenant's data returns 404."""
        response = authenticated_client.get(
            reverse("provider-detail", args=[other_tenant_provider.id])
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
```

---

## ViewSet Test Pattern

```python
import pytest
from django.urls import reverse
from rest_framework import status

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

    def test_create_duplicate_fails(self, authenticated_client, provider_fixture):
        payload = {
            "data": {
                "type": "providers",
                "attributes": {
                    "provider_type": "aws",
                    "uid": provider_fixture.uid,  # Duplicate
                    "alias": "duplicate-provider",
                },
            }
        }
        response = authenticated_client.post(
            reverse("provider-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_update_success(self, authenticated_client, provider_fixture):
        payload = {
            "data": {
                "type": "providers",
                "id": str(provider_fixture.id),
                "attributes": {"alias": "updated-alias"},
            }
        }
        response = authenticated_client.patch(
            reverse("provider-detail", args=[provider_fixture.id]),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK

    def test_delete_success(self, authenticated_client, provider_fixture):
        response = authenticated_client.delete(
            reverse("provider-detail", args=[provider_fixture.id])
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
```

---

## Fixtures (conftest.py)

```python
import pytest
from api.models import Provider, Tenant

@pytest.fixture
def tenant_fixture():
    return Tenant.objects.create(name="test-tenant")

@pytest.fixture
def other_tenant_fixture():
    return Tenant.objects.create(name="other-tenant")

@pytest.fixture
def provider_fixture(tenant_fixture):
    return Provider.objects.create(
        tenant_id=tenant_fixture.id,
        provider_type=Provider.ProviderChoices.AWS,
        uid="123456789012",
        alias="test-aws",
    )

@pytest.fixture
def other_tenant_provider(other_tenant_fixture):
    return Provider.objects.create(
        tenant_id=other_tenant_fixture.id,
        provider_type=Provider.ProviderChoices.AWS,
        uid="999999999999",
        alias="other-aws",
    )

@pytest.fixture
def authenticated_client(client, tenant_fixture, user_fixture):
    client.force_authenticate(user=user_fixture)
    return client
```

---

## Celery Task Test Pattern

```python
@pytest.mark.django_db
class TestProcessScanTask:
    def test_task_success(self, tenant_fixture, scan_fixture):
        with patch("tasks.jobs.scan.run_prowler_scan") as mock_scan:
            mock_scan.return_value = {"findings": []}

            result = process_scan_task(
                str(tenant_fixture.id),
                str(scan_fixture.id)
            )

            assert result["status"] == "completed"
            mock_scan.assert_called_once()

    def test_task_marks_failed_on_error(self, tenant_fixture, scan_fixture):
        with patch("tasks.jobs.scan.run_prowler_scan") as mock_scan:
            mock_scan.side_effect = Exception("Scan failed")

            with pytest.raises(Exception):
                process_scan_task(
                    str(tenant_fixture.id),
                    str(scan_fixture.id)
                )

            scan_fixture.refresh_from_db()
            assert scan_fixture.status == "failed"
```

---

## Test File Structure

```
api/src/backend/api/tests/
├── conftest.py                # Shared fixtures
├── test_providers.py          # Provider ViewSet tests
├── test_scans.py              # Scan ViewSet tests
├── test_findings.py           # Finding ViewSet tests
└── test_serializers.py        # Serializer tests

api/src/backend/tasks/tests/
├── conftest.py                # Task fixtures
└── test_scan_tasks.py         # Celery task tests
```

---

## Commands

```bash
cd api && poetry run pytest                    # All tests
cd api && poetry run pytest -x --tb=short      # Stop on first failure
cd api && poetry run pytest -k "test_provider" # By name
cd api && poetry run pytest -k "TestProviderViewSet"  # By class
cd api && poetry run pytest --cov=api          # With coverage
cd api && poetry run pytest -v                 # Verbose
```

## Keywords
prowler api test, pytest, django, drf, json:api, rls, celery, viewset test
