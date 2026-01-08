# Example: ViewSet Tests with RLS Isolation
# Source: api/src/backend/api/tests/

from unittest.mock import patch

import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
class TestTenantViewSet:
    """Example CRUD + filtering tests."""

    def test_tenants_list(self, authenticated_client, tenants_fixture):
        """Test list endpoint returns only user's tenants."""
        response = authenticated_client.get(reverse("tenant-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2  # User belongs to 2 tenants

    def test_tenants_retrieve(self, authenticated_client, tenants_fixture):
        """Test retrieve endpoint."""
        tenant1, *_ = tenants_fixture
        response = authenticated_client.get(
            reverse("tenant-detail", kwargs={"pk": tenant1.id})
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["name"] == tenant1.name

    def test_tenants_create(self, authenticated_client):
        """Test create with JSON:API format."""
        payload = {
            "data": {
                "type": "tenants",
                "attributes": {"name": "New Tenant"},
            }
        }
        response = authenticated_client.post(
            reverse("tenant-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

    def test_tenants_partial_update(self, authenticated_client, tenants_fixture):
        """Test PATCH update with JSON:API format."""
        tenant1, *_ = tenants_fixture
        new_name = "Updated Name"
        payload = {
            "data": {
                "type": "tenants",
                "id": str(tenant1.id),
                "attributes": {"name": new_name},
            },
        }
        response = authenticated_client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        tenant1.refresh_from_db()
        assert tenant1.name == new_name

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        [
            ("name", "Tenant One", 1),
            ("name.icontains", "Tenant", 2),
        ],
    )
    def test_tenants_filters(
        self,
        authenticated_client,
        tenants_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        """Parametrized filter tests."""
        response = authenticated_client.get(
            reverse("tenant-list"),
            {f"filter[{filter_name}]": filter_value},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count


@pytest.mark.django_db
class TestRLSIsolation:
    """Test that RLS properly isolates tenant data."""

    @patch("api.v1.views.schedule_provider_scan")
    def test_cross_tenant_access_denied(
        self,
        schedule_mock,
        authenticated_client,
        tenants_fixture,
        set_user_admin_roles_fixture,
    ):
        """Verify user cannot access another tenant's resources."""
        from conftest import (
            TEST_PASSWORD,
            TEST_USER,
            get_api_tokens,
            get_authorization_header,
        )

        client = authenticated_client
        tenant1 = str(tenants_fixture[0].id)
        tenant2 = str(tenants_fixture[1].id)

        # Get tokens for each tenant
        tenant1_token, _ = get_api_tokens(
            client, TEST_USER, TEST_PASSWORD, tenant_id=tenant1
        )
        tenant2_token, _ = get_api_tokens(
            client, TEST_USER, TEST_PASSWORD, tenant_id=tenant2
        )

        tenant1_headers = get_authorization_header(tenant1_token)
        tenant2_headers = get_authorization_header(tenant2_token)

        # Create provider in tenant 1
        provider_data = {
            "data": {
                "type": "providers",
                "attributes": {
                    "alias": "test_provider",
                    "provider": "aws",
                    "uid": "123456789012",
                },
            }
        }
        response = client.post(
            reverse("provider-list"),
            data=provider_data,
            format="vnd.api+json",
            headers=tenant1_headers,
        )
        assert response.status_code == 201
        provider1_id = response.json()["data"]["id"]

        # Try to access tenant1's provider from tenant2 - should 404
        response = client.get(
            reverse("provider-detail", kwargs={"pk": provider1_id}),
            headers=tenant2_headers,
        )
        assert response.status_code == 404  # RLS blocks access
