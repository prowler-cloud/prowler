import pytest
from django.urls import reverse
from rest_framework import status

from api.models import Tenant

API_JSON_CONTENT_TYPE = "application/vnd.api+json"


@pytest.mark.django_db
class TestTenantViewSet:
    @pytest.fixture
    def tenants(self):
        tenant1 = Tenant.objects.create(
            name="Tenant One",
            inserted_at="2023-01-01T00:00:00Z",
            updated_at="2023-01-02T00:00:00Z",
        )
        tenant2 = Tenant.objects.create(
            name="Tenant Two",
            inserted_at="2023-01-03T00:00:00Z",
            updated_at="2023-01-04T00:00:00Z",
        )
        return tenant1, tenant2

    @pytest.fixture
    def valid_tenant_payload(self):
        return {
            "name": "Tenant Three",
            "inserted_at": "2023-01-05T00:00:00Z",
            "updated_at": "2023-01-06T00:00:00Z",
        }

    @pytest.fixture
    def invalid_tenant_payload(self):
        return {
            "name": "",
            "inserted_at": "2023-01-05T00:00:00Z",
            "updated_at": "2023-01-06T00:00:00Z",
        }

    def test_tenants_list(self, client, tenants):
        response = client.get(reverse("tenant-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(tenants)

    def test_tenants_retrieve(self, client, tenants):
        tenant1, _ = tenants
        response = client.get(reverse("tenant-detail", kwargs={"pk": tenant1.id}))
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["name"] == tenant1.name

    def test_tenants_invalid_retrieve(self, client, tenants):
        tenant1, _ = tenants
        response = client.get(reverse("tenant-detail", kwargs={"pk": "random_id"}))
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tenants_create(self, client, valid_tenant_payload):
        response = client.post(
            reverse("tenant-list"), data=valid_tenant_payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Tenant.objects.count() == 1
        assert Tenant.objects.get().name == valid_tenant_payload["name"]

    def test_tenants_invalid_create(self, client, invalid_tenant_payload):
        response = client.post(
            reverse("tenant-list"),
            data=invalid_tenant_payload,
            format="json",
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_partial_update(self, client, tenants):
        tenant1, _ = tenants
        new_name = "This is the new name"
        payload = {
            "data": {
                "type": "Tenant",
                "id": tenant1.id,
                "attributes": {"name": new_name},
            },
        }
        response = client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_200_OK
        tenant1.refresh_from_db()
        assert tenant1.name == new_name

    def test_tenants_partial_update_invalid_content_type(self, client, tenants):
        tenant1, _ = tenants
        response = client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}), data={}
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_tenants_partial_update_invalid_content(self, client, tenants):
        tenant1, _ = tenants
        new_name = "This is the new name"
        payload = {"name": new_name}
        response = client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_delete(self, client, tenants):
        tenant1, _ = tenants
        response = client.delete(reverse("tenant-detail", kwargs={"pk": tenant1.id}))
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert Tenant.objects.count() == 1

    def test_tenants_delete_invalid(self, client):
        response = client.delete(reverse("tenant-detail", kwargs={"pk": "random_id"}))
        # To change if we implement RBAC
        # (user might not have permissions to see if the tenant exists or not -> 200 empty)
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tenants_list_filter_search(self, client, tenants):
        """Search is applied to tenants name."""
        tenant1, _ = tenants
        response = client.get(reverse("tenant-list"), {"filter[search]": tenant1.name})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["name"] == tenant1.name

    def test_tenants_list_query_param_name(self, client, tenants):
        tenant1, _ = tenants
        response = client.get(reverse("tenant-list"), {"name": tenant1.name})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_list_invalid_query_param(self, client):
        response = client.get(reverse("tenant-list"), {"random": "value"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_list_filter_name(self, client, tenants):
        tenant1, _ = tenants
        response = client.get(reverse("tenant-list"), {"filter[name]": tenant1.name})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["name"] == tenant1.name

    def test_tenants_list_filter_invalid(self, client):
        response = client.get(reverse("tenant-list"), {"filter[invalid]": "whatever"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_list_page_size(self, client, tenants):
        page_size = 1

        response = client.get(reverse("tenant-list"), {"page[size]": page_size})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == page_size
        assert response.json()["meta"]["pagination"]["page"] == 1
        assert response.json()["meta"]["pagination"]["pages"] == len(tenants)

    def test_tenants_list_page_number(self, client, tenants):
        page_size = 1
        page_number = 2

        response = client.get(
            reverse("tenant-list"),
            {"page[size]": page_size, "page[number]": page_number},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == page_size
        assert response.json()["meta"]["pagination"]["page"] == page_number
        assert response.json()["meta"]["pagination"]["pages"] == len(tenants)

    def test_tenants_list_sort_name(self, client, tenants):
        _, tenant2 = tenants
        response = client.get(reverse("tenant-list"), {"sort": "-name"})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2
        assert response.json()["data"][0]["attributes"]["name"] == tenant2.name
