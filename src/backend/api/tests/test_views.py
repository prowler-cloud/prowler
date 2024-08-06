from datetime import datetime

import pytest
from django.urls import reverse
from rest_framework import status

from api.models import Provider
from api.rls import Tenant

API_JSON_CONTENT_TYPE = "application/vnd.api+json"
# TODO Change to 401 when authentication/authorization is implemented
NO_TENANT_HTTP_STATUS = status.HTTP_403_FORBIDDEN


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

    def test_tenants_invalid_retrieve(self, client):
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


@pytest.mark.django_db
class TestProviderViewSet:
    @pytest.fixture
    def providers(self, get_tenant):
        tenant = get_tenant
        provider1 = Provider.objects.create(
            provider="aws",
            provider_id="123456789012",
            alias="aws_testing_1",
            tenant_id=tenant.id,
        )
        provider2 = Provider.objects.create(
            provider="aws",
            provider_id="123456789013",
            alias="aws_testing_2",
            tenant_id=tenant.id,
        )
        provider3 = Provider.objects.create(
            provider="gcp",
            provider_id="a12322-test321",
            alias="gcp_testing",
            tenant_id=tenant.id,
        )
        provider4 = Provider.objects.create(
            provider="kubernetes",
            provider_id="kubernetes-test-12345",
            alias="k8s_testing",
            tenant_id=tenant.id,
        )
        provider5 = Provider.objects.create(
            provider="azure",
            provider_id="37b065f8-26b0-4218-a665-0b23d07b27d9",
            alias="azure_testing",
            tenant_id=tenant.id,
        )

        return provider1, provider2, provider3, provider4, provider5

    def test_providers_rls(self, client):
        response = client.get(reverse("provider-list"))
        assert response.status_code == NO_TENANT_HTTP_STATUS

    def test_providers_list(self, client, providers, tenant_header):
        response = client.get(reverse("provider-list"), headers=tenant_header)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(providers)

    def test_providers_retrieve(self, client, providers, tenant_header):
        provider1, *_ = providers
        response = client.get(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["provider"] == provider1.provider
        assert (
            response.json()["data"]["attributes"]["provider_id"]
            == provider1.provider_id
        )
        assert response.json()["data"]["attributes"]["alias"] == provider1.alias

    def test_providers_invalid_retrieve(self, client, tenant_header):
        response = client.get(
            reverse("provider-detail", kwargs={"pk": "random_id"}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "provider_json_payload",
        (
            [
                {"provider": "aws", "provider_id": "111111111111", "alias": "test"},
                {"provider": "gcp", "provider_id": "a12322-test54321", "alias": "test"},
                {
                    "provider": "kubernetes",
                    "provider_id": "kubernetes-test-123456789",
                    "alias": "test",
                },
                {
                    "provider": "azure",
                    "provider_id": "8851db6b-42e5-4533-aa9e-30a32d67e875",
                    "alias": "test",
                },
            ]
        ),
    )
    def test_providers_create_valid(self, client, tenant_header, provider_json_payload):
        response = client.post(
            reverse("provider-list"),
            data=provider_json_payload,
            format="json",
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Provider.objects.count() == 1
        assert Provider.objects.get().provider == provider_json_payload["provider"]
        assert (
            Provider.objects.get().provider_id == provider_json_payload["provider_id"]
        )
        assert Provider.objects.get().alias == provider_json_payload["alias"]

    @pytest.mark.parametrize(
        "provider_json_payload, error_code",
        (
            [
                (
                    {"provider": "aws", "provider_id": "1", "alias": "test"},
                    "min_length",
                ),
                (
                    {
                        "provider": "aws",
                        "provider_id": "1111111111111",
                        "alias": "test",
                    },
                    "aws-provider-id",
                ),
                (
                    {"provider": "aws", "provider_id": "aaaaaaaaaaaa", "alias": "test"},
                    "aws-provider-id",
                ),
                (
                    {"provider": "gcp", "provider_id": "1234asdf", "alias": "test"},
                    "gcp-provider-id",
                ),
                (
                    {
                        "provider": "kubernetes",
                        "provider_id": "-1234asdf",
                        "alias": "test",
                    },
                    "kubernetes-provider-id",
                ),
                (
                    {
                        "provider": "azure",
                        "provider_id": "8851db6b-42e5-4533-aa9e-30a32d67e87",
                        "alias": "test",
                    },
                    "azure-provider-id",
                ),
            ]
        ),
    )
    def test_providers_invalid_create(
        self, client, tenant_header, provider_json_payload, error_code
    ):
        response = client.post(
            reverse("provider-list"),
            data=provider_json_payload,
            format="json",
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == error_code
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/provider_id"
        )

    def test_providers_partial_update(self, client, providers, tenant_header):
        provider1, *_ = providers
        new_alias = "This is the new name"
        payload = {
            "data": {
                "type": "Provider",
                "id": provider1.id,
                "attributes": {"alias": new_alias},
            },
        }
        response = client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        provider1.refresh_from_db()
        assert provider1.alias == new_alias

    def test_providers_partial_update_invalid_content_type(
        self, client, providers, tenant_header
    ):
        provider1, *_ = providers
        response = client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data={},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_providers_partial_update_invalid_content(
        self, client, providers, tenant_header
    ):
        provider1, *_ = providers
        new_name = "This is the new name"
        payload = {"alias": new_name}
        response = client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "attribute_key, attribute_value",
        [
            ("provider", "aws"),
            ("provider_id", "123456789012"),
        ],
    )
    def test_providers_partial_update_invalid_fields(
        self, client, providers, tenant_header, attribute_key, attribute_value
    ):
        provider1, *_ = providers
        payload = {
            "data": {
                "type": "Provider",
                "id": provider1.id,
                "attributes": {attribute_key: attribute_value},
            },
        }
        response = client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_providers_delete(self, client, providers, tenant_header):
        provider1, *_ = providers
        response = client.delete(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert "Content-Location" in response.headers
        assert Provider.objects.count() == len(providers) - 1
        # TODO Assert a task is returned when they are implemented

    def test_providers_delete_invalid(self, client, tenant_header):
        response = client.delete(
            reverse("provider-detail", kwargs={"pk": "random_id"}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_providers_connection(self, client, providers, tenant_header):
        provider1, *_ = providers
        assert provider1.connected is None
        assert provider1.connection_last_checked_at is None

        response = client.post(
            reverse("provider-connection", kwargs={"pk": provider1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert "Content-Location" in response.headers
        # TODO Assert a task is returned when they are implemented

        provider1.refresh_from_db()
        assert provider1.connected is True
        assert isinstance(provider1.connection_last_checked_at, datetime)

    def test_providers_connection_invalid_provider(
        self, client, providers, tenant_header
    ):
        response = client.post(
            reverse("provider-connection", kwargs={"pk": "random_id"}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "filter_name, filter_value",
        (
            [
                ("provider", "aws"),
                ("provider_id", "12345"),
                ("alias", "test"),
                ("search", "test"),
                ("inserted_at", "2024-01-01 00:00:00"),
                ("updated_at", "2024-01-01 00:00:00"),
            ]
        ),
    )
    def test_providers_filters(self, client, tenant_header, filter_name, filter_value):
        response = client.get(
            reverse("provider-list"),
            {f"filter[{filter_name}]": filter_value},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.parametrize(
        "filter_name",
        (
            [
                "provider",  # Valid filter, invalid value
                "invalid",
            ]
        ),
    )
    def test_providers_filters_invalid(self, client, tenant_header, filter_name):
        response = client.get(
            reverse("provider-list"),
            {f"filter[{filter_name}]": "whatever"},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "sort_field",
        (
            [
                "provider",
                "provider_id",
                "alias",
                "connected",
                "inserted_at",
                "updated_at",
            ]
        ),
    )
    def test_providers_sort(self, client, tenant_header, sort_field):
        response = client.get(
            reverse("provider-list"), {"sort": sort_field}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_200_OK

    def test_providers_sort_invalid(self, client, tenant_header):
        response = client.get(
            reverse("provider-list"), {"sort": "invalid"}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
