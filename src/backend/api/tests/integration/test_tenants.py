import pytest
from django.urls import reverse


@pytest.mark.django_db
def test_check_resources_between_different_tenants(
    enforce_test_user_db_connection, authenticated_api_client, tenants_fixture
):
    client = authenticated_api_client

    tenant1 = str(tenants_fixture[0].id)
    tenant2 = str(tenants_fixture[1].id)

    # Create a provider on tenant 1
    provider_data = {
        "data": {
            "type": "Provider",
            "attributes": {
                "alias": "test_provider_tenant_1",
                "provider": "aws",
                "uid": "123456789012",
            },
        }
    }
    provider1_response = client.post(
        reverse("provider-list"),
        data=provider_data,
        format="vnd.api+json",
        HTTP_X_TENANT_ID=tenant1,
    )
    assert provider1_response.status_code == 201
    provider1_id = provider1_response.json()["data"]["id"]

    # Create a provider on tenant 2
    provider_data = {
        "data": {
            "type": "Provider",
            "attributes": {
                "alias": "test_provider_tenant_2",
                "provider": "aws",
                "uid": "123456789013",
            },
        }
    }
    provider2_response = client.post(
        reverse("provider-list"),
        data=provider_data,
        format="vnd.api+json",
        HTTP_X_TENANT_ID=tenant2,
    )
    assert provider2_response.status_code == 201
    provider2_id = provider2_response.json()["data"]["id"]

    # Try to get the provider from tenant 1 on tenant 2 and vice versa
    tenant1_response = client.get(
        reverse("provider-detail", kwargs={"pk": provider1_id}),
        HTTP_X_TENANT_ID=tenant2,
    )
    assert tenant1_response.status_code == 404
    tenant2_response = client.get(
        reverse("provider-detail", kwargs={"pk": provider1_id}),
        HTTP_X_TENANT_ID=tenant1,
    )
    assert tenant2_response.status_code == 200
    assert tenant2_response.json()["data"]["id"] == provider1_id

    # Vice versa

    tenant2_response = client.get(
        reverse("provider-detail", kwargs={"pk": provider2_id}),
        HTTP_X_TENANT_ID=tenant1,
    )
    assert tenant2_response.status_code == 404
    tenant1_response = client.get(
        reverse("provider-detail", kwargs={"pk": provider2_id}),
        HTTP_X_TENANT_ID=tenant2,
    )
    assert tenant1_response.status_code == 200
    assert tenant1_response.json()["data"]["id"] == provider2_id
