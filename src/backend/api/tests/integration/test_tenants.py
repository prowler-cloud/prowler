from unittest.mock import patch

import pytest
from django.urls import reverse

from conftest import TEST_USER, TEST_PASSWORD, get_api_tokens, get_authorization_header


@patch("api.v1.views.schedule_provider_scan")
@pytest.mark.django_db
def test_check_resources_between_different_tenants(
    schedule_mock,
    enforce_test_user_db_connection,
    authenticated_api_client,
    tenants_fixture,
):
    client = authenticated_api_client

    tenant1 = str(tenants_fixture[0].id)
    tenant2 = str(tenants_fixture[1].id)

    tenant1_token, _ = get_api_tokens(
        client, TEST_USER, TEST_PASSWORD, tenant_id=tenant1
    )
    tenant2_token, _ = get_api_tokens(
        client, TEST_USER, TEST_PASSWORD, tenant_id=tenant2
    )

    tenant1_headers = get_authorization_header(tenant1_token)
    tenant2_headers = get_authorization_header(tenant2_token)

    # Create a provider on tenant 1
    provider_data = {
        "data": {
            "type": "providers",
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
        headers=tenant1_headers,
    )
    assert provider1_response.status_code == 201
    provider1_id = provider1_response.json()["data"]["id"]

    # Create a provider on tenant 2
    provider_data = {
        "data": {
            "type": "providers",
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
        headers=tenant2_headers,
    )
    assert provider2_response.status_code == 201
    provider2_id = provider2_response.json()["data"]["id"]

    # Try to get the provider from tenant 1 on tenant 2 and vice versa
    tenant1_response = client.get(
        reverse("provider-detail", kwargs={"pk": provider1_id}),
        headers=tenant2_headers,
    )
    assert tenant1_response.status_code == 404
    tenant2_response = client.get(
        reverse("provider-detail", kwargs={"pk": provider1_id}),
        headers=tenant1_headers,
    )
    assert tenant2_response.status_code == 200
    assert tenant2_response.json()["data"]["id"] == provider1_id

    # Vice versa

    tenant2_response = client.get(
        reverse("provider-detail", kwargs={"pk": provider2_id}),
        headers=tenant1_headers,
    )
    assert tenant2_response.status_code == 404
    tenant1_response = client.get(
        reverse("provider-detail", kwargs={"pk": provider2_id}),
        headers=tenant2_headers,
    )
    assert tenant1_response.status_code == 200
    assert tenant1_response.json()["data"]["id"] == provider2_id
