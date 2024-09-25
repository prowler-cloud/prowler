import base64

import pytest
from django.urls import reverse
from rest_framework.test import APIClient


@pytest.mark.django_db
def test_basic_authentication(providers_fixture, tenant_header):
    client = APIClient()

    test_user = "test_user"
    test_password = "test_password"
    credentials = base64.b64encode(f"{test_user}:{test_password}".encode()).decode()

    # Check that a 401 is returned when no basic authentication is provided
    no_auth_response = client.get(reverse("provider-list"), headers=tenant_header)
    assert no_auth_response.status_code == 401

    # Check that we can create a new user without any kind of authentication
    user_creation_response = client.post(
        reverse("user-list"),
        data={
            "data": {
                "type": "User",
                "attributes": {
                    "name": "test",
                    "username": test_user,
                    "password": test_password,
                    "email": "thisisnotimportant@prowler.com",
                },
            }
        },
        format="vnd.api+json",
    )
    assert user_creation_response.status_code == 201

    # Check that using our new user's credentials we can authenticate and get the providers
    auth_response = client.get(
        reverse("provider-list"),
        headers=tenant_header,
        HTTP_AUTHORIZATION=f"Basic {credentials}",
    )
    assert auth_response.status_code == 200
    assert len(auth_response.json()["data"]) == len(providers_fixture)
