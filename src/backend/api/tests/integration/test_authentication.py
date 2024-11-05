import pytest
from django.urls import reverse
from unittest.mock import patch
from rest_framework.test import APIClient

from conftest import TEST_PASSWORD, get_api_tokens, get_authorization_header


@patch("api.v1.views.MainRouter.admin_db", new="default")
@pytest.mark.django_db
def test_basic_authentication():
    client = APIClient()

    test_user = "test_email@prowler.com"
    test_password = "test_password"

    # Check that a 401 is returned when no basic authentication is provided
    no_auth_response = client.get(reverse("provider-list"))
    assert no_auth_response.status_code == 401

    # Check that we can create a new user without any kind of authentication
    user_creation_response = client.post(
        reverse("user-list"),
        data={
            "data": {
                "type": "User",
                "attributes": {
                    "name": "test",
                    "email": test_user,
                    "password": test_password,
                },
            }
        },
        format="vnd.api+json",
    )
    assert user_creation_response.status_code == 201

    # Check that using our new user's credentials we can authenticate and get the providers
    access_token, _ = get_api_tokens(client, test_user, test_password)
    auth_headers = get_authorization_header(access_token)

    auth_response = client.get(
        reverse("provider-list"),
        headers=auth_headers,
    )
    assert auth_response.status_code == 200


@pytest.mark.django_db
def test_refresh_token(create_test_user, tenants_fixture):
    client = APIClient()

    # Assert that we can obtain a new access token using the refresh one
    access_token, refresh_token = get_api_tokens(
        client, create_test_user.email, TEST_PASSWORD
    )
    valid_refresh_response = client.post(
        reverse("token-refresh"),
        data={
            "data": {
                "type": "TokenRefresh",
                "attributes": {"refresh": refresh_token},
            }
        },
        format="vnd.api+json",
    )
    assert valid_refresh_response.status_code == 200
    assert (
        valid_refresh_response.json()["data"]["attributes"]["refresh"] != refresh_token
    )

    # Assert the former refresh token gets invalidated
    invalid_refresh_response = client.post(
        reverse("token-refresh"),
        data={
            "data": {
                "type": "TokenRefresh",
                "attributes": {"refresh": refresh_token},
            }
        },
        format="vnd.api+json",
    )
    assert invalid_refresh_response.status_code == 400

    # Assert that the new refresh token could be used
    new_refresh_response = client.post(
        reverse("token-refresh"),
        data={
            "data": {
                "type": "TokenRefresh",
                "attributes": {
                    "refresh": valid_refresh_response.json()["data"]["attributes"][
                        "refresh"
                    ]
                },
            }
        },
        format="vnd.api+json",
    )
    assert new_refresh_response.status_code == 200
