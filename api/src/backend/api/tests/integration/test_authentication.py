from unittest.mock import patch

import pytest
from conftest import TEST_PASSWORD, get_api_tokens, get_authorization_header
from django.urls import reverse
from rest_framework.test import APIClient


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
                "type": "users",
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
                "type": "tokens-refresh",
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
                "type": "tokens-refresh",
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
                "type": "tokens-refresh",
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


@patch("api.db_router.MainRouter.admin_db", new="default")
@pytest.mark.django_db
def test_user_me_when_inviting_users(create_test_user, tenants_fixture):
    client = APIClient()

    user1_email = "user1@testing.com"
    user2_email = "user2@testing.com"

    password = "thisisapassword123"

    user1_response = client.post(
        reverse("user-list"),
        data={
            "data": {
                "type": "users",
                "attributes": {
                    "name": "user1",
                    "email": user1_email,
                    "password": password,
                },
            }
        },
        format="vnd.api+json",
    )
    assert user1_response.status_code == 201

    user1_access_token, _ = get_api_tokens(client, user1_email, password)
    user1_headers = get_authorization_header(user1_access_token)

    user2_invitation = client.post(
        reverse("invitation-list"),
        data={
            "data": {
                "type": "invitations",
                "attributes": {"email": user2_email},
            }
        },
        format="vnd.api+json",
        headers=user1_headers,
    )
    assert user2_invitation.status_code == 201
    invitation_token = user2_invitation.json()["data"]["attributes"]["token"]

    user2_response = client.post(
        reverse("user-list") + f"?invitation_token={invitation_token}",
        data={
            "data": {
                "type": "users",
                "attributes": {
                    "name": "user2",
                    "email": user2_email,
                    "password": password,
                },
            }
        },
        format="vnd.api+json",
    )
    assert user2_response.status_code == 201

    user2_access_token, _ = get_api_tokens(client, user2_email, password)
    user2_headers = get_authorization_header(user2_access_token)

    user1_me = client.get(reverse("user-me"), headers=user1_headers)
    assert user1_me.status_code == 200
    assert user1_me.json()["data"]["attributes"]["email"] == user1_email

    user2_me = client.get(reverse("user-me"), headers=user2_headers)
    assert user2_me.status_code == 200
    assert user2_me.json()["data"]["attributes"]["email"] == user2_email
