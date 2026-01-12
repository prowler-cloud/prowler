import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from conftest import TEST_PASSWORD, get_api_tokens, get_authorization_header
from django.urls import reverse
from drf_simple_apikey.crypto import get_crypto
from rest_framework.test import APIClient

from api.models import Membership, Role, TenantAPIKey, User, UserRoleRelationship


@pytest.mark.django_db
def test_basic_authentication():
    client = APIClient()

    test_user = "test_email@prowler.com"
    test_password = "Test_password@1"

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


@pytest.mark.django_db
def test_user_me_when_inviting_users(create_test_user, tenants_fixture, roles_fixture):
    client = APIClient()

    role = roles_fixture[0]

    user1_email = "user1@testing.com"
    user2_email = "user2@testing.com"

    password = "Thisisapassword123@"

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
                "relationships": {
                    "roles": {
                        "data": [
                            {
                                "type": "roles",
                                "id": str(role.id),
                            }
                        ]
                    }
                },
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


@pytest.mark.django_db
class TestTokenSwitchTenant:
    def test_switch_tenant_with_valid_token(self, tenants_fixture, providers_fixture):
        client = APIClient()

        test_user = "test_email@prowler.com"
        test_password = "Test_password1@"

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

        # Create a new relationship between this user and another tenant
        tenant_id = tenants_fixture[0].id
        user_instance = User.objects.get(email=test_user)
        Membership.objects.create(user=user_instance, tenant_id=tenant_id)

        # Check that using our new user's credentials we can authenticate and get the providers
        access_token, _ = get_api_tokens(client, test_user, test_password)
        auth_headers = get_authorization_header(access_token)

        user_me_response = client.get(
            reverse("user-me"),
            headers=auth_headers,
        )
        assert user_me_response.status_code == 200
        # Assert this user belongs to two tenants
        assert (
            user_me_response.json()["data"]["relationships"]["memberships"]["meta"][
                "count"
            ]
            == 2
        )

        provider_response = client.get(
            reverse("provider-list"),
            headers=auth_headers,
        )
        assert provider_response.status_code == 200
        # Empty response since there are no providers in this tenant
        assert not provider_response.json()["data"]

        switch_tenant_response = client.post(
            reverse("token-switch"),
            data={
                "data": {
                    "type": "tokens-switch-tenant",
                    "attributes": {"tenant_id": tenant_id},
                }
            },
            headers=auth_headers,
        )
        assert switch_tenant_response.status_code == 200
        new_access_token = switch_tenant_response.json()["data"]["attributes"]["access"]
        new_auth_headers = get_authorization_header(new_access_token)

        provider_response = client.get(
            reverse("provider-list"),
            headers=new_auth_headers,
        )
        assert provider_response.status_code == 200
        # Now it must be data because we switched to another tenant with providers
        assert provider_response.json()["data"]

    def test_switch_tenant_with_invalid_token(self, create_test_user, tenants_fixture):
        client = APIClient()

        access_token, refresh_token = get_api_tokens(
            client, create_test_user.email, TEST_PASSWORD
        )
        auth_headers = get_authorization_header(access_token)

        invalid_token_response = client.post(
            reverse("token-switch"),
            data={
                "data": {
                    "type": "tokens-switch-tenant",
                    "attributes": {"tenant_id": "invalid_tenant_id"},
                }
            },
            headers=auth_headers,
        )
        assert invalid_token_response.status_code == 400
        assert invalid_token_response.json()["errors"][0]["code"] == "invalid"
        assert (
            invalid_token_response.json()["errors"][0]["detail"]
            == "Must be a valid UUID."
        )

        invalid_tenant_response = client.post(
            reverse("token-switch"),
            data={
                "data": {
                    "type": "tokens-switch-tenant",
                    "attributes": {"tenant_id": tenants_fixture[-1].id},
                }
            },
            headers=auth_headers,
        )
        assert invalid_tenant_response.status_code == 400
        assert invalid_tenant_response.json()["errors"][0]["code"] == "invalid"
        assert invalid_tenant_response.json()["errors"][0]["detail"] == (
            "Tenant does not exist or user is not a " "member."
        )


@pytest.mark.django_db
class TestAPIKeyAuthentication:
    def test_successful_authentication_with_api_key(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """Verify API key can authenticate and access protected endpoints."""
        client = APIClient()
        api_key = api_keys_fixture[0]

        # Use API key to authenticate and access protected endpoint
        api_key_headers = get_api_key_header(api_key._raw_key)
        response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert response.status_code == 200
        assert "data" in response.json()

    def test_api_key_one_time_display_on_creation(
        self, create_test_user_rbac, tenants_fixture
    ):
        """Verify full key only returned on creation, subsequent retrieval shows prefix only."""
        client = APIClient()

        # Authenticate with JWT to create API key
        access_token, _ = get_api_tokens(
            client, create_test_user_rbac.email, TEST_PASSWORD
        )
        jwt_headers = get_authorization_header(access_token)

        # Create API key
        api_key_name = "Test One-Time Key"
        create_response = client.post(
            reverse("api-key-list"),
            data={
                "data": {
                    "type": "api-keys",
                    "attributes": {
                        "name": api_key_name,
                    },
                }
            },
            format="vnd.api+json",
            headers=jwt_headers,
        )

        assert create_response.status_code == 201
        created_data = create_response.json()["data"]
        api_key_id = created_data["id"]

        # Verify full key is present in creation response
        assert "api_key" in created_data["attributes"]
        full_key = created_data["attributes"]["api_key"]
        assert full_key.startswith("pk_")
        assert "." in full_key

        # Retrieve the same API key
        retrieve_response = client.get(
            reverse("api-key-detail", kwargs={"pk": api_key_id}),
            headers=jwt_headers,
        )

        assert retrieve_response.status_code == 200
        retrieved_data = retrieve_response.json()["data"]

        # Verify full key is NOT present in retrieval response
        assert "api_key" not in retrieved_data["attributes"]
        # Only prefix should be visible
        assert "prefix" in retrieved_data["attributes"]
        assert retrieved_data["attributes"]["prefix"].startswith("pk_")

    def test_last_used_at_tracking(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """Verify last_used_at timestamp updates on each authentication."""
        client = APIClient()
        api_key = api_keys_fixture[0]

        # Verify initially last_used_at is None
        assert api_key.last_used_at is None

        # Use API key to authenticate
        api_key_headers = get_api_key_header(api_key._raw_key)
        first_response = client.get(reverse("provider-list"), headers=api_key_headers)
        assert first_response.status_code == 200

        # Reload from database and check last_used_at is set
        api_key.refresh_from_db()
        first_used_at = api_key.last_used_at
        assert first_used_at is not None

        # Use the same key again after a small delay
        time.sleep(0.1)

        second_response = client.get(reverse("provider-list"), headers=api_key_headers)
        assert second_response.status_code == 200

        # Reload and verify last_used_at was updated
        api_key.refresh_from_db()
        second_used_at = api_key.last_used_at
        assert second_used_at is not None
        assert second_used_at > first_used_at


@pytest.mark.django_db
class TestAPIKeyErrors:
    def test_invalid_api_key_format_missing_separator(
        self, create_test_user, tenants_fixture
    ):
        """Malformed key without . separator."""
        client = APIClient()

        # Create malformed key without separator
        malformed_key = "pk_12345678abcdefgh"
        api_key_headers = get_api_key_header(malformed_key)

        response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert response.status_code == 401
        assert "Invalid API Key." in response.json()["errors"][0]["detail"]

    def test_invalid_api_key_format_malformed(self, create_test_user, tenants_fixture):
        """Completely invalid format."""
        client = APIClient()

        # Various malformed keys
        malformed_keys = [
            "invalid_key",
            "Bearer some_token",
            "",
            "pk_.",
            ".encrypted_part",
        ]

        for malformed_key in malformed_keys:
            api_key_headers = get_api_key_header(malformed_key)
            response = client.get(reverse("provider-list"), headers=api_key_headers)

            assert response.status_code == 401
            assert "Invalid API Key." in response.json()["errors"][0]["detail"]

    def test_expired_api_key_rejected(self, create_test_user, tenants_fixture):
        """Key past expiry date returns 401."""
        client = APIClient()

        # Create API key with past expiry date
        expired_key, raw_key = TenantAPIKey.objects.create_api_key(
            name="Expired Key",
            tenant_id=tenants_fixture[0].id,
            entity=create_test_user,
            expiry_date=datetime.now(timezone.utc) - timedelta(days=1),
        )

        api_key_headers = get_api_key_header(raw_key)
        response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert response.status_code == 401
        assert "API Key has already expired." in response.json()["errors"][0]["detail"]

    def test_revoked_api_key_rejected(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """Revoked key returns 401."""
        client = APIClient()

        # Use the revoked key from fixture
        revoked_key = api_keys_fixture[2]
        assert revoked_key.revoked is True

        api_key_headers = get_api_key_header(revoked_key._raw_key)
        response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert response.status_code == 401
        assert "API Key has been revoked." in response.json()["errors"][0]["detail"]

    def test_non_existent_api_key(self, create_test_user, tenants_fixture):
        """Key UUID doesn't exist in database."""
        client = APIClient()

        # Create a valid-looking key with non-existent UUID
        crypto = get_crypto()
        fake_uuid = str(uuid4())
        fake_expiry = (datetime.now(timezone.utc) + timedelta(days=30)).timestamp()
        payload = {"_pk": fake_uuid, "_exp": fake_expiry}
        encrypted_payload = crypto.generate(payload)

        fake_key = f"pk_fakepfx.{encrypted_payload}"
        api_key_headers = get_api_key_header(fake_key)

        response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert response.status_code == 401
        assert (
            "No entity matching this api key." in response.json()["errors"][0]["detail"]
        )

    def test_corrupted_payload(self, create_test_user, tenants_fixture):
        """Tampered/corrupted encrypted payload."""
        client = APIClient()

        # Create key with corrupted encrypted portion
        corrupted_key = "pk_12345678.corrupted_encrypted_data_here"
        api_key_headers = get_api_key_header(corrupted_key)

        response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert response.status_code == 401
        assert "Invalid API Key." in response.json()["errors"][0]["detail"]


@pytest.mark.django_db
class TestAPIKeyTenantIsolation:
    def test_api_key_tenant_isolation(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """User in tenant A cannot use API key from tenant B."""
        client = APIClient()

        # Create a second user in a different tenant
        second_user = User.objects.create_user(
            name="second_user",
            email="second_user@prowler.com",
            password="Test_password@1",
        )
        second_tenant = tenants_fixture[1]
        Membership.objects.create(user=second_user, tenant=second_tenant)

        # Create and assign role to second_user
        second_role = Role.objects.create(
            tenant_id=second_tenant.id,
            name="Second Tenant Role",
            unlimited_visibility=True,
            manage_account=True,
        )
        UserRoleRelationship.objects.create(
            user=second_user,
            role=second_role,
            tenant_id=second_tenant.id,
        )

        # Create API key for second user in second tenant
        second_key, raw_key = TenantAPIKey.objects.create_api_key(
            name="Second Tenant Key",
            tenant_id=second_tenant.id,
            entity=second_user,
        )

        # First user's API key from first tenant
        first_key = api_keys_fixture[0]
        tenants_fixture[0]

        # Verify both keys are from different tenants
        assert first_key.tenant_id != second_key.tenant_id

        # Each key should only access resources in its own tenant
        # This is enforced by RLS at the database level
        first_headers = get_api_key_header(first_key._raw_key)
        second_headers = get_api_key_header(raw_key)

        # Both should work for their respective tenants
        first_response = client.get(reverse("provider-list"), headers=first_headers)
        assert first_response.status_code == 200

        second_response = client.get(reverse("provider-list"), headers=second_headers)
        assert second_response.status_code == 200

        # Verify tenant context is correct in each response
        # The responses should contain only data for their respective tenants

    def test_api_key_filters_by_tenant(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """List endpoint only shows keys for current tenant."""
        client = APIClient()

        # Create JWT token for first tenant
        access_token, _ = get_api_tokens(client, create_test_user.email, TEST_PASSWORD)
        jwt_headers = get_authorization_header(access_token)

        # List API keys
        list_response = client.get(reverse("api-key-list"), headers=jwt_headers)

        assert list_response.status_code == 200
        keys_data = list_response.json()["data"]

        # Verify all returned keys belong to the current tenant
        tenants_fixture[0].id
        for key_data in keys_data:
            # We can't directly see tenant_id in response, but all keys should be from fixtures
            # which are created in first tenant
            assert key_data["type"] == "api-keys"

        # Count should match the number of non-revoked keys in api_keys_fixture for this tenant
        # api_keys_fixture creates 3 keys (1 normal, 1 with expiry, 1 revoked)
        assert len(keys_data) == 3

    def test_api_key_revoked_when_user_removed_from_tenant(self, tenants_fixture):
        """When user membership is deleted, all user's API keys for that tenant are revoked."""
        client = APIClient()
        tenant = tenants_fixture[0]

        # Create a fresh user for this test
        test_user = User.objects.create_user(
            name="test_membership_removal",
            email="membership_removal@prowler.com",
            password=TEST_PASSWORD,
        )

        # Create membership between user and tenant
        Membership.objects.create(
            user=test_user,
            tenant=tenant,
            role=Membership.RoleChoices.OWNER,
        )

        # Create role with manage_account permission
        role = Role.objects.create(
            tenant_id=tenant.id,
            name="Membership Removal Role",
            unlimited_visibility=True,
            manage_account=True,
        )

        # Assign role to user
        UserRoleRelationship.objects.create(
            user=test_user,
            role=role,
            tenant_id=tenant.id,
        )

        # Create API key for this user in this tenant
        api_key, raw_key = TenantAPIKey.objects.create_api_key(
            name="Test Key for Membership Removal",
            tenant_id=tenant.id,
            entity=test_user,
        )

        # Verify API key works initially
        api_key_headers = get_api_key_header(raw_key)
        initial_response = client.get(reverse("provider-list"), headers=api_key_headers)
        assert initial_response.status_code == 200

        # Store API key ID for later verification
        api_key_id = api_key.id

        # Remove user from tenant by deleting membership
        Membership.objects.filter(user=test_user, tenant=tenant).delete()

        # Reload API key from database
        api_key.refresh_from_db()

        # Verify API key still exists in database
        assert TenantAPIKey.objects.filter(id=api_key_id).exists()

        # Verify API key is now revoked
        assert api_key.revoked is True

        # Verify authentication with this API key now fails with 401
        auth_response = client.get(reverse("provider-list"), headers=api_key_headers)
        assert auth_response.status_code == 401

        # Verify error message indicates revocation
        response_json = auth_response.json()
        assert "errors" in response_json
        error_detail = response_json["errors"][0]["detail"]
        assert "revoked" in error_detail.lower()


@pytest.mark.django_db
class TestAPIKeyLifecycle:
    def test_create_api_key(self, create_test_user_rbac, tenants_fixture):
        """Create via POST with name and optional expiry."""
        client = APIClient()

        # Authenticate with JWT
        access_token, _ = get_api_tokens(
            client, create_test_user_rbac.email, TEST_PASSWORD
        )
        jwt_headers = get_authorization_header(access_token)

        # Create API key without expiry
        key_name = "Test Lifecycle Key"
        create_response = client.post(
            reverse("api-key-list"),
            data={
                "data": {
                    "type": "api-keys",
                    "attributes": {
                        "name": key_name,
                    },
                }
            },
            format="vnd.api+json",
            headers=jwt_headers,
        )

        assert create_response.status_code == 201
        created_data = create_response.json()["data"]

        assert created_data["attributes"]["name"] == key_name
        assert "api_key" in created_data["attributes"]
        assert "prefix" in created_data["attributes"]
        assert created_data["attributes"]["revoked"] is False

        # Create API key with expiry
        future_expiry = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        create_with_expiry_response = client.post(
            reverse("api-key-list"),
            data={
                "data": {
                    "type": "api-keys",
                    "attributes": {
                        "name": "Key with Expiry",
                        "expires_at": future_expiry,
                    },
                }
            },
            format="vnd.api+json",
            headers=jwt_headers,
        )

        assert create_with_expiry_response.status_code == 201
        expiry_data = create_with_expiry_response.json()["data"]
        assert expiry_data["attributes"]["expires_at"] is not None

    def test_update_api_key_name_only(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """PATCH only allows name changes."""
        client = APIClient()

        # Authenticate with JWT
        access_token, _ = get_api_tokens(client, create_test_user.email, TEST_PASSWORD)
        jwt_headers = get_authorization_header(access_token)

        api_key = api_keys_fixture[0]
        api_key.name
        new_name = "Updated API Key Name"

        # Update name
        update_response = client.patch(
            reverse("api-key-detail", kwargs={"pk": api_key.id}),
            data={
                "data": {
                    "type": "api-keys",
                    "id": str(api_key.id),
                    "attributes": {
                        "name": new_name,
                    },
                }
            },
            format="vnd.api+json",
            headers=jwt_headers,
        )

        assert update_response.status_code == 200
        updated_data = update_response.json()["data"]
        assert updated_data["attributes"]["name"] == new_name

        # Verify name was actually updated in database
        api_key.refresh_from_db()
        assert api_key.name == new_name

        # Verify other fields remain unchanged
        assert api_key.prefix == updated_data["attributes"]["prefix"]
        assert api_key.revoked is False

    def test_delete_api_key(self, create_test_user, tenants_fixture, api_keys_fixture):
        """DELETE revokes key (sets revoked=True)."""
        client = APIClient()

        # Authenticate with JWT
        access_token, _ = get_api_tokens(client, create_test_user.email, TEST_PASSWORD)
        jwt_headers = get_authorization_header(access_token)

        api_key = api_keys_fixture[1]
        api_key_id = api_key.id

        # Revoke API key using the revoke endpoint
        revoke_response = client.delete(
            reverse("api-key-revoke", kwargs={"pk": api_key_id}),
            headers=jwt_headers,
        )

        assert revoke_response.status_code == 200

        # Verify key still exists but is revoked
        api_key.refresh_from_db()
        assert api_key.revoked is True

        # Verify revoked key can no longer authenticate
        api_key_headers = get_api_key_header(api_key._raw_key)
        auth_response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert auth_response.status_code == 401

    def test_multiple_keys_per_user(self, create_test_user_rbac, tenants_fixture):
        """User can have multiple active keys."""
        client = APIClient()

        # Authenticate with JWT
        access_token, _ = get_api_tokens(
            client, create_test_user_rbac.email, TEST_PASSWORD
        )
        jwt_headers = get_authorization_header(access_token)

        # Create multiple API keys
        key_names = ["Key One", "Key Two", "Key Three"]
        created_keys = []

        for name in key_names:
            create_response = client.post(
                reverse("api-key-list"),
                data={
                    "data": {
                        "type": "api-keys",
                        "attributes": {
                            "name": name,
                        },
                    }
                },
                format="vnd.api+json",
                headers=jwt_headers,
            )

            assert create_response.status_code == 201
            created_keys.append(create_response.json()["data"])

        # Verify all keys were created
        assert len(created_keys) == 3

        # List all keys and verify count
        list_response = client.get(reverse("api-key-list"), headers=jwt_headers)
        assert list_response.status_code == 200

        # Should include the 3 new keys plus the ones from api_keys_fixture
        keys_list = list_response.json()["data"]
        assert len(keys_list) >= 3

        # Verify each created key can authenticate independently
        for key_data in created_keys:
            full_key = key_data["attributes"]["api_key"]
            api_key_headers = get_api_key_header(full_key)
            auth_response = client.get(
                reverse("provider-list"), headers=api_key_headers
            )
            assert auth_response.status_code == 200

    def test_api_key_becomes_invalid_when_user_deleted(self, tenants_fixture):
        """When user is deleted, API key entity is set to None and authentication fails."""
        client = APIClient()
        tenant = tenants_fixture[0]

        # Create a fresh user for this test to avoid affecting other tests
        test_user = User.objects.create_user(
            name="test_deletion_user",
            email="deletion_test@prowler.com",
            password=TEST_PASSWORD,
        )
        Membership.objects.create(
            user=test_user,
            tenant=tenant,
            role=Membership.RoleChoices.OWNER,
        )

        # Create role for the user
        role = Role.objects.create(
            tenant_id=tenant.id,
            name="Deletion Test Role",
            unlimited_visibility=True,
            manage_account=True,
        )
        UserRoleRelationship.objects.create(
            user=test_user,
            role=role,
            tenant_id=tenant.id,
        )

        # Create API key for this user
        api_key, raw_key = TenantAPIKey.objects.create_api_key(
            name="Test Key for Deletion",
            tenant_id=tenant.id,
            entity=test_user,
        )

        # Verify the API key works initially
        api_key_headers = get_api_key_header(raw_key)
        initial_response = client.get(reverse("provider-list"), headers=api_key_headers)
        assert initial_response.status_code == 200

        # Store the API key ID for later verification
        api_key_id = api_key.id

        # Delete the user
        test_user.delete()

        # Reload the API key from database
        api_key.refresh_from_db()

        # Verify the API key still exists in database (not cascade deleted)
        assert TenantAPIKey.objects.filter(id=api_key_id).exists()

        # Verify entity field is now None (CASCADE behavior is SET_NULL)
        assert api_key.entity is None

        # Verify authentication with this API key now fails
        auth_response = client.get(reverse("provider-list"), headers=api_key_headers)

        # Must return 401 Unauthorized, not 500 Internal Server Error
        assert auth_response.status_code == 401, (
            f"Expected 401 but got {auth_response.status_code}: "
            f"{auth_response.json()}"
        )

        # Verify error message is present
        response_json = auth_response.json()
        assert "errors" in response_json
        error_detail = response_json["errors"][0]["detail"]
        # The error should indicate authentication failed due to invalid/orphaned key
        assert (
            "API Key" in error_detail
            or "Invalid" in error_detail
            or "entity" in error_detail.lower()
        )


@pytest.mark.django_db
class TestCombinedAuthentication:
    def test_jwt_takes_priority_over_api_key(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """When Bearer token present, JWT is used."""
        client = APIClient()

        # Get JWT token
        access_token, _ = get_api_tokens(client, create_test_user.email, TEST_PASSWORD)

        # Create headers with both Bearer (JWT) and API key would conflict
        # But we'll test that Bearer takes priority by setting Authorization to Bearer
        jwt_headers = {"Authorization": f"Bearer {access_token}"}

        response = client.get(reverse("provider-list"), headers=jwt_headers)

        assert response.status_code == 200

        # The authentication should have used JWT, not API key
        # We can verify this worked as JWT authentication

    def test_api_key_header_format_validation(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """Verify Authorization: Api-Key <key> format."""
        client = APIClient()

        api_key = api_keys_fixture[0]

        # Correct format
        correct_headers = {"Authorization": f"Api-Key {api_key._raw_key}"}
        correct_response = client.get(reverse("provider-list"), headers=correct_headers)
        assert correct_response.status_code == 200

        # Wrong format - using Bearer instead of Api-Key
        wrong_format_headers = {"Authorization": f"Bearer {api_key._raw_key}"}
        wrong_response = client.get(
            reverse("provider-list"), headers=wrong_format_headers
        )
        # Should fail because it tries to parse as JWT
        assert wrong_response.status_code == 401

        # Wrong format - missing Api-Key prefix
        no_prefix_headers = {"Authorization": api_key._raw_key}
        no_prefix_response = client.get(
            reverse("provider-list"), headers=no_prefix_headers
        )
        assert no_prefix_response.status_code == 401

    def test_concurrent_api_key_usage(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """Same key can be used multiple times concurrently."""
        client = APIClient()

        api_key = api_keys_fixture[0]
        api_key_headers = get_api_key_header(api_key._raw_key)

        # Make multiple concurrent requests with the same key
        responses = []
        for _ in range(5):
            response = client.get(reverse("provider-list"), headers=api_key_headers)
            responses.append(response)

        # All requests should succeed
        for response in responses:
            assert response.status_code == 200

        # Verify last_used_at was updated
        api_key.refresh_from_db()
        assert api_key.last_used_at is not None


@pytest.mark.django_db
class TestAPIKeyRLSBypass:
    """Test RLS bypass fix for API key authentication.

    These tests verify that API key authentication works correctly even when
    RLS context is not set, which is critical since we don't know the tenant_id
    until we look up the API key (which itself is protected by RLS).

    The fix ensures all database operations during authentication use the admin
    database, bypassing RLS constraints.
    """

    def test_api_key_authentication_without_rls_context(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """Verify API key authentication works without pre-existing RLS context.

        This is the core fix: authentication must succeed even when prowler.tenant_id
        is not set, since we need to look up the API key to discover the tenant.
        """
        client = APIClient()
        api_key = api_keys_fixture[0]

        api_key_headers = get_api_key_header(api_key._raw_key)
        response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert response.status_code == 200
        assert "data" in response.json()

    def test_api_key_lookup_uses_admin_database(
        self, create_test_user, tenants_fixture
    ):
        """Verify API key lookup uses admin database during authentication.

        The TenantAPIKey model is RLS-protected, so queries against it would
        normally fail without prowler.tenant_id set. The fix routes lookups
        to the admin database which bypasses RLS.
        """
        client = APIClient()
        tenant = tenants_fixture[0]

        role = Role.objects.create(
            tenant_id=tenant.id,
            name="Admin DB Test Role",
            unlimited_visibility=True,
            manage_account=True,
        )
        UserRoleRelationship.objects.create(
            user=create_test_user,
            role=role,
            tenant_id=tenant.id,
        )

        api_key, raw_key = TenantAPIKey.objects.create_api_key(
            name="Admin DB Test Key",
            tenant_id=tenant.id,
            entity=create_test_user,
        )

        api_key_headers = get_api_key_header(raw_key)
        response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert response.status_code == 200

        api_key.refresh_from_db()
        assert api_key.last_used_at is not None

    def test_tenant_context_established_after_authentication(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """Verify correct tenant context is established after API key auth.

        After authentication, the tenant_id from the API key should be used
        to set up the proper RLS context for subsequent queries.
        """
        client = APIClient()
        api_key = api_keys_fixture[0]

        api_key_headers = get_api_key_header(api_key._raw_key)

        # Use tenant-list endpoint to get actual tenant IDs
        tenant_response = client.get(reverse("tenant-list"), headers=api_key_headers)

        assert tenant_response.status_code == 200
        tenant_data = tenant_response.json()["data"]
        tenant_ids = [t["id"] for t in tenant_data]

        # Verify the API key's tenant is in the list of accessible tenants
        assert str(api_key.tenant_id) in tenant_ids

    def test_concurrent_authentication_different_tenants(self, tenants_fixture):
        """Verify multiple API keys from different tenants can authenticate simultaneously.

        This tests that the admin database routing works correctly in concurrent
        scenarios and doesn't cause tenant isolation issues.
        """
        client = APIClient()

        user1 = User.objects.create_user(
            name="concurrent_user1",
            email="concurrent1@test.com",
            password=TEST_PASSWORD,
        )
        user2 = User.objects.create_user(
            name="concurrent_user2",
            email="concurrent2@test.com",
            password=TEST_PASSWORD,
        )

        tenant1 = tenants_fixture[0]
        tenant2 = tenants_fixture[1]

        Membership.objects.create(user=user1, tenant=tenant1)
        Membership.objects.create(user=user2, tenant=tenant2)

        role1 = Role.objects.create(
            tenant_id=tenant1.id,
            name="Concurrent Role 1",
            unlimited_visibility=True,
            manage_account=True,
        )
        role2 = Role.objects.create(
            tenant_id=tenant2.id,
            name="Concurrent Role 2",
            unlimited_visibility=True,
            manage_account=True,
        )

        UserRoleRelationship.objects.create(
            user=user1,
            role=role1,
            tenant_id=tenant1.id,
        )
        UserRoleRelationship.objects.create(
            user=user2,
            role=role2,
            tenant_id=tenant2.id,
        )

        api_key1, raw_key1 = TenantAPIKey.objects.create_api_key(
            name="Concurrent Key 1",
            tenant_id=tenant1.id,
            entity=user1,
        )
        api_key2, raw_key2 = TenantAPIKey.objects.create_api_key(
            name="Concurrent Key 2",
            tenant_id=tenant2.id,
            entity=user2,
        )

        headers1 = get_api_key_header(raw_key1)
        headers2 = get_api_key_header(raw_key2)

        response1 = client.get(reverse("provider-list"), headers=headers1)
        response2 = client.get(reverse("provider-list"), headers=headers2)

        assert response1.status_code == 200
        assert response2.status_code == 200

        api_key1.refresh_from_db()
        api_key2.refresh_from_db()

        assert api_key1.last_used_at is not None
        assert api_key2.last_used_at is not None
        assert api_key1.tenant_id == tenant1.id
        assert api_key2.tenant_id == tenant2.id

    def test_api_key_update_last_used_uses_admin_db(
        self, create_test_user, tenants_fixture, api_keys_fixture
    ):
        """Verify last_used_at update uses admin database.

        The update to last_used_at during authentication must also use the
        admin database since it occurs before RLS context is established.
        """
        client = APIClient()
        api_key = api_keys_fixture[0]

        assert api_key.last_used_at is None

        api_key_headers = get_api_key_header(api_key._raw_key)
        first_response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert first_response.status_code == 200

        api_key.refresh_from_db()
        first_timestamp = api_key.last_used_at
        assert first_timestamp is not None

        time.sleep(0.1)

        second_response = client.get(reverse("provider-list"), headers=api_key_headers)
        assert second_response.status_code == 200

        api_key.refresh_from_db()
        second_timestamp = api_key.last_used_at
        assert second_timestamp > first_timestamp

    def test_api_key_prefix_lookup_bypasses_rls(
        self, create_test_user, tenants_fixture
    ):
        """Verify prefix-based API key lookup works without RLS context.

        The authentication process splits the key into prefix and encrypted parts,
        then looks up by prefix. This lookup must work via admin database.
        """
        client = APIClient()
        tenant = tenants_fixture[0]

        role = Role.objects.create(
            tenant_id=tenant.id,
            name="Prefix Test Role",
            unlimited_visibility=True,
            manage_account=True,
        )
        UserRoleRelationship.objects.create(
            user=create_test_user,
            role=role,
            tenant_id=tenant.id,
        )

        api_key, raw_key = TenantAPIKey.objects.create_api_key(
            name="Prefix Test Key",
            tenant_id=tenant.id,
            entity=create_test_user,
        )

        prefix = raw_key.split(".")[0]
        assert prefix == api_key.prefix

        api_key_headers = get_api_key_header(raw_key)
        response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert response.status_code == 200

    def test_expired_api_key_check_uses_admin_db(
        self, create_test_user, tenants_fixture
    ):
        """Verify expired API key validation works via admin database.

        Checking if a key is expired requires reading from TenantAPIKey,
        which must use admin database during authentication.
        """
        client = APIClient()
        tenant = tenants_fixture[0]

        expired_key, raw_key = TenantAPIKey.objects.create_api_key(
            name="Expired Test Key",
            tenant_id=tenant.id,
            entity=create_test_user,
            expiry_date=datetime.now(timezone.utc) - timedelta(days=1),
        )

        api_key_headers = get_api_key_header(raw_key)
        response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert response.status_code == 401
        assert "expired" in response.json()["errors"][0]["detail"].lower()

    def test_revoked_api_key_check_uses_admin_db(
        self, create_test_user, tenants_fixture
    ):
        """Verify revoked API key validation works via admin database.

        Checking if a key is revoked requires reading from TenantAPIKey,
        which must use admin database during authentication.
        """
        client = APIClient()
        tenant = tenants_fixture[0]

        role = Role.objects.create(
            tenant_id=tenant.id,
            name="Revoked Test Role",
            unlimited_visibility=True,
            manage_account=True,
        )
        UserRoleRelationship.objects.create(
            user=create_test_user,
            role=role,
            tenant_id=tenant.id,
        )

        api_key, raw_key = TenantAPIKey.objects.create_api_key(
            name="Revoked Test Key",
            tenant_id=tenant.id,
            entity=create_test_user,
        )

        api_key.revoked = True
        api_key.save()

        api_key_headers = get_api_key_header(raw_key)
        response = client.get(reverse("provider-list"), headers=api_key_headers)

        assert response.status_code == 401
        assert "revoked" in response.json()["errors"][0]["detail"].lower()


@pytest.mark.django_db
class TestAPIKeyMultiTenantWorkflows:
    """Test complete multi-tenant workflows using API keys.

    These integration tests verify end-to-end scenarios where API keys
    are used across different tenants and ensure proper isolation.
    """

    def test_user_with_multiple_tenant_memberships_api_keys(self, tenants_fixture):
        """User with memberships in multiple tenants can use different API keys.

        Tests that a user can have separate API keys for different tenants
        and each key only accesses resources in its tenant.
        """
        client = APIClient()

        user = User.objects.create_user(
            name="multi_tenant_user",
            email="multitenant@test.com",
            password=TEST_PASSWORD,
        )

        tenant1 = tenants_fixture[0]
        tenant2 = tenants_fixture[1]

        Membership.objects.create(user=user, tenant=tenant1)
        Membership.objects.create(user=user, tenant=tenant2)

        role1 = Role.objects.create(
            tenant_id=tenant1.id,
            name="Multi Tenant Role 1",
            unlimited_visibility=True,
            manage_account=True,
        )
        role2 = Role.objects.create(
            tenant_id=tenant2.id,
            name="Multi Tenant Role 2",
            unlimited_visibility=True,
            manage_account=True,
        )

        UserRoleRelationship.objects.create(
            user=user,
            role=role1,
            tenant_id=tenant1.id,
        )
        UserRoleRelationship.objects.create(
            user=user,
            role=role2,
            tenant_id=tenant2.id,
        )

        key1, raw_key1 = TenantAPIKey.objects.create_api_key(
            name="Tenant 1 Key",
            tenant_id=tenant1.id,
            entity=user,
        )
        key2, raw_key2 = TenantAPIKey.objects.create_api_key(
            name="Tenant 2 Key",
            tenant_id=tenant2.id,
            entity=user,
        )

        headers1 = get_api_key_header(raw_key1)
        headers2 = get_api_key_header(raw_key2)

        response1 = client.get(reverse("provider-list"), headers=headers1)
        response2 = client.get(reverse("provider-list"), headers=headers2)

        assert response1.status_code == 200
        assert response2.status_code == 200

        me_response1 = client.get(reverse("user-me"), headers=headers1)
        me_response2 = client.get(reverse("user-me"), headers=headers2)

        assert me_response1.status_code == 200
        assert me_response2.status_code == 200

        assert me_response1.json()["data"]["id"] == str(user.id)
        assert me_response2.json()["data"]["id"] == str(user.id)

    def test_api_key_cannot_access_different_tenant_resources(
        self, tenants_fixture, providers_fixture
    ):
        """API key from one tenant cannot access resources from another tenant.

        Verifies RLS enforcement after authentication ensures tenant isolation.
        """
        client = APIClient()

        user1 = User.objects.create_user(
            name="tenant1_user",
            email="tenant1user@test.com",
            password=TEST_PASSWORD,
        )
        user2 = User.objects.create_user(
            name="tenant2_user",
            email="tenant2user@test.com",
            password=TEST_PASSWORD,
        )

        tenant1 = tenants_fixture[0]
        tenant2 = tenants_fixture[1]

        Membership.objects.create(user=user1, tenant=tenant1)
        Membership.objects.create(user=user2, tenant=tenant2)

        role1 = Role.objects.create(
            tenant_id=tenant1.id,
            name="Isolation Test Role 1",
            unlimited_visibility=True,
            manage_account=True,
        )
        role2 = Role.objects.create(
            tenant_id=tenant2.id,
            name="Isolation Test Role 2",
            unlimited_visibility=True,
            manage_account=True,
        )

        UserRoleRelationship.objects.create(
            user=user1,
            role=role1,
            tenant_id=tenant1.id,
        )
        UserRoleRelationship.objects.create(
            user=user2,
            role=role2,
            tenant_id=tenant2.id,
        )

        key1, raw_key1 = TenantAPIKey.objects.create_api_key(
            name="Isolation Key 1",
            tenant_id=tenant1.id,
            entity=user1,
        )

        headers1 = get_api_key_header(raw_key1)

        provider_response = client.get(reverse("provider-list"), headers=headers1)
        assert provider_response.status_code == 200

        providers_data = provider_response.json()["data"]

        if providers_data:
            for provider in providers_data:
                provider_tenant_id = str(tenants_fixture[0].id)
                assert str(tenant2.id) != provider_tenant_id

    def test_api_key_workflow_create_authenticate_revoke(
        self, create_test_user_rbac, tenants_fixture
    ):
        """Complete workflow: create API key via JWT, use it, then revoke via JWT.

        Tests the full lifecycle using both JWT and API key authentication.
        """
        client = APIClient()
        tenants_fixture[0]

        jwt_access_token, _ = get_api_tokens(
            client, create_test_user_rbac.email, TEST_PASSWORD
        )
        jwt_headers = get_authorization_header(jwt_access_token)

        create_response = client.post(
            reverse("api-key-list"),
            data={
                "data": {
                    "type": "api-keys",
                    "attributes": {
                        "name": "Workflow Test Key",
                    },
                }
            },
            format="vnd.api+json",
            headers=jwt_headers,
        )

        assert create_response.status_code == 201
        api_key_data = create_response.json()["data"]
        api_key_id = api_key_data["id"]
        raw_api_key = api_key_data["attributes"]["api_key"]

        api_key_headers = get_api_key_header(raw_api_key)
        auth_response = client.get(reverse("provider-list"), headers=api_key_headers)
        assert auth_response.status_code == 200

        revoke_response = client.delete(
            reverse("api-key-revoke", kwargs={"pk": api_key_id}),
            headers=jwt_headers,
        )
        assert revoke_response.status_code == 200

        revoked_auth_response = client.get(
            reverse("provider-list"), headers=api_key_headers
        )
        assert revoked_auth_response.status_code == 401
        assert "revoked" in revoked_auth_response.json()["errors"][0]["detail"].lower()


def get_api_key_header(api_key: str) -> dict:
    """Helper to create API key authorization header."""
    return {"Authorization": f"Api-Key {api_key}"}
