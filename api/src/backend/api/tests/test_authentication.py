import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.test import RequestFactory
from rest_framework.exceptions import AuthenticationFailed

from api.authentication import TenantAPIKeyAuthentication
from api.db_router import MainRouter
from api.models import TenantAPIKey


@pytest.mark.django_db
class TestTenantAPIKeyAuthentication:
    @pytest.fixture
    def auth_backend(self):
        """Create an instance of TenantAPIKeyAuthentication."""
        return TenantAPIKeyAuthentication()

    @pytest.fixture
    def request_factory(self):
        """Create a Django request factory."""
        return RequestFactory()

    def test_authenticate_credentials_uses_admin_database(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test that _authenticate_credentials routes queries to admin database."""
        api_key = api_keys_fixture[0]
        raw_key = api_key._raw_key

        # Extract the encrypted key part (after the prefix and separator)
        _, encrypted_key = raw_key.split(TenantAPIKey.objects.separator, 1)

        # Create a mock request
        request = request_factory.get("/")

        # Call the method
        entity, auth_dict = auth_backend._authenticate_credentials(
            request, encrypted_key
        )

        # Verify that the entity is the user associated with the API key
        assert entity == api_key.entity
        assert entity.id == api_key.entity.id

    def test_authenticate_credentials_restores_manager_on_success(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test that the manager is restored after successful authentication."""
        api_key = api_keys_fixture[0]
        raw_key = api_key._raw_key
        _, encrypted_key = raw_key.split(TenantAPIKey.objects.separator, 1)

        # Store the original manager
        original_manager = TenantAPIKey.objects

        request = request_factory.get("/")

        # Call the method
        auth_backend._authenticate_credentials(request, encrypted_key)

        # Verify the manager was restored
        assert TenantAPIKey.objects == original_manager

    def test_authenticate_credentials_restores_manager_on_exception(
        self, auth_backend, request_factory
    ):
        """Test that the manager is restored even when an exception occurs."""
        # Store the original manager
        original_manager = TenantAPIKey.objects

        request = request_factory.get("/")

        # Try to authenticate with an invalid key that will raise an exception
        with pytest.raises(Exception):
            auth_backend._authenticate_credentials(request, "invalid_encrypted_key")

        # Verify the manager was restored despite the exception
        assert TenantAPIKey.objects == original_manager

    def test_authenticate_valid_api_key(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test successful authentication with a valid API key."""
        api_key = api_keys_fixture[0]
        raw_key = api_key._raw_key

        # Create a request with the API key in the Authorization header
        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Api-Key {raw_key}"

        # Authenticate
        entity, auth_dict = auth_backend.authenticate(request)

        # Verify the entity and auth dict
        assert entity == api_key.entity
        assert auth_dict["tenant_id"] == str(api_key.tenant_id)
        assert auth_dict["sub"] == str(api_key.entity.id)
        assert auth_dict["api_key_prefix"] == api_key.prefix

        # Verify that last_used_at was updated
        api_key.refresh_from_db()
        assert api_key.last_used_at is not None
        assert (datetime.now(timezone.utc) - api_key.last_used_at).seconds < 5

    def test_authenticate_valid_api_key_uses_admin_database(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test that authenticate uses admin database for API key lookup."""
        api_key = api_keys_fixture[0]
        raw_key = api_key._raw_key

        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Api-Key {raw_key}"

        # Mock the manager's using method to verify it's called with admin_db
        with patch.object(
            TenantAPIKey.objects, "using", wraps=TenantAPIKey.objects.using
        ) as mock_using:
            auth_backend.authenticate(request)

            # Verify that .using('admin') was called
            mock_using.assert_called_with(MainRouter.admin_db)

    def test_authenticate_invalid_key_format_missing_separator(
        self, auth_backend, request_factory
    ):
        """Test authentication fails with invalid API key format (no separator)."""
        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = "Api-Key invalid_key_no_separator"

        with pytest.raises(AuthenticationFailed) as exc_info:
            auth_backend.authenticate(request)

        assert str(exc_info.value.detail) == "Invalid API Key."

    def test_authenticate_invalid_key_format_empty_prefix(
        self, auth_backend, request_factory
    ):
        """Test authentication fails with empty prefix."""
        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = "Api-Key .encrypted_part"

        with pytest.raises(AuthenticationFailed) as exc_info:
            auth_backend.authenticate(request)

        assert str(exc_info.value.detail) == "Invalid API Key."

    def test_authenticate_invalid_encrypted_key(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test authentication fails with invalid encrypted key."""
        api_key = api_keys_fixture[0]

        # Create an invalid key with valid prefix but invalid encryption
        invalid_key = f"{api_key.prefix}.invalid_encrypted_data"

        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Api-Key {invalid_key}"

        with pytest.raises(AuthenticationFailed) as exc_info:
            auth_backend.authenticate(request)

        assert str(exc_info.value.detail) == "Invalid API Key."

    def test_authenticate_revoked_api_key(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test authentication fails with a revoked API key."""
        # Use the revoked API key (index 2 from fixture)
        api_key = api_keys_fixture[2]
        raw_key = api_key._raw_key

        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Api-Key {raw_key}"

        # The revoked key should fail during credential validation
        with pytest.raises(AuthenticationFailed) as exc_info:
            auth_backend.authenticate(request)

        assert str(exc_info.value.detail) == "This API Key has been revoked."

    def test_authenticate_expired_api_key(
        self, auth_backend, create_test_user, tenants_fixture, request_factory
    ):
        """Test authentication fails with an expired API key."""
        tenant = tenants_fixture[0]
        user = create_test_user

        # Create an expired API key
        api_key, raw_key = TenantAPIKey.objects.create_api_key(
            name="Expired API Key",
            tenant_id=tenant.id,
            entity=user,
            expiry_date=datetime.now(timezone.utc) - timedelta(days=1),
        )

        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Api-Key {raw_key}"

        with pytest.raises(AuthenticationFailed) as exc_info:
            auth_backend.authenticate(request)

        assert str(exc_info.value.detail) == "API Key has already expired."

    def test_authenticate_nonexistent_api_key(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test authentication fails when API key doesn't exist in database."""
        # Create a valid-looking encrypted key with a non-existent UUID
        api_key = api_keys_fixture[0]
        non_existent_uuid = str(uuid4())

        # Manually create an encrypted key with a non-existent ID
        payload = {
            "_pk": non_existent_uuid,
            "_exp": (datetime.now(timezone.utc) + timedelta(days=30)).timestamp(),
        }
        encrypted_key = auth_backend.key_crypto.generate(payload)
        fake_key = f"{api_key.prefix}.{encrypted_key}"

        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Api-Key {fake_key}"

        with pytest.raises(AuthenticationFailed) as exc_info:
            auth_backend.authenticate(request)

        assert str(exc_info.value.detail) == "No entity matching this api key."

    def test_authenticate_updates_last_used_at(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test that last_used_at is updated on successful authentication."""
        api_key = api_keys_fixture[0]
        raw_key = api_key._raw_key

        # Store the original last_used_at
        original_last_used = api_key.last_used_at

        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Api-Key {raw_key}"

        # Authenticate
        auth_backend.authenticate(request)

        # Refresh from database
        api_key.refresh_from_db()

        # Verify last_used_at was updated
        assert api_key.last_used_at is not None
        if original_last_used:
            assert api_key.last_used_at > original_last_used

    def test_authenticate_saves_to_admin_database(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test that the API key save operation uses admin database."""
        api_key = api_keys_fixture[0]
        raw_key = api_key._raw_key

        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Api-Key {raw_key}"

        # Mock the save method to verify it's called with using='admin'
        with patch.object(TenantAPIKey, "save") as mock_save:
            auth_backend.authenticate(request)

            # Verify save was called with using=admin_db
            mock_save.assert_called_once_with(
                update_fields=["last_used_at"], using=MainRouter.admin_db
            )

    def test_authenticate_returns_correct_auth_dict(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test that the auth dict contains all required fields."""
        api_key = api_keys_fixture[0]
        raw_key = api_key._raw_key

        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Api-Key {raw_key}"

        entity, auth_dict = auth_backend.authenticate(request)

        # Verify all required fields are present
        assert "tenant_id" in auth_dict
        assert "sub" in auth_dict
        assert "api_key_prefix" in auth_dict

        # Verify values are correct
        assert auth_dict["tenant_id"] == str(api_key.tenant_id)
        assert auth_dict["sub"] == str(api_key.entity.id)
        assert auth_dict["api_key_prefix"] == api_key.prefix

    def test_authenticate_with_multiple_api_keys_same_tenant(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test that authentication works correctly with multiple API keys for the same tenant."""
        # Test with first API key
        api_key1 = api_keys_fixture[0]
        raw_key1 = api_key1._raw_key

        request1 = request_factory.get("/")
        request1.META["HTTP_AUTHORIZATION"] = f"Api-Key {raw_key1}"

        entity1, auth_dict1 = auth_backend.authenticate(request1)

        assert entity1 == api_key1.entity
        assert auth_dict1["api_key_prefix"] == api_key1.prefix

        # Test with second API key
        api_key2 = api_keys_fixture[1]
        raw_key2 = api_key2._raw_key

        request2 = request_factory.get("/")
        request2.META["HTTP_AUTHORIZATION"] = f"Api-Key {raw_key2}"

        entity2, auth_dict2 = auth_backend.authenticate(request2)

        assert entity2 == api_key2.entity
        assert auth_dict2["api_key_prefix"] == api_key2.prefix

        # Verify they're different keys but same tenant
        assert auth_dict1["api_key_prefix"] != auth_dict2["api_key_prefix"]
        assert auth_dict1["tenant_id"] == auth_dict2["tenant_id"]

    def test_authenticate_with_wrong_prefix_in_db(
        self, auth_backend, api_keys_fixture, request_factory
    ):
        """Test authentication fails when prefix doesn't match database."""
        api_key = api_keys_fixture[0]
        raw_key = api_key._raw_key

        # Extract the encrypted part and combine with wrong prefix
        _, encrypted_part = raw_key.split(TenantAPIKey.objects.separator, 1)
        wrong_key = f"pk_wrong123.{encrypted_part}"

        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Api-Key {wrong_key}"

        with pytest.raises(AuthenticationFailed) as exc_info:
            auth_backend.authenticate(request)

        assert str(exc_info.value.detail) == "Invalid API Key."

    def test_authenticate_credentials_exception_handling(
        self, auth_backend, request_factory
    ):
        """Test that exceptions in _authenticate_credentials are properly handled."""
        request = request_factory.get("/")

        # Test with completely invalid data that will cause InvalidToken
        with pytest.raises(Exception):
            auth_backend._authenticate_credentials(request, "completely_invalid")

    def test_authenticate_with_expired_timestamp(
        self, auth_backend, create_test_user, tenants_fixture, request_factory
    ):
        """Test that expired timestamp in encrypted key causes authentication failure."""
        tenant = tenants_fixture[0]
        user = create_test_user

        # Create an API key with a very short expiry
        api_key, raw_key = TenantAPIKey.objects.create_api_key(
            name="Short-lived API Key",
            tenant_id=tenant.id,
            entity=user,
            expiry_date=datetime.now(timezone.utc) + timedelta(seconds=1),
        )

        # Wait for the key to expire
        time.sleep(2)

        request = request_factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Api-Key {raw_key}"

        # Should fail with expired key
        with pytest.raises(AuthenticationFailed) as exc_info:
            auth_backend.authenticate(request)

        assert str(exc_info.value.detail) == "API Key has already expired."
