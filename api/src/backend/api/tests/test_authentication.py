"""
Tests for API Key Authentication functionality.
"""

import pytest
from unittest.mock import patch
from django.test import RequestFactory
from django.utils import timezone
from datetime import timedelta
from rest_framework import exceptions

from api.authentication import APIKeyAuthentication
from api.models import APIKey, APIKeyUser, Tenant


@pytest.mark.django_db
class TestAPIKeyAuthentication:
    """Test comprehensive API key authentication functionality."""

    @pytest.fixture
    def auth_instance(self):
        """Create an APIKeyAuthentication instance for testing."""
        return APIKeyAuthentication()

    @pytest.fixture
    def request_factory(self):
        """Create a Django request factory for testing."""
        return RequestFactory()

    @pytest.fixture
    def tenant(self):
        """Create a test tenant."""
        return Tenant.objects.create(name="Test Tenant")

    @pytest.fixture
    def valid_api_key(self, tenant):
        """Create a valid API key for testing."""
        raw_key = APIKey.generate_key()
        prefix = APIKey.extract_prefix(raw_key)
        key_hash = APIKey.hash_key(raw_key)

        api_key = APIKey.objects.create(
            name="Test API Key",
            tenant_id=tenant.id,
            key_hash=key_hash,
            prefix=prefix,
            expiry_date=None,
            revoked=False,
        )

        # Store the raw key for testing
        api_key._raw_key = raw_key
        return api_key

    def test_authenticate_no_header(self, auth_instance, request_factory):
        """Test authentication with no authorization header."""
        request = request_factory.get("/api/v1/test")
        result = auth_instance.authenticate(request)
        assert result is None

    def test_authenticate_wrong_auth_type(self, auth_instance, request_factory):
        """Test authentication with wrong authorization type."""
        request = request_factory.get("/api/v1/test")
        request.META["HTTP_AUTHORIZATION"] = "Bearer some-token"
        result = auth_instance.authenticate(request)
        assert result is None

    def test_authenticate_invalid_header_format(self, auth_instance, request_factory):
        """Test authentication with malformed authorization header."""
        request = request_factory.get("/api/v1/test")
        request.META["HTTP_AUTHORIZATION"] = "ApiKey"  # Missing key part
        result = auth_instance.authenticate(request)
        assert result is None

    def test_authenticate_credentials_invalid_format(
        self, auth_instance, request_factory
    ):
        """Test authentication with invalid API key format."""
        request = request_factory.get("/api/v1/test")

        with pytest.raises(exceptions.AuthenticationFailed) as exc_info:
            auth_instance.authenticate_credentials("invalid-key", request)

        assert "Invalid API key format" in str(exc_info.value)

    def test_authenticate_credentials_key_not_found(
        self, auth_instance, request_factory
    ):
        """Test authentication with non-existent API key."""
        request = request_factory.get("/api/v1/test")
        # Use valid format but non-existent key
        fake_key = "pk_12345678.abcdefghijklmnopqrstuvwxyz123456"

        with pytest.raises(exceptions.AuthenticationFailed) as exc_info:
            auth_instance.authenticate_credentials(fake_key, request)

        assert "Invalid API key" in str(exc_info.value)

    def test_authenticate_credentials_revoked_key(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test authentication with revoked API key."""
        request = request_factory.get("/api/v1/test")

        # Revoke the key
        valid_api_key.revoke()

        with pytest.raises(exceptions.AuthenticationFailed) as exc_info:
            auth_instance.authenticate_credentials(valid_api_key._raw_key, request)

        assert "revoked" in str(exc_info.value)

    def test_authenticate_credentials_expired_key(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test authentication with expired API key."""
        request = request_factory.get("/api/v1/test")

        # Set key to be expired
        valid_api_key.expiry_date = timezone.now() - timedelta(days=1)
        valid_api_key.save()

        with pytest.raises(exceptions.AuthenticationFailed) as exc_info:
            auth_instance.authenticate_credentials(valid_api_key._raw_key, request)

        assert "expired" in str(exc_info.value)

    def test_authenticate_credentials_wrong_password(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test authentication with wrong key (correct prefix, wrong hash)."""
        request = request_factory.get("/api/v1/test")

        # Create a fake key with the same prefix but different suffix
        prefix = APIKey.extract_prefix(valid_api_key._raw_key)
        fake_key = f"pk_{prefix}.wrongsuffixhere123456789012345"

        with pytest.raises(exceptions.AuthenticationFailed) as exc_info:
            auth_instance.authenticate_credentials(fake_key, request)

        assert "Invalid API key" in str(exc_info.value)

    def test_authenticate_credentials_valid_key(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test successful authentication with valid key."""
        request = request_factory.get("/api/v1/test")

        user, auth_info = auth_instance.authenticate_credentials(
            valid_api_key._raw_key, request
        )

        # Check returned user and auth info
        assert isinstance(user, APIKeyUser)
        assert user.api_key_id == str(valid_api_key.id)
        assert user.api_key_name == valid_api_key.name
        assert user.tenant_id == str(valid_api_key.tenant_id)
        assert user.is_authenticated
        assert not user.is_anonymous
        assert user.is_active

        assert auth_info["api_key_id"] == str(valid_api_key.id)
        assert auth_info["api_key_name"] == valid_api_key.name
        assert auth_info["tenant_id"] == str(valid_api_key.tenant_id)

        # Check that last_used_at was updated
        valid_api_key.refresh_from_db()
        assert valid_api_key.last_used_at is not None
        assert valid_api_key.last_used_at <= timezone.now()

    def test_authenticate_credentials_updates_last_used(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test that authentication updates the last_used_at timestamp."""
        request = request_factory.get("/api/v1/test")

        # Ensure last_used_at is initially None
        assert valid_api_key.last_used_at is None

        # Authenticate
        auth_instance.authenticate_credentials(valid_api_key._raw_key, request)

        # Check timestamp was updated
        valid_api_key.refresh_from_db()
        assert valid_api_key.last_used_at is not None

        # Authenticate again and check timestamp is updated again
        first_use_time = valid_api_key.last_used_at
        auth_instance.authenticate_credentials(valid_api_key._raw_key, request)

        valid_api_key.refresh_from_db()
        assert valid_api_key.last_used_at >= first_use_time

    def test_authenticate_full_flow_valid_key(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test full authentication flow with valid API key."""
        request = request_factory.get("/api/v1/test")
        request.META["HTTP_AUTHORIZATION"] = f"ApiKey {valid_api_key._raw_key}"

        user, auth_info = auth_instance.authenticate(request)

        assert isinstance(user, APIKeyUser)
        assert user.api_key_id == str(valid_api_key.id)
        assert user.api_key_name == valid_api_key.name
        assert user.tenant_id == str(valid_api_key.tenant_id)

    def test_authenticate_header_method(self, auth_instance, request_factory):
        """Test authenticate_header method returns correct keyword."""
        request = request_factory.get("/api/v1/test")
        header = auth_instance.authenticate_header(request)
        assert header == "ApiKey"

    @patch("api.authentication.logger")
    def test_failed_last_used_update_doesnt_fail_auth(
        self, mock_logger, auth_instance, request_factory, valid_api_key
    ):
        """Test that failed last_used_at update doesn't prevent authentication."""
        request = request_factory.get("/api/v1/test")

        # Mock save to raise an exception
        with patch.object(valid_api_key, "save", side_effect=Exception("DB Error")):
            # Authentication should still succeed
            user, auth_info = auth_instance.authenticate_credentials(
                valid_api_key._raw_key, request
            )

            assert isinstance(user, APIKeyUser)
            assert auth_info["api_key_id"] == str(valid_api_key.id)

        # Check that warning was logged
        mock_logger.warning.assert_called_once()
        assert "Failed to update last_used_at" in str(mock_logger.warning.call_args)
