"""
Tests for API Key Authentication functionality.
"""

import pytest
from unittest.mock import patch
from django.test import RequestFactory
from django.contrib.auth.models import AnonymousUser
from django.utils import timezone
from datetime import timedelta
from rest_framework import exceptions

from api.authentication import APIKeyAuthentication
from api.models import APIKey, Tenant


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
            expires_at=None,
            revoked_at=None,
        )

        # Store the raw key for testing
        api_key._raw_key = raw_key
        return api_key

    @pytest.fixture
    def expired_api_key(self, tenant):
        """Create an expired API key for testing."""
        raw_key = APIKey.generate_key()
        prefix = APIKey.extract_prefix(raw_key)
        key_hash = APIKey.hash_key(raw_key)
        past_time = timezone.now() - timedelta(hours=1)

        api_key = APIKey.objects.create(
            name="Expired API Key",
            tenant_id=tenant.id,
            key_hash=key_hash,
            prefix=prefix,
            expires_at=past_time,
            revoked_at=None,
        )

        api_key._raw_key = raw_key
        return api_key

    @pytest.fixture
    def revoked_api_key(self, tenant):
        """Create a revoked API key for testing."""
        raw_key = APIKey.generate_key()
        prefix = APIKey.extract_prefix(raw_key)
        key_hash = APIKey.hash_key(raw_key)
        past_time = timezone.now() - timedelta(minutes=30)

        api_key = APIKey.objects.create(
            name="Revoked API Key",
            tenant_id=tenant.id,
            key_hash=key_hash,
            prefix=prefix,
            expires_at=None,
            revoked_at=past_time,
        )

        api_key._raw_key = raw_key
        return api_key

    def test_authenticate_no_header(self, auth_instance, request_factory):
        """Test authentication with no Authorization header."""
        request = request_factory.get("/api/v1/test")
        result = auth_instance.authenticate(request)
        assert result is None

    def test_authenticate_empty_header(self, auth_instance, request_factory):
        """Test authentication with empty Authorization header."""
        request = request_factory.get("/api/v1/test")
        request.META["HTTP_AUTHORIZATION"] = ""
        result = auth_instance.authenticate(request)
        assert result is None

    def test_authenticate_malformed_header_no_space(
        self, auth_instance, request_factory
    ):
        """Test authentication with malformed header (no space)."""
        request = request_factory.get("/api/v1/test")
        request.META["HTTP_AUTHORIZATION"] = "ApiKeypk_test1234.abcdef"
        result = auth_instance.authenticate(request)
        assert result is None

    def test_authenticate_wrong_auth_type(self, auth_instance, request_factory):
        """Test authentication with wrong auth type (not ApiKey)."""
        request = request_factory.get("/api/v1/test")
        request.META["HTTP_AUTHORIZATION"] = "Bearer some_jwt_token"
        result = auth_instance.authenticate(request)
        assert result is None

    def test_authenticate_case_insensitive_keyword(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test that authentication keyword is case insensitive."""
        request = request_factory.get("/api/v1/test")
        request.META["HTTP_AUTHORIZATION"] = f"apikey {valid_api_key._raw_key}"

        user, auth_info = auth_instance.authenticate(request)

        assert isinstance(user, AnonymousUser)
        assert auth_info["api_key_id"] == str(valid_api_key.id)

    def test_authenticate_credentials_invalid_format(
        self, auth_instance, request_factory
    ):
        """Test authenticate_credentials with invalid key format."""
        request = request_factory.get("/api/v1/test")

        with pytest.raises(
            exceptions.AuthenticationFailed, match="Invalid API key format"
        ):
            auth_instance.authenticate_credentials("invalid_key_format", request)

    def test_authenticate_credentials_nonexistent_key(
        self, auth_instance, request_factory
    ):
        """Test authenticate_credentials with non-existent key."""
        request = request_factory.get("/api/v1/test")
        fake_key = "pk_nonexist.abcdef123456789012345678901234"

        with pytest.raises(exceptions.AuthenticationFailed, match="Invalid API key"):
            auth_instance.authenticate_credentials(fake_key, request)

    def test_authenticate_credentials_wrong_key(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test authenticate_credentials with wrong key (same prefix, different key)."""
        request = request_factory.get("/api/v1/test")
        # Create a key with same prefix but different random part
        wrong_key = f"pk_{valid_api_key.prefix}.wrongrandompart123456789012345"

        with pytest.raises(exceptions.AuthenticationFailed, match="Invalid API key"):
            auth_instance.authenticate_credentials(wrong_key, request)

    def test_authenticate_credentials_expired_key(
        self, auth_instance, request_factory, expired_api_key
    ):
        """Test authenticate_credentials with expired key."""
        request = request_factory.get("/api/v1/test")

        with pytest.raises(
            exceptions.AuthenticationFailed, match="API key has expired"
        ):
            auth_instance.authenticate_credentials(expired_api_key._raw_key, request)

    def test_authenticate_credentials_revoked_key(
        self, auth_instance, request_factory, revoked_api_key
    ):
        """Test authenticate_credentials with revoked key."""
        request = request_factory.get("/api/v1/test")

        with pytest.raises(
            exceptions.AuthenticationFailed, match="API key has been revoked"
        ):
            auth_instance.authenticate_credentials(revoked_api_key._raw_key, request)

    def test_authenticate_credentials_valid_key(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test successful authentication with valid key."""
        request = request_factory.get("/api/v1/test")

        user, auth_info = auth_instance.authenticate_credentials(
            valid_api_key._raw_key, request
        )

        # Check returned user and auth info
        assert isinstance(user, AnonymousUser)
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

        assert isinstance(user, AnonymousUser)
        assert auth_info["api_key_id"] == str(valid_api_key.id)
        assert auth_info["api_key_name"] == valid_api_key.name
        assert auth_info["tenant_id"] == str(valid_api_key.tenant_id)

    def test_authenticate_header_method(self, auth_instance, request_factory):
        """Test authenticate_header method returns correct keyword."""
        request = request_factory.get("/api/v1/test")
        header = auth_instance.authenticate_header(request)
        assert header == "ApiKey"

    def test_authenticate_with_multiple_candidate_keys(
        self, auth_instance, request_factory, tenant
    ):
        """Test authentication when multiple keys have the same prefix."""
        # Create two keys with the same prefix but different hashes
        prefix = "samepre1"

        # First key (wrong one)
        wrong_key = "pk_samepre1.wrongpart123456789012345678901"
        wrong_hash = APIKey.hash_key(wrong_key)
        APIKey.objects.create(
            name="Wrong Key", tenant_id=tenant.id, key_hash=wrong_hash, prefix=prefix
        )

        # Second key (correct one)
        correct_key = "pk_samepre1.correctpart123456789012345678"
        correct_hash = APIKey.hash_key(correct_key)
        correct_api_key = APIKey.objects.create(
            name="Correct Key",
            tenant_id=tenant.id,
            key_hash=correct_hash,
            prefix=prefix,
        )

        request = request_factory.get("/api/v1/test")
        user, auth_info = auth_instance.authenticate_credentials(correct_key, request)

        # Should authenticate with the correct key
        assert auth_info["api_key_id"] == str(correct_api_key.id)
        assert auth_info["api_key_name"] == "Correct Key"

    def test_authenticate_credentials_timezone_mock(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test that last_used_at is updated during authentication."""
        # Store original last_used_at (should be None)
        original_last_used = valid_api_key.last_used_at

        request = request_factory.get("/api/v1/test")
        auth_instance.authenticate_credentials(valid_api_key._raw_key, request)

        valid_api_key.refresh_from_db()
        # Verify last_used_at was updated and is recent
        assert valid_api_key.last_used_at is not None
        assert valid_api_key.last_used_at != original_last_used
        assert (
            timezone.now() - valid_api_key.last_used_at
        ).total_seconds() < 5  # Within 5 seconds

    def test_authenticate_credentials_database_save_fields(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test that only last_used_at field is updated during authentication."""
        request = request_factory.get("/api/v1/test")

        with patch.object(valid_api_key, "save") as mock_save:
            # Mock the APIKey.all_objects.filter() to return our key (not objects.filter)
            with patch("api.models.APIKey.all_objects.filter") as mock_filter:
                # Create a mock queryset that behaves like Django queryset
                from unittest.mock import MagicMock
                mock_queryset = MagicMock()
                mock_queryset.count.return_value = 1
                mock_queryset.__iter__.return_value = iter([valid_api_key])
                mock_filter.return_value = mock_queryset

                auth_instance.authenticate_credentials(valid_api_key._raw_key, request)

                # Verify save was called with update_fields
                mock_save.assert_called_once_with(update_fields=["last_used_at"])

    def test_authenticate_with_extra_spaces_in_header(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test authentication handles extra spaces in authorization header."""
        request = request_factory.get("/api/v1/test")
        request.META["HTTP_AUTHORIZATION"] = f"  ApiKey   {valid_api_key._raw_key}  "

        # Should handle extra spaces gracefully
        result = auth_instance.authenticate(request)
        assert result is None  # Extra spaces will cause split to fail

    def test_authenticate_with_multiple_spaces_in_header(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test authentication with multiple spaces between ApiKey and token."""
        request = request_factory.get("/api/v1/test")
        request.META["HTTP_AUTHORIZATION"] = f"ApiKey    {valid_api_key._raw_key}"

        user, auth_info = auth_instance.authenticate(request)

        # Should work with multiple spaces
        assert isinstance(user, AnonymousUser)
        assert auth_info["api_key_id"] == str(valid_api_key.id)

    def test_authenticate_credentials_with_future_expiry(
        self, auth_instance, request_factory, tenant
    ):
        """Test authentication with key that expires in the future."""
        raw_key = APIKey.generate_key()
        prefix = APIKey.extract_prefix(raw_key)
        key_hash = APIKey.hash_key(raw_key)
        future_time = timezone.now() + timedelta(hours=1)

        api_key = APIKey.objects.create(
            name="Future Expiry Key",
            tenant_id=tenant.id,
            key_hash=key_hash,
            prefix=prefix,
            expires_at=future_time,
            revoked_at=None,
        )

        request = request_factory.get("/api/v1/test")
        user, auth_info = auth_instance.authenticate_credentials(raw_key, request)

        # Should authenticate successfully
        assert isinstance(user, AnonymousUser)
        assert auth_info["api_key_id"] == str(api_key.id)

    def test_authenticate_credentials_returns_tenant_context(
        self, auth_instance, request_factory, valid_api_key
    ):
        """Test that authentication returns proper tenant context from API key."""
        request = request_factory.get("/api/v1/test")
        user, auth_info = auth_instance.authenticate_credentials(
            valid_api_key._raw_key, request
        )

        # Verify API key is tenant-bound and returns tenant context
        assert isinstance(user, AnonymousUser)
        assert "tenant_id" in auth_info
        assert auth_info["tenant_id"] == str(valid_api_key.tenant_id)
        assert auth_info["api_key_id"] == str(valid_api_key.id)
        assert auth_info["api_key_name"] == valid_api_key.name
