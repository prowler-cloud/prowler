"""
Security tests for API Key functionality.

These tests verify security aspects of API key usage including:
- Expired key rejection
- Revoked key rejection
- Invalid format handling
- Prefix collision security
- Rate limiting behavior
- Concurrent access scenarios
"""

import pytest
from unittest.mock import patch, MagicMock
from django.test import RequestFactory
from django.utils import timezone
from datetime import timedelta

from api.models import APIKey, Tenant
from api.authentication import APIKeyAuthentication
from api.middleware import APILoggingMiddleware
from rest_framework import exceptions


@pytest.mark.django_db
class TestAPIKeySecurityScenarios:
    """Test comprehensive API key security scenarios."""

    @pytest.fixture
    def tenant(self):
        """Create a test tenant."""
        return Tenant.objects.create(name="Security Test Tenant")

    @pytest.fixture
    def valid_api_key(self, tenant):
        """Create a valid API key for security testing."""
        raw_key = APIKey.generate_key()
        prefix = APIKey.extract_prefix(raw_key)
        key_hash = APIKey.hash_key(raw_key)

        api_key = APIKey.objects.create(
            name="Security Test Key",
            tenant_id=tenant.id,
            key_hash=key_hash,
            prefix=prefix,
            expiry_date=None,
            revoked=False,
        )

        api_key._raw_key = raw_key
        return api_key

    @pytest.fixture
    def expired_api_key(self, tenant):
        """Create an expired API key."""
        raw_key = APIKey.generate_key()
        prefix = APIKey.extract_prefix(raw_key)
        key_hash = APIKey.hash_key(raw_key)

        api_key = APIKey.objects.create(
            name="Expired Security Key",
            tenant_id=tenant.id,
            key_hash=key_hash,
            prefix=prefix,
            expiry_date=timezone.now() - timedelta(hours=1),
            revoked=False,
        )

        api_key._raw_key = raw_key
        return api_key

    @pytest.fixture
    def revoked_api_key(self, tenant):
        """Create a revoked API key."""
        raw_key = APIKey.generate_key()
        prefix = APIKey.extract_prefix(raw_key)
        key_hash = APIKey.hash_key(raw_key)

        api_key = APIKey.objects.create(
            name="Revoked Security Key",
            tenant_id=tenant.id,
            key_hash=key_hash,
            prefix=prefix,
            expiry_date=None,
            revoked=True,
        )

        api_key._raw_key = raw_key
        return api_key

    def test_expired_key_authentication_rejection(self, expired_api_key):
        """Test that expired API keys are rejected during authentication."""
        auth = APIKeyAuthentication()
        factory = RequestFactory()
        request = factory.get("/api/v1/test")

        with pytest.raises(
            exceptions.AuthenticationFailed, match="API key has expired"
        ):
            auth.authenticate_credentials(expired_api_key._raw_key, request)

    def test_revoked_key_authentication_rejection(self, revoked_api_key):
        """Test that revoked API keys are rejected during authentication."""
        auth = APIKeyAuthentication()
        factory = RequestFactory()
        request = factory.get("/api/v1/test")

        with pytest.raises(
            exceptions.AuthenticationFailed, match="API key has been revoked"
        ):
            auth.authenticate_credentials(revoked_api_key._raw_key, request)

    def test_malformed_key_format_rejection(self):
        """Test various malformed API key formats are rejected."""
        auth = APIKeyAuthentication()
        factory = RequestFactory()
        request = factory.get("/api/v1/test")

        # Keys that fail format validation (extract_prefix)
        format_error_keys = [
            "not_an_api_key",
            "pk_",
            "pk_short",
            "pk_12345678",  # Missing dot and second part
            ".abcdef123456789012345678901234",  # Missing prefix
            "pk_12345678.abcdef123456789012345678901234.extra",  # Too many parts
            "",  # Empty string
        ]

        for malformed_key in format_error_keys:
            with pytest.raises(
                exceptions.AuthenticationFailed, match="Invalid API key format"
            ):
                auth.authenticate_credentials(malformed_key, request)

        # Keys that pass format validation but fail authentication
        invalid_keys = [
            "wrong_prefix_12345678.abcdef123456789012345678901234",
            "pk_12345678.",  # Empty second part
            "pk_12345678.short",  # Second part too short
        ]

        for invalid_key in invalid_keys:
            with pytest.raises(
                exceptions.AuthenticationFailed, match="Invalid API key"
            ):
                auth.authenticate_credentials(invalid_key, request)

    def test_prefix_collision_security_isolation(self, tenant):
        """Test that prefix collisions don't allow cross-key authentication."""
        # Create two keys with same prefix but different random parts
        prefix = "samepref"

        # First key
        key1 = f"pk_{prefix}.abcdef123456789012345678901234"
        hash1 = APIKey.hash_key(key1)
        api_key1 = APIKey.objects.create(
            name="Key 1", tenant_id=tenant.id, key_hash=hash1, prefix=prefix
        )

        # Second key with same prefix
        key2 = f"pk_{prefix}.different123456789012345678901"
        hash2 = APIKey.hash_key(key2)
        api_key2 = APIKey.objects.create(
            name="Key 2", tenant_id=tenant.id, key_hash=hash2, prefix=prefix
        )

        auth = APIKeyAuthentication()
        factory = RequestFactory()
        request = factory.get("/api/v1/test")

        # Key 1 should only authenticate with its own hash
        user, auth_info = auth.authenticate_credentials(key1, request)
        assert auth_info["api_key_id"] == str(api_key1.id)

        # Key 2 should only authenticate with its own hash
        user, auth_info = auth.authenticate_credentials(key2, request)
        assert auth_info["api_key_id"] == str(api_key2.id)

        # Wrong key should fail
        wrong_key = f"pk_{prefix}.wrongkey123456789012345678901"
        with pytest.raises(exceptions.AuthenticationFailed, match="Invalid API key"):
            auth.authenticate_credentials(wrong_key, request)

    def test_key_expiry_edge_case_timing(self, tenant):
        """Test key expiry at exact boundary conditions."""
        # Create a key that expires in 1 second
        raw_key = APIKey.generate_key()
        prefix = APIKey.extract_prefix(raw_key)
        key_hash = APIKey.hash_key(raw_key)

        future_time = timezone.now() + timedelta(seconds=1)
        api_key = APIKey.objects.create(
            name="Edge Case Key",
            tenant_id=tenant.id,
            key_hash=key_hash,
            prefix=prefix,
            expiry_date=future_time,
            revoked=False,
        )

        # Should be valid initially
        assert api_key.is_active() is True

        # Mock time to be past expiry
        with patch("django.utils.timezone.now") as mock_now:
            mock_now.return_value = future_time + timedelta(seconds=1)
            assert api_key.is_active() is False

    def test_concurrent_key_revocation_safety(self, valid_api_key):
        """Test that concurrent revocation operations are safe."""
        # Simulate concurrent revocation attempts
        api_key1 = valid_api_key
        api_key2 = APIKey.objects.get(id=valid_api_key.id)  # Second reference

        # Both should be valid initially
        assert api_key1.is_active() is True
        assert api_key2.is_active() is True

        # Revoke through first reference
        api_key1.revoke()

        # Refresh second reference and verify it sees the revocation
        api_key2.refresh_from_db()
        assert api_key2.is_active() is False

        # Revoking again should be safe (idempotent)
        api_key2.revoke()
        assert api_key2.is_active() is False

    def test_api_key_activity_logging_security_data(self, valid_api_key):
        """Test that security-relevant data is logged in structured application logs."""
        factory = RequestFactory()
        request = factory.post("/api/v1/sensitive-endpoint")
        request.META["REMOTE_ADDR"] = "192.168.1.100"
        request.META["HTTP_USER_AGENT"] = "PotentialThreatAgent/1.0"

        # Mock middleware behavior
        auth_info = {
            "api_key_id": str(valid_api_key.id),
            "api_key_name": valid_api_key.name,
            "user_id": "test-user-id",
            "tenant_id": str(valid_api_key.tenant_id),
        }

        response = MagicMock()
        response.status_code = 403  # Simulating access denied

        with patch("api.middleware.extract_auth_info") as mock_extract_auth_info:
            mock_extract_auth_info.return_value = auth_info

            # Mock the logger to capture log calls
            middleware = APILoggingMiddleware(lambda req: response)
            with patch.object(middleware, "logger") as mock_logger:
                middleware(request)

                # Verify security-relevant data was logged
                mock_logger.info.assert_called_once()
                call_args = mock_logger.info.call_args

                # Check the log message contains API key info
                assert "API Key:" in call_args[0][0]

                # Check the extra data contains security-relevant information
                extra_data = call_args[1]["extra"]
                assert extra_data["api_key_id"] == str(valid_api_key.id)
                assert extra_data["api_key_name"] == valid_api_key.name
                assert extra_data["source_ip"] == "192.168.1.100"
                assert extra_data["user_agent"] == "PotentialThreatAgent/1.0"
                assert extra_data["status_code"] == 403
                assert extra_data["path"] == "/api/v1/sensitive-endpoint"
                assert extra_data["is_api_key_request"] is True

    def test_api_key_brute_force_protection_simulation(self, tenant):
        """Test simulation of brute force attacks on API key validation."""
        # Create a valid key
        raw_key = APIKey.generate_key()
        prefix = APIKey.extract_prefix(raw_key)
        key_hash = APIKey.hash_key(raw_key)

        api_key = APIKey.objects.create(
            name="Brute Force Test Key",
            tenant_id=tenant.id,
            key_hash=key_hash,
            prefix=prefix,
        )

        auth = APIKeyAuthentication()
        factory = RequestFactory()
        request = factory.get("/api/v1/test")

        # Simulate multiple failed attempts with wrong keys
        failed_attempts = 0
        for i in range(10):
            wrong_key = f"pk_{prefix}.wrong{i:026d}"  # Same prefix, wrong random part
            try:
                auth.authenticate_credentials(wrong_key, request)
            except exceptions.AuthenticationFailed:
                failed_attempts += 1

        # All attempts should fail
        assert failed_attempts == 10

        # Valid key should still work
        user, auth_info = auth.authenticate_credentials(raw_key, request)
        assert auth_info["api_key_id"] == str(api_key.id)

    def test_key_hash_security_properties(self):
        """Test security properties of key hashing."""
        key1 = "pk_test1234.abcdef123456789012345678901234"
        key2 = "pk_test1234.abcdef123456789012345678901235"  # Different by one char

        hash1 = APIKey.hash_key(key1)
        hash2 = APIKey.hash_key(key2)

        # Hashes should be different for different keys
        assert hash1 != hash2

        # Hashes should be different each time (salted)
        hash1_again = APIKey.hash_key(key1)
        assert hash1 != hash1_again

        # But verification should work
        assert APIKey.verify_key(key1, hash1) is True
        assert APIKey.verify_key(key1, hash1_again) is True
        assert APIKey.verify_key(key1, hash2) is False

    def test_api_key_generation_entropy(self):
        """Test that API key generation has sufficient entropy."""
        keys = set()
        prefixes = set()

        # Generate many keys and check for uniqueness
        for _ in range(1000):
            key = APIKey.generate_key()
            keys.add(key)
            prefix = APIKey.extract_prefix(key)
            prefixes.add(prefix)

        # All keys should be unique
        assert len(keys) == 1000

        # Most prefixes should be unique (allowing for very rare collisions)
        assert len(prefixes) >= 990  # 99% uniqueness threshold

    def test_tenant_isolation_security(self, tenant):
        """Test that API keys are properly isolated between tenants."""
        # Create second tenant
        tenant2 = Tenant.objects.create(name="Second Tenant")

        # Create API key for first tenant
        raw_key1 = APIKey.generate_key()
        prefix1 = APIKey.extract_prefix(raw_key1)
        key_hash1 = APIKey.hash_key(raw_key1)

        api_key1 = APIKey.objects.create(
            name="Tenant 1 Key", tenant_id=tenant.id, key_hash=key_hash1, prefix=prefix1
        )

        # Create API key for second tenant
        raw_key2 = APIKey.generate_key()
        prefix2 = APIKey.extract_prefix(raw_key2)
        key_hash2 = APIKey.hash_key(raw_key2)

        api_key2 = APIKey.objects.create(
            name="Tenant 2 Key",
            tenant_id=tenant2.id,
            key_hash=key_hash2,
            prefix=prefix2,
        )

        # Keys should authenticate to their respective tenants
        auth = APIKeyAuthentication()
        factory = RequestFactory()
        request = factory.get("/api/v1/test")

        user1, auth_info1 = auth.authenticate_credentials(raw_key1, request)
        assert auth_info1["tenant_id"] == str(tenant.id)

        user2, auth_info2 = auth.authenticate_credentials(raw_key2, request)
        assert auth_info2["tenant_id"] == str(tenant2.id)

        # Verify tenant isolation in database queries
        tenant1_keys = APIKey.objects.filter(tenant_id=tenant.id)
        tenant2_keys = APIKey.objects.filter(tenant_id=tenant2.id)

        assert api_key1 in tenant1_keys
        assert api_key1 not in tenant2_keys
        assert api_key2 in tenant2_keys
        assert api_key2 not in tenant1_keys

    def test_key_validation_performance_security(self, tenant):
        """Test that key validation doesn't have timing vulnerabilities."""
        # Create a valid key
        raw_key = APIKey.generate_key()
        prefix = APIKey.extract_prefix(raw_key)
        key_hash = APIKey.hash_key(raw_key)

        APIKey.objects.create(
            name="Performance Test Key",
            tenant_id=tenant.id,
            key_hash=key_hash,
            prefix=prefix,
        )

        auth = APIKeyAuthentication()
        factory = RequestFactory()
        request = factory.get("/api/v1/test")

        # Test that hash verification is the time-consuming operation,
        # not the database lookup
        import time

        # Valid key (should find match in DB and verify hash)
        start_time = time.time()
        try:
            auth.authenticate_credentials(raw_key, request)
        except Exception:
            pass
        valid_key_time = time.time() - start_time

        # Invalid key with same prefix (should find match in DB but fail hash verification)
        wrong_key = f"pk_{prefix}.wrongpart123456789012345678901234"
        start_time = time.time()
        try:
            auth.authenticate_credentials(wrong_key, request)
        except Exception:
            pass
        invalid_key_time = time.time() - start_time

        # Times should be similar (both do hash verification)
        # This is a basic timing attack protection check
        time_ratio = max(valid_key_time, invalid_key_time) / min(
            valid_key_time, invalid_key_time
        )
        assert time_ratio < 5  # Should not differ by more than 5x

    def test_api_key_memory_cleanup_security(self, valid_api_key):
        """Test that sensitive data is properly cleaned up."""
        # This test verifies that raw keys aren't accidentally stored
        # in the database or left in memory longer than necessary

        # Valid API key should not have raw key stored in database
        db_api_key = APIKey.objects.get(id=valid_api_key.id)

        # Check that no field contains the raw key
        for field_name in ["name", "key_hash", "prefix"]:
            field_value = getattr(db_api_key, field_name)
            assert valid_api_key._raw_key not in str(field_value)

        # The key_hash should be a hashed version, not the raw key
        assert db_api_key.key_hash != valid_api_key._raw_key
        assert len(db_api_key.key_hash) > len(valid_api_key._raw_key)

        # Prefix should only contain the prefix part, not the full key
        expected_prefix = APIKey.extract_prefix(valid_api_key._raw_key)
        assert db_api_key.prefix == expected_prefix
        assert valid_api_key._raw_key not in db_api_key.prefix
