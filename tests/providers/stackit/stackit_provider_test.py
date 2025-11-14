"""Tests for StackIT Provider input validation."""

import pytest

from prowler.providers.stackit.exceptions.exceptions import (
    StackITInvalidProjectIdError,
    StackITNonExistentTokenError,
)
from prowler.providers.stackit.stackit_provider import StackitProvider


class TestStackITProviderValidation:
    """Test suite for StackIT Provider input validation."""

    def test_validate_arguments_valid_uuid(self):
        """Test validation passes with valid UUID and token."""
        valid_token = "test-api-token-12345"
        valid_project_id = "12345678-1234-1234-1234-123456789abc"

        # Should not raise any exception
        StackitProvider.validate_arguments(valid_token, valid_project_id)

    def test_validate_arguments_empty_token(self):
        """Test validation fails with empty API token."""
        valid_project_id = "12345678-1234-1234-1234-123456789abc"

        with pytest.raises(StackITNonExistentTokenError) as exc_info:
            StackitProvider.validate_arguments("", valid_project_id)

        assert "API token is required" in str(exc_info.value)

    def test_validate_arguments_none_token(self):
        """Test validation fails with None API token."""
        valid_project_id = "12345678-1234-1234-1234-123456789abc"

        with pytest.raises(StackITNonExistentTokenError) as exc_info:
            StackitProvider.validate_arguments(None, valid_project_id)

        assert "API token is required" in str(exc_info.value)

    def test_validate_arguments_whitespace_only_token(self):
        """Test validation fails with whitespace-only API token."""
        valid_project_id = "12345678-1234-1234-1234-123456789abc"

        with pytest.raises(StackITNonExistentTokenError) as exc_info:
            StackitProvider.validate_arguments("   ", valid_project_id)

        assert "API token is required" in str(exc_info.value)

    def test_validate_arguments_empty_project_id(self):
        """Test validation fails with empty project ID."""
        valid_token = "test-api-token-12345"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, "")

        assert "project ID is required" in str(exc_info.value)

    def test_validate_arguments_none_project_id(self):
        """Test validation fails with None project ID."""
        valid_token = "test-api-token-12345"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, None)

        assert "project ID is required" in str(exc_info.value)

    def test_validate_arguments_whitespace_only_project_id(self):
        """Test validation fails with whitespace-only project ID."""
        valid_token = "test-api-token-12345"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, "   ")

        assert "project ID is required" in str(exc_info.value)

    def test_validate_arguments_invalid_uuid_format(self):
        """Test validation fails with invalid UUID format for project ID."""
        valid_token = "test-api-token-12345"
        invalid_project_id = "not-a-valid-uuid"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, invalid_project_id)

        assert "must be a valid UUID format" in str(exc_info.value)
        assert "not-a-valid-uuid" in str(exc_info.value)

    def test_validate_arguments_invalid_uuid_too_short(self):
        """Test validation fails with too short project ID."""
        valid_token = "test-api-token-12345"
        invalid_project_id = "1234-5678"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, invalid_project_id)

        assert "must be a valid UUID format" in str(exc_info.value)

    def test_validate_arguments_uuid_without_hyphens(self):
        """Test validation passes with UUID without hyphens (Python's UUID() normalizes it)."""
        valid_token = "test-api-token-12345"
        # Missing hyphens - Python's UUID() accepts this and normalizes it
        valid_project_id = "12345678123412341234123456789abc"

        # Should not raise exception - Python's UUID() handles this
        StackitProvider.validate_arguments(valid_token, valid_project_id)

    def test_validate_arguments_numeric_only_project_id(self):
        """Test validation fails with numeric-only project ID (not UUID)."""
        valid_token = "test-api-token-12345"
        # AWS-style numeric account ID (not valid UUID)
        invalid_project_id = "123456789012"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, invalid_project_id)

        assert "must be a valid UUID format" in str(exc_info.value)

    def test_validate_arguments_uuid_with_uppercase(self):
        """Test validation passes with uppercase UUID (should be normalized)."""
        valid_token = "test-api-token-12345"
        # UUIDs are case-insensitive
        valid_project_id = "12345678-1234-1234-1234-123456789ABC"

        # Should not raise any exception
        StackitProvider.validate_arguments(valid_token, valid_project_id)

    def test_validate_arguments_uuid_with_braces(self):
        """Test validation fails with UUID in braces (not standard format)."""
        valid_token = "test-api-token-12345"
        # Some systems use {UUID} format, but Python's UUID() should handle it
        valid_project_id = "{12345678-1234-1234-1234-123456789abc}"

        # Should not raise exception - Python's UUID() handles braces
        StackitProvider.validate_arguments(valid_token, valid_project_id)

    def test_validate_arguments_uuid_v4_format(self):
        """Test validation passes with valid UUID v4 format."""
        valid_token = "test-api-token-12345"
        # Standard UUID v4 format
        valid_project_id = "550e8400-e29b-41d4-a716-446655440000"

        # Should not raise any exception
        StackitProvider.validate_arguments(valid_token, valid_project_id)

    def test_validate_arguments_both_invalid(self):
        """Test validation fails with both token and project_id invalid."""
        # Should fail on token first (checked first in the method)
        with pytest.raises(StackITNonExistentTokenError):
            StackitProvider.validate_arguments("", "not-a-uuid")

    def test_validate_arguments_both_none(self):
        """Test validation fails with both token and project_id None."""
        # Should fail on token first (checked first in the method)
        with pytest.raises(StackITNonExistentTokenError):
            StackitProvider.validate_arguments(None, None)
