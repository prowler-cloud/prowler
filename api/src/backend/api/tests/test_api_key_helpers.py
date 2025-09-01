"""
Helper utilities for API key tests to maintain backward compatibility
while using the new djangorestframework-api-key implementation.
"""

from api.models import APIKey


def create_test_api_key(tenant, role, name="Test API Key", **kwargs):
    """
    Create a test API key using the new DRF-based implementation.
    Returns (api_key_instance, raw_key_string).
    """
    # Handle expiry_date parameter (old tests might use expires_at)
    if "expires_at" in kwargs:
        kwargs["expiry_date"] = kwargs.pop("expires_at")

    api_key, raw_key = APIKey.objects.create_key(
        tenant_id=tenant.id, role=role, name=name, **kwargs
    )

    return api_key, raw_key


def create_test_api_key_with_fields(tenant, role, name="Test API Key", **old_fields):
    """
    Create a test API key using old field names for backward compatibility.
    Maps old field names to new ones.
    """
    # Map old field names to new ones
    new_fields = {}

    # Handle expires_at -> expiry_date
    if "expires_at" in old_fields:
        new_fields["expiry_date"] = old_fields.pop("expires_at")

    # Handle revoked_at -> revoked (boolean)
    if "revoked_at" in old_fields:
        new_fields["revoked"] = old_fields.pop("revoked_at") is not None

    # Pass through other fields
    new_fields.update(old_fields)

    return create_test_api_key(tenant, role, name, **new_fields)


class APIKeyTestMixin:
    """
    Mixin class to provide API key test utilities.
    """

    def create_api_key(self, tenant=None, role=None, **kwargs):
        """Create an API key for testing."""
        if tenant is None:
            tenant = self.tenant
        if role is None:
            role = self.role

        return create_test_api_key(tenant, role, **kwargs)

    def create_api_key_with_raw_key(self, tenant=None, role=None, **kwargs):
        """Create an API key and return both instance and raw key."""
        if tenant is None:
            tenant = self.tenant
        if role is None:
            role = self.role

        return create_test_api_key(tenant, role, **kwargs)
