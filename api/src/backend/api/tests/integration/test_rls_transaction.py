"""Tests for rls_transaction retry and fallback logic."""

import pytest
from django.db import DEFAULT_DB_ALIAS
from rest_framework_json_api.serializers import ValidationError

from api.db_utils import rls_transaction


@pytest.mark.django_db
class TestRLSTransaction:
    """Simple integration tests for rls_transaction using real DB."""

    @pytest.fixture
    def tenant(self, tenants_fixture):
        return tenants_fixture[0]

    def test_success_on_primary(self, tenant):
        """Basic: transaction succeeds on primary database."""
        with rls_transaction(str(tenant.id), using=DEFAULT_DB_ALIAS) as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            assert result == (1,)

    def test_invalid_uuid_raises_validation_error(self):
        """Invalid UUID raises ValidationError before DB operations."""
        with pytest.raises(ValidationError, match="Must be a valid UUID"):
            with rls_transaction("not-a-uuid", using=DEFAULT_DB_ALIAS):
                pass

    def test_custom_parameter_name(self, tenant):
        """Test custom RLS parameter name."""
        custom_param = "api.custom_id"
        with rls_transaction(
            str(tenant.id), parameter=custom_param, using=DEFAULT_DB_ALIAS
        ) as cursor:
            cursor.execute("SELECT current_setting(%s, true)", [custom_param])
            result = cursor.fetchone()
            assert result == (str(tenant.id),)
