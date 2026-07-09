"""Tests for rls_transaction retry and fallback logic."""

import pytest
from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import POSTGRES_TENANT_VAR, rls_transaction
from django.db import DEFAULT_DB_ALIAS, OperationalError, connections
from psycopg2 import OperationalError as Psycopg2OperationalError
from rest_framework_json_api.serializers import ValidationError


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

    @pytest.mark.django_db(transaction=True, databases="__all__")
    def test_mid_query_replica_connection_loss_falls_back_to_primary(self, tenant):
        """Real Django connection state: closed replica atomic falls back to primary."""
        if not READ_REPLICA_ALIAS or READ_REPLICA_ALIAS not in connections:
            pytest.skip("Read replica is not configured")

        replica = connections[READ_REPLICA_ALIAS]
        sql = "SELECT current_setting(%s, true), %s"
        params = [POSTGRES_TENANT_VAR, 42]
        failed_once = {"value": False}

        def close_replica_and_raise(execute, sql_arg, params_arg, many, context):
            if not failed_once["value"] and sql_arg == sql:
                failed_once["value"] = True
                replica.close()
                try:
                    raise Psycopg2OperationalError("SSL SYSCALL error: EOF detected")
                except Psycopg2OperationalError as psycopg_error:
                    raise OperationalError(
                        "SSL SYSCALL error: EOF detected"
                    ) from psycopg_error
            return execute(sql_arg, params_arg, many, context)

        with rls_transaction(str(tenant.id), using=READ_REPLICA_ALIAS) as cursor:
            with replica.execute_wrapper(close_replica_and_raise):
                cursor.execute(sql, params)
                result = cursor.fetchone()

        assert failed_once["value"]
        assert result == (str(tenant.id), 42)
