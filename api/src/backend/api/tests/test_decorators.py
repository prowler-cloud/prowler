import uuid
from unittest.mock import call, patch

import pytest
from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError, IntegrityError

from api.db_utils import POSTGRES_TENANT_VAR, SET_CONFIG_QUERY
from api.decorators import handle_provider_deletion, set_tenant
from api.exceptions import ProviderDeletedException


@pytest.mark.django_db
class TestSetTenantDecorator:
    @patch("api.decorators.connection.cursor")
    def test_set_tenant(self, mock_cursor):
        mock_cursor.return_value.__enter__.return_value = mock_cursor

        @set_tenant
        def random_func(arg):
            return arg

        tenant_id = str(uuid.uuid4())

        result = random_func("test_arg", tenant_id=tenant_id)

        assert (
            call(SET_CONFIG_QUERY, [POSTGRES_TENANT_VAR, tenant_id])
            in mock_cursor.execute.mock_calls
        )
        assert result == "test_arg"

    def test_set_tenant_exception(self):
        @set_tenant
        def random_func(arg):
            return arg

        with pytest.raises(KeyError):
            random_func("test_arg")


@pytest.mark.django_db
class TestHandleProviderDeletionDecorator:
    def test_success_no_exception(self, tenants_fixture, providers_fixture):
        """Decorated function runs normally when no exception is raised."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        @handle_provider_deletion
        def task_func(**kwargs):
            return "success"

        result = task_func(
            tenant_id=str(tenant.id),
            provider_id=str(provider.id),
        )
        assert result == "success"

    @patch("api.decorators.rls_transaction")
    @patch("api.decorators.Provider.objects.filter")
    def test_provider_deleted_with_provider_id(
        self, mock_filter, mock_rls, tenants_fixture
    ):
        """Raises ProviderDeletedException when provider_id provided and provider deleted."""
        tenant = tenants_fixture[0]
        deleted_provider_id = str(uuid.uuid4())

        mock_rls.return_value.__enter__ = lambda s: None
        mock_rls.return_value.__exit__ = lambda s, *args: None
        mock_filter.return_value.exists.return_value = False

        @handle_provider_deletion
        def task_func(**kwargs):
            raise ObjectDoesNotExist("Some object not found")

        with pytest.raises(ProviderDeletedException) as exc_info:
            task_func(tenant_id=str(tenant.id), provider_id=deleted_provider_id)

        assert deleted_provider_id in str(exc_info.value)

    @patch("api.decorators.rls_transaction")
    @patch("api.decorators.Provider.objects.filter")
    @patch("api.decorators.Scan.objects.filter")
    def test_provider_deleted_with_scan_id(
        self, mock_scan_filter, mock_provider_filter, mock_rls, tenants_fixture
    ):
        """Raises ProviderDeletedException when scan exists but provider deleted."""
        tenant = tenants_fixture[0]
        scan_id = str(uuid.uuid4())
        provider_id = str(uuid.uuid4())

        mock_rls.return_value.__enter__ = lambda s: None
        mock_rls.return_value.__exit__ = lambda s, *args: None

        mock_scan = type("MockScan", (), {"provider_id": provider_id})()
        mock_scan_filter.return_value.first.return_value = mock_scan
        mock_provider_filter.return_value.exists.return_value = False

        @handle_provider_deletion
        def task_func(**kwargs):
            raise ObjectDoesNotExist("Some object not found")

        with pytest.raises(ProviderDeletedException) as exc_info:
            task_func(tenant_id=str(tenant.id), scan_id=scan_id)

        assert provider_id in str(exc_info.value)

    @patch("api.decorators.rls_transaction")
    @patch("api.decorators.Scan.objects.filter")
    def test_scan_deleted_cascade(self, mock_scan_filter, mock_rls, tenants_fixture):
        """Raises ProviderDeletedException when scan was deleted (CASCADE from provider)."""
        tenant = tenants_fixture[0]
        scan_id = str(uuid.uuid4())

        mock_rls.return_value.__enter__ = lambda s: None
        mock_rls.return_value.__exit__ = lambda s, *args: None
        mock_scan_filter.return_value.first.return_value = None

        @handle_provider_deletion
        def task_func(**kwargs):
            raise ObjectDoesNotExist("Some object not found")

        with pytest.raises(ProviderDeletedException) as exc_info:
            task_func(tenant_id=str(tenant.id), scan_id=scan_id)

        assert scan_id in str(exc_info.value)

    @patch("api.decorators.rls_transaction")
    @patch("api.decorators.Provider.objects.filter")
    def test_provider_exists_reraises_original(
        self, mock_filter, mock_rls, tenants_fixture, providers_fixture
    ):
        """Re-raises original exception when provider still exists."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        mock_rls.return_value.__enter__ = lambda s: None
        mock_rls.return_value.__exit__ = lambda s, *args: None
        mock_filter.return_value.exists.return_value = True

        @handle_provider_deletion
        def task_func(**kwargs):
            raise ObjectDoesNotExist("Actual object missing")

        with pytest.raises(ObjectDoesNotExist):
            task_func(tenant_id=str(tenant.id), provider_id=str(provider.id))

    @patch("api.decorators.rls_transaction")
    @patch("api.decorators.Provider.objects.filter")
    def test_integrity_error_provider_deleted(
        self, mock_filter, mock_rls, tenants_fixture
    ):
        """Raises ProviderDeletedException on IntegrityError when provider deleted."""
        tenant = tenants_fixture[0]
        deleted_provider_id = str(uuid.uuid4())

        mock_rls.return_value.__enter__ = lambda s: None
        mock_rls.return_value.__exit__ = lambda s, *args: None
        mock_filter.return_value.exists.return_value = False

        @handle_provider_deletion
        def task_func(**kwargs):
            raise IntegrityError("FK constraint violation")

        with pytest.raises(ProviderDeletedException):
            task_func(tenant_id=str(tenant.id), provider_id=deleted_provider_id)

    @patch("api.decorators.rls_transaction")
    @patch("api.decorators.Provider.objects.filter")
    def test_database_error_provider_deleted(
        self, mock_filter, mock_rls, tenants_fixture
    ):
        """Raises ProviderDeletedException on DatabaseError when provider deleted."""
        tenant = tenants_fixture[0]
        deleted_provider_id = str(uuid.uuid4())

        mock_rls.return_value.__enter__ = lambda s: None
        mock_rls.return_value.__exit__ = lambda s, *args: None
        mock_filter.return_value.exists.return_value = False

        @handle_provider_deletion
        def task_func(**kwargs):
            raise DatabaseError("Save with update_fields did not affect any rows")

        with pytest.raises(ProviderDeletedException):
            task_func(tenant_id=str(tenant.id), provider_id=deleted_provider_id)

    @patch("api.decorators.rls_transaction")
    @patch("api.decorators.Provider.objects.filter")
    def test_database_error_provider_exists_reraises(
        self, mock_filter, mock_rls, tenants_fixture, providers_fixture
    ):
        """Re-raises original DatabaseError when provider still exists."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        mock_rls.return_value.__enter__ = lambda s: None
        mock_rls.return_value.__exit__ = lambda s, *args: None
        mock_filter.return_value.exists.return_value = True

        @handle_provider_deletion
        def task_func(**kwargs):
            raise DatabaseError("Save with update_fields did not affect any rows")

        with pytest.raises(DatabaseError):
            task_func(tenant_id=str(tenant.id), provider_id=str(provider.id))

    def test_missing_provider_and_scan_raises_assertion(self, tenants_fixture):
        """Raises AssertionError when neither provider_id nor scan_id in kwargs."""

        @handle_provider_deletion
        def task_func(**kwargs):
            raise ObjectDoesNotExist("Some object not found")

        with pytest.raises(AssertionError) as exc_info:
            task_func(tenant_id=str(tenants_fixture[0].id))

        assert "provider or scan" in str(exc_info.value)
