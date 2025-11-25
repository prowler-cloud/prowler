from unittest.mock import call

import pytest

from django.core.exceptions import ObjectDoesNotExist

from api.models import Provider, Tenant
from tasks.jobs.deletion import delete_provider, delete_tenant


@pytest.mark.django_db
class TestDeleteProvider:
    def test_delete_provider_success(self, providers_fixture, graph_db_mocks):
        instance = providers_fixture[0]
        tenant_id = str(instance.tenant_id)
        result = delete_provider(tenant_id, instance.id)

        assert result
        with pytest.raises(ObjectDoesNotExist):
            Provider.objects.get(pk=instance.id)
        graph_db_mocks["drop_tenant_provider_database"].assert_called_once_with(
            tenant_id, instance.provider, str(instance.id)
        )
        graph_db_mocks["drop_tenant_databases"].assert_not_called()

    def test_delete_provider_does_not_exist(self, tenants_fixture, graph_db_mocks):
        tenant_id = str(tenants_fixture[0].id)
        non_existent_pk = "babf6796-cfcc-4fd3-9dcf-88d012247645"

        with pytest.raises(ObjectDoesNotExist):
            delete_provider(tenant_id, non_existent_pk)
        graph_db_mocks["drop_tenant_provider_database"].assert_not_called()
        graph_db_mocks["drop_tenant_databases"].assert_not_called()


@pytest.mark.django_db
class TestDeleteTenant:
    def test_delete_tenant_success(
        self, tenants_fixture, providers_fixture, graph_db_mocks
    ):
        """
        Test successful deletion of a tenant and its related data.
        """
        tenant = tenants_fixture[0]
        providers = list(Provider.objects.filter(tenant_id=tenant.id))

        # Ensure the tenant and related providers exist before deletion
        assert Tenant.objects.filter(id=tenant.id).exists()
        assert providers

        # Call the function and validate the result
        deletion_summary = delete_tenant(tenant.id)

        assert deletion_summary is not None
        assert not Tenant.objects.filter(id=tenant.id).exists()
        assert not Provider.objects.filter(tenant_id=tenant.id).exists()

        expected_calls = [
            call(str(provider.tenant_id), provider.provider, str(provider.id))
            for provider in providers
        ]
        graph_db_mocks["drop_tenant_provider_database"].assert_has_calls(
            expected_calls, any_order=True
        )
        assert graph_db_mocks["drop_tenant_provider_database"].call_count == len(
            expected_calls
        )
        graph_db_mocks["drop_tenant_databases"].assert_called_once_with(
            tenant_id=tenant.id
        )

    def test_delete_tenant_with_no_providers(self, tenants_fixture, graph_db_mocks):
        """
        Test deletion of a tenant with no related providers.
        """
        tenant = tenants_fixture[1]  # Assume this tenant has no providers
        providers = Provider.objects.filter(tenant_id=tenant.id)

        # Ensure the tenant exists but has no related providers
        assert Tenant.objects.filter(id=tenant.id).exists()
        assert not providers.exists()

        # Call the function and validate the result
        deletion_summary = delete_tenant(tenant.id)

        assert deletion_summary == {}  # No providers, so empty summary
        assert not Tenant.objects.filter(id=tenant.id).exists()
        graph_db_mocks["drop_tenant_provider_database"].assert_not_called()
        graph_db_mocks["drop_tenant_databases"].assert_called_once_with(
            tenant_id=tenant.id
        )
