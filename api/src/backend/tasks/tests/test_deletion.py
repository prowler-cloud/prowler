from unittest.mock import call, patch

import pytest

from django.core.exceptions import ObjectDoesNotExist

from api.models import Provider, Tenant
from tasks.jobs.deletion import delete_provider, delete_tenant


@pytest.mark.django_db
class TestDeleteProvider:
    def test_delete_provider_success(self, providers_fixture):
        with patch(
            "tasks.jobs.deletion.get_provider_graph_database_names"
        ) as mock_get_provider_graph_database_names, patch(
            "tasks.jobs.deletion.graph_database.drop_database"
        ) as mock_drop_database:
            graph_db_names = ["graph-db-1", "graph-db-2"]
            mock_get_provider_graph_database_names.return_value = graph_db_names

            instance = providers_fixture[0]
            tenant_id = str(instance.tenant_id)
            result = delete_provider(tenant_id, instance.id)

            assert result
            with pytest.raises(ObjectDoesNotExist):
                Provider.objects.get(pk=instance.id)

            mock_get_provider_graph_database_names.assert_called_once_with(
                tenant_id, instance.id
            )
            mock_drop_database.assert_has_calls(
                [call(graph_db_name) for graph_db_name in graph_db_names]
            )

    def test_delete_provider_does_not_exist(self, tenants_fixture):
        with patch(
            "tasks.jobs.deletion.get_provider_graph_database_names"
        ) as mock_get_provider_graph_database_names, patch(
            "tasks.jobs.deletion.graph_database.drop_database"
        ) as mock_drop_database:
            graph_db_names = ["graph-db-1"]
            mock_get_provider_graph_database_names.return_value = graph_db_names

            tenant_id = str(tenants_fixture[0].id)
            non_existent_pk = "babf6796-cfcc-4fd3-9dcf-88d012247645"

            with pytest.raises(ObjectDoesNotExist):
                delete_provider(tenant_id, non_existent_pk)

            mock_get_provider_graph_database_names.assert_called_once_with(
                tenant_id, non_existent_pk
            )
            mock_drop_database.assert_has_calls(
                [call(graph_db_name) for graph_db_name in graph_db_names]
            )


@pytest.mark.django_db
class TestDeleteTenant:
    def test_delete_tenant_success(self, tenants_fixture, providers_fixture):
        """
        Test successful deletion of a tenant and its related data.
        """
        with patch(
            "tasks.jobs.deletion.get_provider_graph_database_names"
        ) as mock_get_provider_graph_database_names, patch(
            "tasks.jobs.deletion.graph_database.drop_database"
        ) as mock_drop_database:
            tenant = tenants_fixture[0]
            providers = list(Provider.objects.filter(tenant_id=tenant.id))

            graph_db_names_per_provider = [
                [f"graph-db-{provider.id}"] for provider in providers
            ]
            mock_get_provider_graph_database_names.side_effect = (
                graph_db_names_per_provider
            )

            # Ensure the tenant and related providers exist before deletion
            assert Tenant.objects.filter(id=tenant.id).exists()
            assert providers

            # Call the function and validate the result
            deletion_summary = delete_tenant(tenant.id)

            assert deletion_summary is not None
            assert not Tenant.objects.filter(id=tenant.id).exists()
            assert not Provider.objects.filter(tenant_id=tenant.id).exists()

            expected_calls = [
                call(provider.tenant_id, provider.id) for provider in providers
            ]
            mock_get_provider_graph_database_names.assert_has_calls(
                expected_calls, any_order=True
            )
            assert mock_get_provider_graph_database_names.call_count == len(
                expected_calls
            )
            expected_drop_calls = [
                call(graph_db_name[0]) for graph_db_name in graph_db_names_per_provider
            ]
            mock_drop_database.assert_has_calls(expected_drop_calls, any_order=True)
            assert mock_drop_database.call_count == len(expected_drop_calls)

    def test_delete_tenant_with_no_providers(self, tenants_fixture):
        """
        Test deletion of a tenant with no related providers.
        """
        with patch(
            "tasks.jobs.deletion.get_provider_graph_database_names"
        ) as mock_get_provider_graph_database_names, patch(
            "tasks.jobs.deletion.graph_database.drop_database"
        ) as mock_drop_database:
            tenant = tenants_fixture[1]  # Assume this tenant has no providers
            providers = Provider.objects.filter(tenant_id=tenant.id)

            # Ensure the tenant exists but has no related providers
            assert Tenant.objects.filter(id=tenant.id).exists()
            assert not providers.exists()

            # Call the function and validate the result
            deletion_summary = delete_tenant(tenant.id)

            assert deletion_summary == {}  # No providers, so empty summary
            assert not Tenant.objects.filter(id=tenant.id).exists()

            mock_get_provider_graph_database_names.assert_not_called()
            mock_drop_database.assert_not_called()
