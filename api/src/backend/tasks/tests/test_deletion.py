from unittest.mock import call, patch

import pytest

from django.core.exceptions import ObjectDoesNotExist

from api.models import Provider, Tenant
from tasks.jobs.attack_paths import providers
from tasks.jobs.deletion import delete_provider, delete_tenant


@pytest.mark.django_db
class TestDeleteProvider:
    def test_delete_provider_success(self, providers_fixture):
        with (
            patch("tasks.jobs.deletion.graph_database.get_database_name", return_value="tenant-db"),
            patch("tasks.jobs.deletion.graph_database.drop_subgraph") as mock_drop_subgraph,
        ):
            instance = providers_fixture[0]
            tenant_id = str(instance.tenant_id)
            result = delete_provider(tenant_id, instance.id)

            assert result
            with pytest.raises(ObjectDoesNotExist):
                Provider.objects.get(pk=instance.id)

            mock_drop_subgraph.assert_called_once_with(
                "tenant-db",
                providers.get_root_node_label(instance.provider),
                str(instance.uid),
            )

    def test_delete_provider_does_not_exist(self, tenants_fixture):
        with patch("tasks.jobs.deletion.graph_database.drop_subgraph") as mock_drop_subgraph:
            tenant_id = str(tenants_fixture[0].id)
            non_existent_pk = "babf6796-cfcc-4fd3-9dcf-88d012247645"

            with pytest.raises(ObjectDoesNotExist):
                delete_provider(tenant_id, non_existent_pk)

            mock_drop_subgraph.assert_not_called()


@pytest.mark.django_db
class TestDeleteTenant:
    def test_delete_tenant_success(self, tenants_fixture, providers_fixture):
        """
        Test successful deletion of a tenant and its related data.
        """
        with (
            patch("tasks.jobs.deletion.graph_database.get_database_name", side_effect=lambda tenant_id: f"db-{tenant_id}"),
            patch("tasks.jobs.deletion.graph_database.drop_subgraph") as mock_drop_subgraph,
            patch("tasks.jobs.deletion.graph_database.drop_database") as mock_drop_database,
        ):
            tenant = tenants_fixture[0]
            provider_list = list(Provider.objects.filter(tenant_id=tenant.id))

            # Ensure the tenant and related providers exist before deletion
            assert Tenant.objects.filter(id=tenant.id).exists()
            assert provider_list

            # Call the function and validate the result
            deletion_summary = delete_tenant(tenant.id)

            assert deletion_summary is not None
            assert not Tenant.objects.filter(id=tenant.id).exists()
            assert not Provider.objects.filter(tenant_id=tenant.id).exists()

            expected_subgraph_calls = [
                call(
                    f"db-{tenant.id}",
                    providers.get_root_node_label(provider.provider),
                    provider.uid,
                )
                for provider in provider_list
            ]
            mock_drop_subgraph.assert_has_calls(expected_subgraph_calls, any_order=True)
            assert mock_drop_subgraph.call_count == len(expected_subgraph_calls)

            mock_drop_database.assert_called_once_with(f"db-{tenant.id}")

    def test_delete_tenant_with_no_providers(self, tenants_fixture):
        """
        Test deletion of a tenant with no related providers.
        """
        with (
            patch("tasks.jobs.deletion.graph_database.drop_subgraph") as mock_drop_subgraph,
            patch("tasks.jobs.deletion.graph_database.get_database_name", side_effect=lambda tenant_id: f"db-{tenant_id}"),
            patch("tasks.jobs.deletion.graph_database.drop_database") as mock_drop_database,
        ):
            tenant = tenants_fixture[1]  # Assume this tenant has no providers
            providers = Provider.objects.filter(tenant_id=tenant.id)

            # Ensure the tenant exists but has no related providers
            assert Tenant.objects.filter(id=tenant.id).exists()
            assert not providers.exists()

            # Call the function and validate the result
            deletion_summary = delete_tenant(tenant.id)

            assert deletion_summary == {}  # No providers, so empty summary
            assert not Tenant.objects.filter(id=tenant.id).exists()

            mock_drop_subgraph.assert_not_called()
            mock_drop_database.assert_called_once_with(f"db-{tenant.id}")
