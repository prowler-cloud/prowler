from unittest.mock import call, patch

import pytest
from django.core.exceptions import ObjectDoesNotExist
from tasks.jobs.deletion import delete_provider, delete_tenant

from api.attack_paths import database as graph_database
from api.models import Provider, Tenant, TenantComplianceSummary


@pytest.mark.django_db
class TestDeleteProvider:
    def test_delete_provider_success(self, providers_fixture):
        with (
            patch(
                "tasks.jobs.deletion.graph_database.get_database_name",
                return_value="tenant-db",
            ) as mock_get_database_name,
            patch(
                "tasks.jobs.deletion.graph_database.drop_subgraph"
            ) as mock_drop_subgraph,
        ):
            instance = providers_fixture[0]
            tenant_id = str(instance.tenant_id)
            result = delete_provider(tenant_id, instance.id)

            assert result
            with pytest.raises(ObjectDoesNotExist):
                Provider.objects.get(pk=instance.id)

            mock_get_database_name.assert_called_once_with(tenant_id)
            mock_drop_subgraph.assert_called_once_with(
                "tenant-db",
                str(instance.id),
            )

    def test_delete_provider_does_not_exist(self, tenants_fixture):
        with (
            patch(
                "tasks.jobs.deletion.graph_database.get_database_name",
                return_value="tenant-db",
            ) as mock_get_database_name,
            patch(
                "tasks.jobs.deletion.graph_database.drop_subgraph"
            ) as mock_drop_subgraph,
        ):
            tenant_id = str(tenants_fixture[0].id)
            non_existent_pk = "babf6796-cfcc-4fd3-9dcf-88d012247645"

            result = delete_provider(tenant_id, non_existent_pk)

            assert result == {}
            mock_get_database_name.assert_not_called()
            mock_drop_subgraph.assert_not_called()

    def test_delete_provider_drops_temp_attack_paths_databases(
        self, providers_fixture, create_attack_paths_scan
    ):
        instance = providers_fixture[0]
        tenant_id = str(instance.tenant_id)

        aps1 = create_attack_paths_scan(instance)
        aps2 = create_attack_paths_scan(instance)

        with (
            patch(
                "tasks.jobs.deletion.graph_database.drop_subgraph",
            ),
            patch(
                "tasks.jobs.deletion.graph_database.drop_database",
            ) as mock_drop_database,
        ):
            result = delete_provider(tenant_id, instance.id)

        assert result
        expected_tmp_calls = [
            call(f"db-tmp-scan-{str(aps1.id).lower()}"),
            call(f"db-tmp-scan-{str(aps2.id).lower()}"),
        ]
        mock_drop_database.assert_has_calls(expected_tmp_calls, any_order=True)

    def test_delete_provider_continues_when_temp_db_drop_fails(
        self, providers_fixture, create_attack_paths_scan
    ):
        instance = providers_fixture[0]
        tenant_id = str(instance.tenant_id)

        create_attack_paths_scan(instance)

        with (
            patch(
                "tasks.jobs.deletion.graph_database.drop_subgraph",
            ),
            patch(
                "tasks.jobs.deletion.graph_database.drop_database",
                side_effect=graph_database.GraphDatabaseQueryException(
                    "Neo4j unreachable"
                ),
            ),
        ):
            result = delete_provider(tenant_id, instance.id)

        assert result
        assert not Provider.all_objects.filter(pk=instance.id).exists()

    def test_delete_provider_recalculates_tenant_compliance_summary(
        self,
        providers_fixture,
        provider_compliance_scores_fixture,
    ):
        instance = providers_fixture[0]
        tenant_id = instance.tenant_id

        TenantComplianceSummary.objects.create(
            tenant_id=tenant_id,
            compliance_id="aws_cis_2.0",
            requirements_passed=99,
            requirements_failed=99,
            requirements_manual=99,
            total_requirements=99,
        )
        TenantComplianceSummary.objects.create(
            tenant_id=tenant_id,
            compliance_id="gdpr_aws",
            requirements_passed=99,
            requirements_failed=99,
            requirements_manual=99,
            total_requirements=99,
        )

        with (
            patch(
                "tasks.jobs.deletion.graph_database.get_database_name",
                return_value="tenant-db",
            ),
            patch("tasks.jobs.deletion.graph_database.drop_subgraph"),
        ):
            delete_provider(str(tenant_id), instance.id)

        updated_summary = TenantComplianceSummary.objects.get(
            tenant_id=tenant_id,
            compliance_id="aws_cis_2.0",
        )
        assert updated_summary.requirements_passed == 1
        assert updated_summary.requirements_failed == 1
        assert updated_summary.requirements_manual == 0
        assert updated_summary.total_requirements == 2
        assert not TenantComplianceSummary.objects.filter(
            tenant_id=tenant_id,
            compliance_id="gdpr_aws",
        ).exists()


@pytest.mark.django_db
class TestDeleteTenant:
    def test_delete_tenant_success(self, tenants_fixture, providers_fixture):
        """
        Test successful deletion of a tenant and its related data.
        """
        with (
            patch(
                "tasks.jobs.deletion.graph_database.get_database_name",
                return_value="tenant-db",
            ) as mock_get_database_name,
            patch(
                "tasks.jobs.deletion.graph_database.drop_subgraph"
            ) as mock_drop_subgraph,
            patch(
                "tasks.jobs.deletion.graph_database.drop_database"
            ) as mock_drop_database,
        ):
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

            # get_database_name is called once per provider + once for drop_database
            expected_get_db_calls = [call(tenant.id) for _ in providers] + [
                call(tenant.id)
            ]
            mock_get_database_name.assert_has_calls(
                expected_get_db_calls, any_order=True
            )
            assert mock_get_database_name.call_count == len(expected_get_db_calls)

            expected_drop_subgraph_calls = [
                call("tenant-db", str(provider.id)) for provider in providers
            ]
            mock_drop_subgraph.assert_has_calls(
                expected_drop_subgraph_calls,
                any_order=True,
            )
            assert mock_drop_subgraph.call_count == len(expected_drop_subgraph_calls)

            mock_drop_database.assert_called_once_with("tenant-db")

    def test_delete_tenant_with_no_providers(self, tenants_fixture):
        """
        Test deletion of a tenant with no related providers.
        """
        with (
            patch(
                "tasks.jobs.deletion.graph_database.get_database_name",
                return_value="tenant-db",
            ) as mock_get_database_name,
            patch(
                "tasks.jobs.deletion.graph_database.drop_subgraph"
            ) as mock_drop_subgraph,
            patch(
                "tasks.jobs.deletion.graph_database.drop_database"
            ) as mock_drop_database,
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

            # get_database_name is called once for drop_database
            mock_get_database_name.assert_called_once_with(tenant.id)
            mock_drop_subgraph.assert_not_called()
            mock_drop_database.assert_called_once_with("tenant-db")

    def test_delete_tenant_includes_soft_deleted_providers(self, tenants_fixture):
        tenant = tenants_fixture[0]
        provider = Provider.objects.create(
            provider="aws",
            uid="999999999999",
            alias="soft_deleted_provider",
            tenant_id=tenant.id,
        )
        # Soft-delete the provider so ActiveProviderManager would skip it
        Provider.all_objects.filter(pk=provider.id).update(is_deleted=True)

        with (
            patch(
                "tasks.jobs.deletion.graph_database.get_database_name",
                return_value="tenant-db",
            ),
            patch(
                "tasks.jobs.deletion.graph_database.drop_subgraph"
            ) as mock_drop_subgraph,
            patch("tasks.jobs.deletion.graph_database.drop_database"),
        ):
            delete_tenant(tenant.id)

            mock_drop_subgraph.assert_any_call("tenant-db", str(provider.id))

    def test_delete_tenant_handles_concurrently_deleted_provider(self, tenants_fixture):
        tenant = tenants_fixture[0]
        Provider.objects.create(
            provider="aws",
            uid="111111111111",
            alias="vanishing_provider",
            tenant_id=tenant.id,
        )

        def drop_subgraph_side_effect(_db_name, provider_id):
            # Simulate concurrent deletion by another process
            Provider.all_objects.filter(pk=provider_id).delete()

        with (
            patch(
                "tasks.jobs.deletion.graph_database.get_database_name",
                return_value="tenant-db",
            ),
            patch(
                "tasks.jobs.deletion.graph_database.drop_subgraph",
                side_effect=drop_subgraph_side_effect,
            ),
            patch("tasks.jobs.deletion.graph_database.drop_database"),
        ):
            deletion_summary = delete_tenant(tenant.id)

            assert deletion_summary is not None
