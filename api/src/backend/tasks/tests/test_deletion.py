from unittest.mock import patch

import pytest
from django.core.exceptions import ObjectDoesNotExist
from tasks.jobs.deletion import delete_provider, delete_tenant

from api.models import Provider, Tenant


@pytest.mark.django_db
class TestDeleteProvider:
    def test_delete_provider_success(self, providers_fixture):
        instance = providers_fixture[0]
        result = delete_provider(instance.id)

        assert result
        with pytest.raises(ObjectDoesNotExist):
            Provider.objects.get(pk=instance.id)

    def test_delete_provider_does_not_exist(self):
        non_existent_pk = "babf6796-cfcc-4fd3-9dcf-88d012247645"

        with pytest.raises(ObjectDoesNotExist):
            delete_provider(non_existent_pk)


@patch("api.db_router.MainRouter.admin_db", new="default")
@pytest.mark.django_db
class TestDeleteTenant:
    def test_delete_tenant_success(self, tenants_fixture, providers_fixture):
        """
        Test successful deletion of a tenant and its related data.
        """
        tenant = tenants_fixture[0]
        providers = Provider.objects.filter(tenant_id=tenant.id)

        # Ensure the tenant and related providers exist before deletion
        assert Tenant.objects.filter(id=tenant.id).exists()
        assert providers.exists()

        # Call the function and validate the result
        deletion_summary = delete_tenant(tenant.id)

        assert deletion_summary is not None
        assert not Tenant.objects.filter(id=tenant.id).exists()
        assert not Provider.objects.filter(tenant_id=tenant.id).exists()

    def test_delete_tenant_with_no_providers(self, tenants_fixture):
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
