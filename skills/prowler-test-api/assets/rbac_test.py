# Example: RBAC Test Patterns
# Source: api/src/backend/api/tests/

import pytest
from django.urls import reverse
from rest_framework import status

from api.db_utils import rls_transaction
from api.models import (
    ProviderGroup,
    ProviderGroupMembership,
    Role,
    RoleProviderGroupRelationship,
    UserRoleRelationship,
)
from api.v1.serializers import TokenSerializer

# =============================================================================
# 1. Visibility Tests - unlimited_visibility flag
# =============================================================================


@pytest.mark.django_db
class TestUnlimitedVisibility:
    """Test users with unlimited_visibility flag."""

    def test_admin_sees_all_providers(
        self, authenticated_client_admin, providers_fixture
    ):
        """Admin with unlimited_visibility sees all providers in tenant."""
        response = authenticated_client_admin.get(reverse("provider-list"))

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(providers_fixture)

    def test_admin_can_access_any_resource(
        self, authenticated_client_admin, providers_fixture
    ):
        """Admin can retrieve any provider in tenant."""
        for provider in providers_fixture:
            response = authenticated_client_admin.get(
                reverse("provider-detail", args=[provider.id])
            )
            assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
class TestLimitedVisibility:
    """Test users with limited visibility (provider_groups)."""

    def test_limited_sees_only_assigned(
        self, authenticated_client_limited, provider_group_fixture
    ):
        """User without unlimited_visibility sees only providers in their group."""
        response = authenticated_client_limited.get(reverse("provider-list"))

        assert response.status_code == status.HTTP_200_OK

        returned_ids = {p["id"] for p in response.json()["data"]}
        expected_ids = {str(p.id) for p in provider_group_fixture.providers.all()}
        assert returned_ids == expected_ids

    def test_limited_cannot_see_unassigned(
        self, authenticated_client_limited, providers_fixture, provider_group_fixture
    ):
        """User cannot access providers not in their groups."""
        # Find provider NOT in the group
        group_providers = set(
            provider_group_fixture.providers.values_list("id", flat=True)
        )
        unassigned = [p for p in providers_fixture if p.id not in group_providers]

        if unassigned:
            response = authenticated_client_limited.get(
                reverse("provider-detail", args=[unassigned[0].id])
            )
            assert response.status_code == status.HTTP_404_NOT_FOUND


# =============================================================================
# 2. Permission Flag Tests
# =============================================================================


@pytest.mark.django_db
class TestManageProvidersPermission:
    """Test manage_providers permission flag."""

    def test_with_permission_can_create(
        self, authenticated_client_with_manage_providers
    ):
        """User with manage_providers can create providers."""
        payload = {
            "data": {
                "type": "providers",
                "attributes": {
                    "provider": "aws",
                    "uid": "123456789012",
                    "alias": "test-provider",
                },
            }
        }
        response = authenticated_client_with_manage_providers.post(
            reverse("provider-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

    def test_without_permission_cannot_create(self, authenticated_client_readonly):
        """User without manage_providers gets 403."""
        payload = {
            "data": {
                "type": "providers",
                "attributes": {
                    "provider": "aws",
                    "uid": "123456789012",
                    "alias": "test",
                },
            }
        }
        response = authenticated_client_readonly.post(
            reverse("provider-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_without_permission_can_read(
        self, authenticated_client_readonly, providers_fixture
    ):
        """User without manage_providers can still read."""
        response = authenticated_client_readonly.get(reverse("provider-list"))
        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# 3. Provider Group Tests
# =============================================================================


@pytest.mark.django_db
class TestProviderGroups:
    """Test provider group management."""

    def test_create_provider_group(self, authenticated_client_admin):
        """Admin can create provider groups."""
        payload = {
            "data": {
                "type": "provider-groups",
                "attributes": {"name": "Production AWS Accounts"},
            }
        }
        response = authenticated_client_admin.post(
            reverse("providergroup-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

    def test_add_provider_to_group(
        self, authenticated_client_admin, providers_fixture, provider_group_fixture
    ):
        """Admin can add providers to groups."""
        provider = providers_fixture[0]
        payload = {
            "data": {
                "type": "provider-groups",
                "id": str(provider_group_fixture.id),
                "relationships": {
                    "providers": {
                        "data": [{"type": "providers", "id": str(provider.id)}]
                    }
                },
            }
        }
        response = authenticated_client_admin.patch(
            reverse("providergroup-detail", args=[provider_group_fixture.id]),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# 4. Fixtures
# =============================================================================


@pytest.fixture
def authenticated_client_admin(create_test_user, tenants_fixture, client):
    """Client with unlimited_visibility and all permissions."""
    user = create_test_user
    tenant = tenants_fixture[0]

    with rls_transaction(str(tenant.id)):
        role = Role.objects.create(
            tenant_id=tenant.id,
            name="admin",
            unlimited_visibility=True,
            manage_users=True,
            manage_account=True,
            manage_providers=True,
            manage_integrations=True,
            manage_scans=True,
        )
        UserRoleRelationship.objects.create(user=user, role=role, tenant_id=tenant.id)

    return _get_authenticated_client(client, user, tenant)


@pytest.fixture
def authenticated_client_limited(
    create_test_user, tenants_fixture, provider_group_fixture, client
):
    """Client with limited visibility to specific provider group."""
    user = create_test_user
    tenant = tenants_fixture[0]

    with rls_transaction(str(tenant.id)):
        role = Role.objects.create(
            tenant_id=tenant.id,
            name="limited-viewer",
            unlimited_visibility=False,
            manage_scans=True,
        )
        RoleProviderGroupRelationship.objects.create(
            role=role,
            provider_group=provider_group_fixture,
            tenant_id=tenant.id,
        )
        UserRoleRelationship.objects.create(user=user, role=role, tenant_id=tenant.id)

    return _get_authenticated_client(client, user, tenant)


@pytest.fixture
def authenticated_client_readonly(create_test_user, tenants_fixture, client):
    """Client with no write permissions."""
    user = create_test_user
    tenant = tenants_fixture[0]

    with rls_transaction(str(tenant.id)):
        role = Role.objects.create(
            tenant_id=tenant.id,
            name="readonly",
            unlimited_visibility=True,
            manage_providers=False,
            manage_scans=False,
        )
        UserRoleRelationship.objects.create(user=user, role=role, tenant_id=tenant.id)

    return _get_authenticated_client(client, user, tenant)


@pytest.fixture
def authenticated_client_with_manage_providers(
    create_test_user, tenants_fixture, client
):
    """Client with manage_providers permission only."""
    user = create_test_user
    tenant = tenants_fixture[0]

    with rls_transaction(str(tenant.id)):
        role = Role.objects.create(
            tenant_id=tenant.id,
            name="provider-manager",
            unlimited_visibility=True,
            manage_providers=True,
        )
        UserRoleRelationship.objects.create(user=user, role=role, tenant_id=tenant.id)

    return _get_authenticated_client(client, user, tenant)


@pytest.fixture
def provider_group_fixture(tenants_fixture, providers_fixture):
    """Provider group with first provider."""
    tenant = tenants_fixture[0]

    with rls_transaction(str(tenant.id)):
        group = ProviderGroup.objects.create(
            tenant_id=tenant.id,
            name="Test Provider Group",
        )
        # Add first provider only
        ProviderGroupMembership.objects.create(
            tenant_id=tenant.id,
            provider_group=group,
            provider=providers_fixture[0],
        )

    return group


def _get_authenticated_client(client, user, tenant):
    """Helper to get authenticated client."""
    serializer = TokenSerializer(
        data={
            "type": "tokens",
            "email": user.email,
            "password": "testing_psswd",
            "tenant_id": str(tenant.id),
        }
    )
    serializer.is_valid()
    access_token = serializer.validated_data["access"]

    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"
    client.tenant = tenant
    client.user = user

    return client
