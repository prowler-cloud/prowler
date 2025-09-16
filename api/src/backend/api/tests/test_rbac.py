import json
from unittest.mock import ANY, Mock, patch

import pytest
from conftest import TODAY
from django.urls import reverse
from rest_framework import status

from api.models import (
    Membership,
    ProviderGroup,
    ProviderGroupMembership,
    Role,
    RoleProviderGroupRelationship,
    User,
    UserRoleRelationship,
)
from api.v1.serializers import TokenSerializer


@pytest.mark.django_db
class TestUserViewSet:
    def test_list_users_with_all_permissions(self, authenticated_client_rbac):
        response = authenticated_client_rbac.get(reverse("user-list"))
        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.json()["data"], list)

    def test_list_users_with_no_permissions(
        self, authenticated_client_no_permissions_rbac
    ):
        response = authenticated_client_no_permissions_rbac.get(reverse("user-list"))
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_retrieve_user_with_all_permissions(
        self, authenticated_client_rbac, create_test_user_rbac
    ):
        response = authenticated_client_rbac.get(
            reverse("user-detail", kwargs={"pk": create_test_user_rbac.id})
        )
        assert response.status_code == status.HTTP_200_OK
        assert (
            response.json()["data"]["attributes"]["email"]
            == create_test_user_rbac.email
        )

    def test_retrieve_user_with_no_roles(
        self, authenticated_client_rbac_noroles, create_test_user_rbac_no_roles
    ):
        response = authenticated_client_rbac_noroles.get(
            reverse("user-detail", kwargs={"pk": create_test_user_rbac_no_roles.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_retrieve_user_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, create_test_user
    ):
        response = authenticated_client_no_permissions_rbac.get(
            reverse("user-detail", kwargs={"pk": create_test_user.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_create_user_with_all_permissions(self, authenticated_client_rbac):
        valid_user_payload = {
            "name": "test",
            "password": "Newpassword123@",
            "email": "new_user@test.com",
        }
        response = authenticated_client_rbac.post(
            reverse("user-list"), data=valid_user_payload, format="vnd.api+json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["data"]["attributes"]["email"] == "new_user@test.com"

    def test_create_user_with_no_permissions(
        self, authenticated_client_no_permissions_rbac
    ):
        valid_user_payload = {
            "name": "test",
            "password": "Newpassword123@",
            "email": "new_user@test.com",
        }
        response = authenticated_client_no_permissions_rbac.post(
            reverse("user-list"), data=valid_user_payload, format="vnd.api+json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["data"]["attributes"]["email"] == "new_user@test.com"

    def test_partial_update_user_with_all_permissions(
        self, authenticated_client_rbac, create_test_user_rbac
    ):
        updated_data = {
            "data": {
                "type": "users",
                "id": str(create_test_user_rbac.id),
                "attributes": {"name": "Updated Name"},
            },
        }
        response = authenticated_client_rbac.patch(
            reverse("user-detail", kwargs={"pk": create_test_user_rbac.id}),
            data=updated_data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["name"] == "Updated Name"

    def test_partial_update_user_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, create_test_user
    ):
        updated_data = {
            "data": {
                "type": "users",
                "attributes": {"name": "Updated Name"},
            }
        }
        response = authenticated_client_no_permissions_rbac.patch(
            reverse("user-detail", kwargs={"pk": create_test_user.id}),
            data=updated_data,
            format="vnd.api+json",
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_delete_user_with_all_permissions(
        self, authenticated_client_rbac, create_test_user_rbac
    ):
        response = authenticated_client_rbac.delete(
            reverse("user-detail", kwargs={"pk": create_test_user_rbac.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_delete_user_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, create_test_user
    ):
        response = authenticated_client_no_permissions_rbac.delete(
            reverse("user-detail", kwargs={"pk": create_test_user.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_me_with_all_permissions(
        self, authenticated_client_rbac, create_test_user_rbac
    ):
        response = authenticated_client_rbac.get(reverse("user-me"))
        assert response.status_code == status.HTTP_200_OK
        assert (
            response.json()["data"]["attributes"]["email"]
            == create_test_user_rbac.email
        )

    def test_me_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, create_test_user
    ):
        response = authenticated_client_no_permissions_rbac.get(reverse("user-me"))
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["email"] == "rbac_limited@rbac.com"

    def test_me_shows_own_roles_and_memberships_without_manage_account(
        self, authenticated_client_no_permissions_rbac
    ):
        response = authenticated_client_no_permissions_rbac.get(reverse("user-me"))
        assert response.status_code == status.HTTP_200_OK

        rels = response.json()["data"]["relationships"]

        # Self should see own roles and memberships even without manage_account
        assert isinstance(rels["roles"]["data"], list)
        assert rels["memberships"]["meta"]["count"] == 1

    def test_me_shows_roles_and_memberships_with_manage_account(
        self, authenticated_client_rbac
    ):
        response = authenticated_client_rbac.get(reverse("user-me"))
        assert response.status_code == status.HTTP_200_OK

        rels = response.json()["data"]["relationships"]

        # Roles should have data when manage_account is True
        assert len(rels["roles"]["data"]) > 0

        # Memberships should be present and count > 0
        assert rels["memberships"]["meta"]["count"] > 0

    def test_me_include_roles_and_memberships_included_block(
        self, authenticated_client_rbac
    ):
        # Request current user info including roles and memberships
        response = authenticated_client_rbac.get(
            reverse("user-me"), {"include": "roles,memberships"}
        )
        assert response.status_code == status.HTTP_200_OK
        payload = response.json()

        # Included must contain memberships corresponding to relationships data
        rel_memberships = payload["data"]["relationships"]["memberships"]
        ids_in_relationship = {item["id"] for item in rel_memberships["data"]}

        included = payload["included"]
        included_membership_ids = {
            item["id"] for item in included if item["type"] == "memberships"
        }

        # If there are memberships in relationships, they must be present in included
        if ids_in_relationship:
            assert ids_in_relationship.issubset(included_membership_ids)
        else:
            # At minimum, included should contain the user's membership when requested
            # (count should align with meta count)
            assert rel_memberships["meta"]["count"] == len(included_membership_ids)

    def test_list_users_with_manage_account_only_forbidden(
        self, authenticated_client_rbac_manage_account
    ):
        response = authenticated_client_rbac_manage_account.get(reverse("user-list"))
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_retrieve_other_user_with_manage_account_only_forbidden(
        self, authenticated_client_rbac_manage_account, create_test_user
    ):
        response = authenticated_client_rbac_manage_account.get(
            reverse("user-detail", kwargs={"pk": create_test_user.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_list_users_with_manage_users_only_hides_relationships(
        self, authenticated_client_rbac_manage_users_only
    ):
        # Ensure there is at least one other user in the same tenant
        mu_user = authenticated_client_rbac_manage_users_only.user
        mu_membership = Membership.objects.filter(user=mu_user).first()
        tenant = mu_membership.tenant

        other_user = User.objects.create_user(
            name="other_in_tenant",
            email="other_in_tenant@rbac.com",
            password="Password123@",
        )
        Membership.objects.create(user=other_user, tenant=tenant)

        response = authenticated_client_rbac_manage_users_only.get(reverse("user-list"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert isinstance(data, list)

        current_user_id = str(mu_user.id)
        assert any(item["id"] == current_user_id for item in data)

        for item in data:
            rels = item["relationships"]
            if item["id"] == current_user_id:
                # Self should see own relationships
                assert isinstance(rels["roles"]["data"], list)
                assert rels["memberships"]["meta"].get("count", 0) >= 1
            else:
                # Others should be hidden without manage_account
                assert rels["roles"]["data"] == []
                assert rels["memberships"]["data"] == []
                assert rels["memberships"]["meta"]["count"] == 0

    def test_include_roles_hidden_without_manage_account(
        self, authenticated_client_rbac_manage_users_only
    ):
        # Arrange: ensure another user in the same tenant with its own role
        mu_user = authenticated_client_rbac_manage_users_only.user
        mu_membership = Membership.objects.filter(user=mu_user).first()
        tenant = mu_membership.tenant

        other_user = User.objects.create_user(
            name="other_in_tenant_inc",
            email="other_in_tenant_inc@rbac.com",
            password="Password123@",
        )
        Membership.objects.create(user=other_user, tenant=tenant)
        other_role = Role.objects.create(
            name="other_inc_role",
            tenant_id=tenant.id,
            manage_users=False,
            manage_account=False,
        )
        UserRoleRelationship.objects.create(
            user=other_user, role=other_role, tenant_id=tenant.id
        )

        response = authenticated_client_rbac_manage_users_only.get(
            reverse("user-list"), {"include": "roles"}
        )
        assert response.status_code == status.HTTP_200_OK
        payload = response.json()

        # Assert: included must not contain the other user's role
        included = payload.get("included", [])
        included_role_ids = {
            item["id"] for item in included if item.get("type") == "roles"
        }
        assert str(other_role.id) not in included_role_ids

        # Relationships for other user should be empty
        for item in payload["data"]:
            if item["id"] == str(other_user.id):
                rels = item["relationships"]
                assert rels["roles"]["data"] == []

    def test_include_roles_visible_with_manage_account(
        self, authenticated_client_rbac, tenants_fixture
    ):
        # Arrange: another user in tenant[0] with its role
        tenant = tenants_fixture[0]
        other_user = User.objects.create_user(
            name="other_with_role",
            email="other_with_role@rbac.com",
            password="Password123@",
        )
        Membership.objects.create(user=other_user, tenant=tenant)
        other_role = Role.objects.create(
            name="other_visible_role",
            tenant_id=tenant.id,
            manage_users=False,
            manage_account=False,
        )
        UserRoleRelationship.objects.create(
            user=other_user, role=other_role, tenant_id=tenant.id
        )

        response = authenticated_client_rbac.get(
            reverse("user-list"), {"include": "roles"}
        )
        assert response.status_code == status.HTTP_200_OK
        payload = response.json()

        # Assert: included must contain the other user's role
        included = payload.get("included", [])
        included_role_ids = {
            item["id"] for item in included if item.get("type") == "roles"
        }
        assert str(other_role.id) in included_role_ids

    def test_retrieve_user_with_manage_users_only_hides_relationships(
        self, authenticated_client_rbac_manage_users_only
    ):
        # Create a target user in the same tenant to ensure visibility
        mu_user = authenticated_client_rbac_manage_users_only.user
        mu_membership = Membership.objects.filter(user=mu_user).first()
        tenant = mu_membership.tenant

        target_user = User.objects.create_user(
            name="target_same_tenant",
            email="target_same_tenant@rbac.com",
            password="Password123@",
        )
        Membership.objects.create(user=target_user, tenant=tenant)

        response = authenticated_client_rbac_manage_users_only.get(
            reverse("user-detail", kwargs={"pk": target_user.id})
        )
        assert response.status_code == status.HTTP_200_OK
        rels = response.json()["data"]["relationships"]
        assert rels["roles"]["data"] == []
        assert rels["memberships"]["data"] == []
        assert rels["memberships"]["meta"]["count"] == 0

    def test_list_users_with_all_permissions_shows_relationships(
        self, authenticated_client_rbac
    ):
        response = authenticated_client_rbac.get(reverse("user-list"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert isinstance(data, list)

        rels = data[0]["relationships"]
        assert len(rels["roles"]["data"]) >= 0
        assert rels["memberships"]["meta"]["count"] >= 0


@pytest.mark.django_db
class TestProviderViewSet:
    def test_list_providers_with_all_permissions(
        self, authenticated_client_rbac, providers_fixture
    ):
        response = authenticated_client_rbac.get(reverse("provider-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(providers_fixture)

    def test_list_providers_with_no_permissions(
        self, authenticated_client_no_permissions_rbac
    ):
        response = authenticated_client_no_permissions_rbac.get(
            reverse("provider-list")
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    def test_retrieve_provider_with_all_permissions(
        self, authenticated_client_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        response = authenticated_client_rbac.get(
            reverse("provider-detail", kwargs={"pk": provider.id})
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["alias"] == provider.alias

    def test_retrieve_provider_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        response = authenticated_client_no_permissions_rbac.get(
            reverse("provider-detail", kwargs={"pk": provider.id})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_create_provider_with_all_permissions(self, authenticated_client_rbac):
        payload = {"provider": "aws", "uid": "111111111111", "alias": "new_alias"}
        response = authenticated_client_rbac.post(
            reverse("provider-list"), data=payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["data"]["attributes"]["alias"] == "new_alias"

    def test_create_provider_with_no_permissions(
        self, authenticated_client_no_permissions_rbac
    ):
        payload = {"provider": "aws", "uid": "111111111111", "alias": "new_alias"}
        response = authenticated_client_no_permissions_rbac.post(
            reverse("provider-list"), data=payload, format="json"
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_partial_update_provider_with_all_permissions(
        self, authenticated_client_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        payload = {
            "data": {
                "type": "providers",
                "id": provider.id,
                "attributes": {"alias": "updated_alias"},
            },
        }
        response = authenticated_client_rbac.patch(
            reverse("provider-detail", kwargs={"pk": provider.id}),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["alias"] == "updated_alias"

    def test_partial_update_provider_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        update_payload = {
            "data": {
                "type": "providers",
                "attributes": {"alias": "updated_alias"},
            }
        }
        response = authenticated_client_no_permissions_rbac.patch(
            reverse("provider-detail", kwargs={"pk": provider.id}),
            data=update_payload,
            format="vnd.api+json",
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.delete_provider_task.delay")
    def test_delete_provider_with_all_permissions(
        self,
        mock_delete_task,
        mock_task_get,
        authenticated_client_rbac,
        providers_fixture,
        tasks_fixture,
    ):
        prowler_task = tasks_fixture[0]
        task_mock = Mock()
        task_mock.id = prowler_task.id
        mock_delete_task.return_value = task_mock
        mock_task_get.return_value = prowler_task

        provider1, *_ = providers_fixture
        response = authenticated_client_rbac.delete(
            reverse("provider-detail", kwargs={"pk": provider1.id})
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        mock_delete_task.assert_called_once_with(
            provider_id=str(provider1.id), tenant_id=ANY
        )
        assert "Content-Location" in response.headers
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task_mock.id}"

    def test_delete_provider_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        response = authenticated_client_no_permissions_rbac.delete(
            reverse("provider-detail", kwargs={"pk": provider.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.check_provider_connection_task.delay")
    def test_connection_with_all_permissions(
        self,
        mock_provider_connection,
        mock_task_get,
        authenticated_client_rbac,
        providers_fixture,
        tasks_fixture,
    ):
        prowler_task = tasks_fixture[0]
        task_mock = Mock()
        task_mock.id = prowler_task.id
        task_mock.status = "PENDING"
        mock_provider_connection.return_value = task_mock
        mock_task_get.return_value = prowler_task

        provider1, *_ = providers_fixture
        assert provider1.connected is None
        assert provider1.connection_last_checked_at is None

        response = authenticated_client_rbac.post(
            reverse("provider-connection", kwargs={"pk": provider1.id})
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        mock_provider_connection.assert_called_once_with(
            provider_id=str(provider1.id), tenant_id=ANY
        )
        assert "Content-Location" in response.headers
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task_mock.id}"

    def test_connection_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        response = authenticated_client_no_permissions_rbac.post(
            reverse("provider-connection", kwargs={"pk": provider.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestLimitedVisibility:
    TEST_EMAIL = "rbac@rbac.com"
    TEST_PASSWORD = "Thisisapassword123@"

    @pytest.fixture
    def limited_admin_user(
        self, django_db_setup, django_db_blocker, tenants_fixture, providers_fixture
    ):
        with django_db_blocker.unblock():
            tenant = tenants_fixture[0]
            provider = providers_fixture[0]
            user = User.objects.create_user(
                name="testing",
                email=self.TEST_EMAIL,
                password=self.TEST_PASSWORD,
            )
            Membership.objects.create(
                user=user,
                tenant=tenant,
                role=Membership.RoleChoices.OWNER,
            )

            role = Role.objects.create(
                name="limited_visibility",
                tenant=tenant,
                manage_users=True,
                manage_account=True,
                manage_billing=True,
                manage_providers=True,
                manage_integrations=True,
                manage_scans=True,
                unlimited_visibility=False,
            )
            UserRoleRelationship.objects.create(
                user=user,
                role=role,
                tenant=tenant,
            )

            provider_group = ProviderGroup.objects.create(
                name="limited_visibility_group",
                tenant=tenant,
            )
            ProviderGroupMembership.objects.create(
                tenant=tenant,
                provider=provider,
                provider_group=provider_group,
            )

            RoleProviderGroupRelationship.objects.create(
                tenant=tenant, role=role, provider_group=provider_group
            )

        return user

    @pytest.fixture
    def authenticated_client_rbac_limited(
        self, limited_admin_user, tenants_fixture, client
    ):
        client.user = limited_admin_user
        tenant_id = tenants_fixture[0].id
        serializer = TokenSerializer(
            data={
                "type": "tokens",
                "email": self.TEST_EMAIL,
                "password": self.TEST_PASSWORD,
                "tenant_id": tenant_id,
            }
        )
        serializer.is_valid(raise_exception=True)
        access_token = serializer.validated_data["access"]
        client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"
        return client

    def test_integrations(
        self, authenticated_client_rbac_limited, integrations_fixture, providers_fixture
    ):
        # Integration 2 is related to provider1 and provider 2
        # This user cannot see provider 2
        integration = integrations_fixture[1]

        response = authenticated_client_rbac_limited.get(
            reverse("integration-detail", kwargs={"pk": integration.id})
        )

        assert response.status_code == status.HTTP_200_OK
        assert integration.providers.count() == 2
        assert (
            response.json()["data"]["relationships"]["providers"]["meta"]["count"] == 1
        )

    def test_overviews_providers(
        self,
        authenticated_client_rbac_limited,
        scan_summaries_fixture,
        providers_fixture,
    ):
        # By default, the associated provider is the one which has the overview data
        response = authenticated_client_rbac_limited.get(reverse("overview-providers"))

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) > 0

        # Changing the provider visibility, no data should be returned
        # Only the associated provider to that group is changed
        new_provider = providers_fixture[1]
        ProviderGroupMembership.objects.all().update(provider=new_provider)

        response = authenticated_client_rbac_limited.get(reverse("overview-providers"))

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    @pytest.mark.parametrize(
        "endpoint_name",
        [
            "findings",
            "findings_severity",
        ],
    )
    def test_overviews_findings(
        self,
        endpoint_name,
        authenticated_client_rbac_limited,
        scan_summaries_fixture,
        providers_fixture,
    ):
        # By default, the associated provider is the one which has the overview data
        response = authenticated_client_rbac_limited.get(
            reverse(f"overview-{endpoint_name}")
        )

        assert response.status_code == status.HTTP_200_OK
        values = response.json()["data"]["attributes"].values()
        assert any(value > 0 for value in values)

        # Changing the provider visibility, no data should be returned
        # Only the associated provider to that group is changed
        new_provider = providers_fixture[1]
        ProviderGroupMembership.objects.all().update(provider=new_provider)

        response = authenticated_client_rbac_limited.get(
            reverse(f"overview-{endpoint_name}")
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]["attributes"].values()
        assert all(value == 0 for value in data)

    def test_overviews_services(
        self,
        authenticated_client_rbac_limited,
        scan_summaries_fixture,
        providers_fixture,
    ):
        # By default, the associated provider is the one which has the overview data
        response = authenticated_client_rbac_limited.get(
            reverse("overview-services"), {"filter[inserted_at]": TODAY}
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) > 0

        # Changing the provider visibility, no data should be returned
        # Only the associated provider to that group is changed
        new_provider = providers_fixture[1]
        ProviderGroupMembership.objects.all().update(provider=new_provider)

        response = authenticated_client_rbac_limited.get(
            reverse("overview-services"), {"filter[inserted_at]": TODAY}
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0


@pytest.mark.django_db
class TestRolePermissions:
    def test_role_create_with_manage_account_only_allowed(
        self, authenticated_client_rbac_manage_account
    ):
        data = {
            "data": {
                "type": "roles",
                "attributes": {
                    "name": "Role Manage Account Only",
                    "manage_users": "false",
                    "manage_account": "true",
                    "manage_providers": "false",
                    "manage_scans": "false",
                    "unlimited_visibility": "false",
                },
                "relationships": {"provider_groups": {"data": []}},
            }
        }
        response = authenticated_client_rbac_manage_account.post(
            reverse("role-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

    def test_role_create_with_manage_users_only_forbidden(
        self, authenticated_client_rbac_manage_users_only
    ):
        data = {
            "data": {
                "type": "roles",
                "attributes": {
                    "name": "Role Manage Users Only",
                    "manage_users": "true",
                    "manage_account": "false",
                    "manage_providers": "false",
                    "manage_scans": "false",
                    "unlimited_visibility": "false",
                },
                "relationships": {"provider_groups": {"data": []}},
            }
        }
        response = authenticated_client_rbac_manage_users_only.post(
            reverse("role-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestUserRoleLinkPermissions:
    def test_link_user_roles_with_manage_account_only_allowed(
        self, authenticated_client_rbac_manage_account
    ):
        # Arrange: create a second user in the same tenant as the manage_account user
        ma_user = authenticated_client_rbac_manage_account.user
        ma_membership = Membership.objects.filter(user=ma_user).first()
        tenant = ma_membership.tenant

        user2 = User.objects.create_user(
            name="target_user",
            email="target_user_ma@rbac.com",
            password="Password123@",
        )
        Membership.objects.create(user=user2, tenant=tenant)

        # Create a role in the same tenant
        role = Role.objects.create(
            name="linkable_role",
            tenant_id=tenant.id,
            manage_users=False,
            manage_account=False,
        )

        data = {"data": [{"type": "roles", "id": str(role.id)}]}

        # Act
        response = authenticated_client_rbac_manage_account.post(
            reverse("user-roles-relationship", kwargs={"pk": user2.id}),
            data=data,
            content_type="application/vnd.api+json",
        )

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_link_user_roles_with_manage_users_only_forbidden(
        self, authenticated_client_rbac_manage_users_only
    ):
        mu_user = authenticated_client_rbac_manage_users_only.user
        mu_membership = Membership.objects.filter(user=mu_user).first()
        tenant = mu_membership.tenant

        user2 = User.objects.create_user(
            name="target_user2",
            email="target_user_mu@rbac.com",
            password="Password123@",
        )
        Membership.objects.create(user=user2, tenant=tenant)

        role = Role.objects.create(
            name="linkable_role_mu",
            tenant_id=tenant.id,
            manage_users=False,
            manage_account=False,
        )

        data = {"data": [{"type": "roles", "id": str(role.id)}]}

        response = authenticated_client_rbac_manage_users_only.post(
            reverse("user-roles-relationship", kwargs={"pk": user2.id}),
            data=data,
            content_type="application/vnd.api+json",
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
