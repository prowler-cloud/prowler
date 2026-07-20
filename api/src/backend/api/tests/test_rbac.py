import json
from unittest.mock import ANY, Mock, patch

import pytest
from api.models import (
    Integration,
    IntegrationProviderRelationship,
    Membership,
    ProviderGroup,
    ProviderGroupMembership,
    Role,
    RoleProviderGroupRelationship,
    User,
    UserRoleRelationship,
)
from api.rbac.permissions import HasPermissions, Permissions
from api.v1.serializers import TokenSerializer
from conftest import TEST_PASSWORD, TODAY
from django.urls import reverse
from rest_framework import status


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
        self, authenticated_client_no_permissions_rbac, create_test_user_rbac_limited
    ):
        updated_data = {
            "data": {
                "type": "users",
                "id": str(create_test_user_rbac_limited.id),
                "attributes": {"name": "Updated Name"},
            }
        }
        response = authenticated_client_no_permissions_rbac.patch(
            reverse("user-detail", kwargs={"pk": create_test_user_rbac_limited.id}),
            data=updated_data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["name"] == "Updated Name"

    def test_partial_update_other_user_with_no_permissions_denied(
        self, authenticated_client_no_permissions_rbac, tenants_fixture
    ):
        original_email = "target-rbac-update@example.com"
        original_password = "OriginalPassword123@"
        target_user = User.objects.create_user(
            name="target_rbac_update",
            email=original_email,
            password=original_password,
        )
        Membership.objects.create(user=target_user, tenant=tenants_fixture[0])
        updated_data = {
            "data": {
                "type": "users",
                "id": str(target_user.id),
                "attributes": {
                    "email": "updated-target-rbac@example.com",
                    "password": "UpdatedPassword123@",
                },
            }
        }

        response = authenticated_client_no_permissions_rbac.patch(
            reverse("user-detail", kwargs={"pk": target_user.id}),
            data=updated_data,
            content_type="application/vnd.api+json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        target_user.refresh_from_db()
        assert target_user.email == original_email
        assert target_user.check_password(original_password)

    def test_partial_update_other_user_with_manage_users_allowed(
        self, authenticated_client_rbac_manage_users_only
    ):
        user = authenticated_client_rbac_manage_users_only.user
        tenant = Membership.objects.filter(user=user).first().tenant
        target_user = User.objects.create_user(
            name="target_manage_users_update",
            email="target-manage-users-update@example.com",
            password="Password123@",
        )
        Membership.objects.create(user=target_user, tenant=tenant)
        updated_data = {
            "data": {
                "type": "users",
                "id": str(target_user.id),
                "attributes": {"name": "Updated Target Name"},
            }
        }

        response = authenticated_client_rbac_manage_users_only.patch(
            reverse("user-detail", kwargs={"pk": target_user.id}),
            data=updated_data,
            content_type="application/vnd.api+json",
        )

        assert response.status_code == status.HTTP_200_OK
        target_user.refresh_from_db()
        assert target_user.name == "Updated Target Name"

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
        self, authenticated_client_rbac, aws_provider
    ):
        response = authenticated_client_rbac.get(reverse("provider-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1

    def test_list_providers_with_no_permissions(
        self, authenticated_client_no_permissions_rbac
    ):
        response = authenticated_client_no_permissions_rbac.get(
            reverse("provider-list")
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    def test_retrieve_provider_with_all_permissions(
        self, authenticated_client_rbac, aws_provider
    ):
        provider = aws_provider
        response = authenticated_client_rbac.get(
            reverse("provider-detail", kwargs={"pk": provider.id})
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["alias"] == provider.alias

    def test_retrieve_provider_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, aws_provider
    ):
        provider = aws_provider
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
        self, authenticated_client_rbac, aws_provider
    ):
        provider = aws_provider
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
        self, authenticated_client_no_permissions_rbac, aws_provider
    ):
        provider = aws_provider
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
        aws_provider,
        tasks_fixture,
    ):
        prowler_task = tasks_fixture[0]
        task_mock = Mock()
        task_mock.id = prowler_task.id
        mock_delete_task.return_value = task_mock
        mock_task_get.return_value = prowler_task

        provider1 = aws_provider
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
        self, authenticated_client_no_permissions_rbac, aws_provider
    ):
        provider = aws_provider
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
        aws_provider,
        tasks_fixture,
    ):
        prowler_task = tasks_fixture[0]
        task_mock = Mock()
        task_mock.id = prowler_task.id
        task_mock.status = "PENDING"
        mock_provider_connection.return_value = task_mock
        mock_task_get.return_value = prowler_task

        provider1 = aws_provider
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
        self, authenticated_client_no_permissions_rbac, aws_provider
    ):
        provider = aws_provider
        response = authenticated_client_no_permissions_rbac.post(
            reverse("provider-connection", kwargs={"pk": provider.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestLimitedVisibility:
    TEST_EMAIL = "rbac@rbac.com"
    TEST_PASSWORD = "Thisisapassword123@"

    @pytest.fixture
    def limited_admin_user(self, django_db_blocker, tenants_fixture, aws_provider):
        with django_db_blocker.unblock():
            tenant = tenants_fixture[0]
            provider = aws_provider
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
        self,
        limited_admin_user,
        tenants_fixture,
        authenticated_client_for_tenant_factory,
    ):
        return authenticated_client_for_tenant_factory(
            limited_admin_user, tenants_fixture[0]
        )

    def test_integrations(
        self, authenticated_client_rbac_limited, integrations_fixture
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

    @pytest.fixture
    def jira_integration(self, tenants_fixture):
        # Jira is a tenant-wide integration: it is not attached to any provider
        return Integration.objects.create(
            tenant_id=tenants_fixture[0].id,
            enabled=True,
            connected=True,
            integration_type=Integration.IntegrationChoices.JIRA,
            configuration={"projects": {"TEST": "Test project"}},
            credentials={
                "domain": "test",
                "user_mail": "a@b.com",
                "api_token": "token",
            },
        )

    @pytest.fixture
    def out_of_scope_integration(self, tenants_fixture, provider_factory):
        tenant_id = tenants_fixture[0].id
        integration = Integration.objects.create(
            tenant_id=tenant_id,
            enabled=True,
            connected=True,
            integration_type=Integration.IntegrationChoices.AMAZON_S3,
            configuration={
                "bucket_name": "bucket",
                "output_directory": "output",
            },
            credentials={"aws_access_key_id": "key"},
        )
        IntegrationProviderRelationship.objects.create(
            tenant_id=tenant_id,
            integration=integration,
            provider=provider_factory(),
        )
        return integration

    def test_integrations_list_includes_tenant_wide_integration(
        self,
        authenticated_client_rbac_limited,
        integrations_fixture,
        jira_integration,
        aws_provider_pair,
    ):
        # Integration 2 is attached to both providers, so make both visible to the role
        # to assert the provider join does not duplicate it in the listing
        ProviderGroupMembership.objects.create(
            tenant_id=aws_provider_pair[1].tenant_id,
            provider=aws_provider_pair[1],
            provider_group=ProviderGroup.objects.get(name="limited_visibility_group"),
        )

        response = authenticated_client_rbac_limited.get(reverse("integration-list"))

        assert response.status_code == status.HTTP_200_OK
        integration_ids = [item["id"] for item in response.json()["data"]]
        # The tenant-wide Jira integration is visible without unlimited visibility
        assert str(jira_integration.id) in integration_ids
        # Integrations attached to more than one visible provider are not duplicated
        assert integration_ids.count(str(integrations_fixture[1].id)) == 1
        assert response.json()["meta"]["pagination"]["count"] == len(integration_ids)

    def test_integrations_list_without_provider_groups_keeps_tenant_wide_integration(
        self, authenticated_client_rbac_limited, integrations_fixture, jira_integration
    ):
        # A role with no provider group at all sees no provider, but still needs Jira
        RoleProviderGroupRelationship.objects.all().delete()

        response = authenticated_client_rbac_limited.get(reverse("integration-list"))

        assert response.status_code == status.HTTP_200_OK
        integration_ids = [item["id"] for item in response.json()["data"]]
        assert integration_ids == [str(jira_integration.id)]

    def test_integrations_include_providers_hides_out_of_scope_providers(
        self, authenticated_client_rbac_limited, integrations_fixture, aws_provider_pair
    ):
        # Integration 2 is related to provider1 (visible) and provider2 (not visible)
        hidden_provider = aws_provider_pair[1]

        response = authenticated_client_rbac_limited.get(
            reverse("integration-list"), {"include": "providers"}
        )

        assert response.status_code == status.HTTP_200_OK
        included_ids = {item["id"] for item in response.json().get("included", [])}
        assert str(aws_provider_pair[0].id) in included_ids
        # Sideloaded resources must not disclose the provider the role cannot see
        assert str(hidden_provider.id) not in included_ids

    def test_integrations_list_with_sparse_fields(
        self, authenticated_client_rbac_limited, integrations_fixture
    ):
        response = authenticated_client_rbac_limited.get(
            reverse("integration-list"), {"fields[integrations]": "enabled"}
        )

        assert response.status_code == status.HTTP_200_OK
        assert all(
            list(item["attributes"].keys()) == ["enabled"]
            for item in response.json()["data"]
        )

    def test_integrations_list_excludes_out_of_scope_integration(
        self, authenticated_client_rbac_limited, out_of_scope_integration
    ):
        response = authenticated_client_rbac_limited.get(reverse("integration-list"))

        assert response.status_code == status.HTTP_200_OK
        integration_ids = [item["id"] for item in response.json()["data"]]
        assert str(out_of_scope_integration.id) not in integration_ids

    def test_integration_detail_out_of_scope_returns_404(
        self, authenticated_client_rbac_limited, out_of_scope_integration
    ):
        response = authenticated_client_rbac_limited.get(
            reverse("integration-detail", kwargs={"pk": out_of_scope_integration.id})
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_integration_connection_out_of_scope_returns_404(
        self, authenticated_client_rbac_limited, out_of_scope_integration
    ):
        response = authenticated_client_rbac_limited.post(
            reverse(
                "integration-connection", kwargs={"pk": out_of_scope_integration.id}
            )
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_integration_update_hides_out_of_scope_providers(
        self, authenticated_client_rbac_limited, integrations_fixture
    ):
        # Integration 2 is related to provider1 and provider2, this user cannot see provider2
        integration = integrations_fixture[1]
        payload = {
            "data": {
                "type": "integrations",
                "id": str(integration.id),
                "attributes": {
                    "enabled": False,
                    # integration_type is `amazon_s3`
                    "credentials": {"aws_access_key_id": "new_value"},
                    "configuration": {
                        "bucket_name": "new_bucket_name",
                        "output_directory": "new_output_directory",
                    },
                },
            }
        }

        response = authenticated_client_rbac_limited.patch(
            reverse("integration-detail", kwargs={"pk": integration.id}),
            data=json.dumps(payload),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert integration.providers.count() == 2
        assert len(response.json()["data"]["relationships"]["providers"]["data"]) == 1

    def test_integration_create_rejects_out_of_scope_provider(
        self, authenticated_client_rbac_limited, aws_provider_pair
    ):
        # provider2 is not in any provider group assigned to the role
        payload = {
            "data": {
                "type": "integrations",
                "attributes": {
                    "integration_type": "amazon_s3",
                    "configuration": {
                        "bucket_name": "attacker_bucket",
                        "output_directory": "output",
                    },
                    "credentials": {"aws_access_key_id": "key"},
                },
                "relationships": {
                    "providers": {
                        "data": [
                            {"type": "providers", "id": str(aws_provider_pair[1].id)}
                        ]
                    }
                },
            }
        }

        response = authenticated_client_rbac_limited.post(
            reverse("integration-list"),
            data=json.dumps(payload),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert not Integration.objects.filter(
            integrationproviderrelationship__provider=aws_provider_pair[1],
            configuration__bucket_name="attacker_bucket",
        ).exists()

    @pytest.mark.parametrize("submitted_providers", [True, False])
    def test_integration_update_keeps_out_of_scope_providers(
        self,
        authenticated_client_rbac_limited,
        integrations_fixture,
        aws_provider_pair,
        submitted_providers,
    ):
        # Integration 2 is related to provider1 (visible) and provider2 (not visible)
        integration = integrations_fixture[1]
        visible_provider, hidden_provider = aws_provider_pair
        providers_data = (
            [{"type": "providers", "id": str(visible_provider.id)}]
            if submitted_providers
            else []
        )
        payload = {
            "data": {
                "type": "integrations",
                "id": str(integration.id),
                "attributes": {
                    # integration_type is `amazon_s3`
                    "credentials": {"aws_access_key_id": "new_value"},
                    "configuration": {
                        "bucket_name": "new_bucket_name",
                        "output_directory": "new_output_directory",
                    },
                },
                "relationships": {"providers": {"data": providers_data}},
            }
        }

        response = authenticated_client_rbac_limited.patch(
            reverse("integration-detail", kwargs={"pk": integration.id}),
            data=json.dumps(payload),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == status.HTTP_200_OK
        # The relationship to the provider the role cannot see is left untouched
        assert integration.providers.filter(id=hidden_provider.id).exists()
        assert (
            integration.providers.filter(id=visible_provider.id).exists()
            is submitted_providers
        )

    def test_integration_delete_denied_when_shared_with_hidden_provider(
        self, authenticated_client_rbac_limited, integrations_fixture
    ):
        # Integration 2 is related to provider1 (visible) and provider2 (not visible)
        integration = integrations_fixture[1]

        response = authenticated_client_rbac_limited.delete(
            reverse("integration-detail", kwargs={"pk": integration.id})
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert Integration.objects.filter(id=integration.id).exists()

    def test_integration_delete_allowed_when_fully_visible(
        self, authenticated_client_rbac_limited, integrations_fixture, jira_integration
    ):
        # Integration 1 is only related to provider1, which the role can access
        integration = integrations_fixture[0]

        response = authenticated_client_rbac_limited.delete(
            reverse("integration-detail", kwargs={"pk": integration.id})
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Integration.objects.filter(id=integration.id).exists()

        # Tenant-wide integrations have no provider restricting the role
        response = authenticated_client_rbac_limited.delete(
            reverse("integration-detail", kwargs={"pk": jira_integration.id})
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_jira_issue_types_allowed_without_unlimited_visibility(
        self, authenticated_client_rbac_limited, jira_integration
    ):
        with patch("api.v1.views.initialize_prowler_integration") as mock_jira:
            mock_jira.return_value.get_available_issue_types.return_value = ["Task"]
            response = authenticated_client_rbac_limited.get(
                reverse(
                    "integration-jira-issue-types",
                    kwargs={"integration_pk": jira_integration.id},
                ),
                {"project_key": "TEST"},
            )

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["issue_types"] == ["Task"]

    def test_jira_issue_types_out_of_scope_returns_404(
        self, authenticated_client_rbac_limited, out_of_scope_integration
    ):
        response = authenticated_client_rbac_limited.get(
            reverse(
                "integration-jira-issue-types",
                kwargs={"integration_pk": out_of_scope_integration.id},
            ),
            {"project_key": "TEST"},
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_jira_dispatches_out_of_scope_returns_404(
        self, authenticated_client_rbac_limited, out_of_scope_integration
    ):
        response = authenticated_client_rbac_limited.post(
            reverse(
                "integration-jira-dispatches",
                kwargs={"integration_pk": out_of_scope_integration.id},
            ),
            data=json.dumps({}),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_jira_dispatches_allowed_without_unlimited_visibility(
        self, authenticated_client_rbac_limited, jira_integration
    ):
        response = authenticated_client_rbac_limited.post(
            reverse(
                "integration-jira-dispatches",
                kwargs={"integration_pk": jira_integration.id},
            ),
            data=json.dumps({}),
            content_type="application/vnd.api+json",
        )

        # The integration is reachable: the request fails on payload validation, not RBAC
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.usefixtures("scan_summaries_fixture")
    def test_overviews_providers(
        self,
        authenticated_client_rbac_limited,
        provider_factory,
    ):
        # By default, the associated provider is the one which has the overview data
        response = authenticated_client_rbac_limited.get(reverse("overview-providers"))

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) > 0

        # Changing the provider visibility, no data should be returned
        # Only the associated provider to that group is changed
        new_provider = provider_factory()
        ProviderGroupMembership.objects.all().update(provider=new_provider)

        response = authenticated_client_rbac_limited.get(reverse("overview-providers"))

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    @pytest.mark.usefixtures("scan_summaries_fixture")
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
        provider_factory,
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
        new_provider = provider_factory()
        ProviderGroupMembership.objects.all().update(provider=new_provider)

        response = authenticated_client_rbac_limited.get(
            reverse(f"overview-{endpoint_name}")
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]["attributes"].values()
        assert all(value == 0 for value in data)

    @pytest.mark.usefixtures("scan_summaries_fixture")
    def test_overviews_services(
        self,
        authenticated_client_rbac_limited,
        provider_factory,
    ):
        # By default, the associated provider is the one which has the overview data
        response = authenticated_client_rbac_limited.get(
            reverse("overview-services"), {"filter[inserted_at]": TODAY}
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) > 0

        # Changing the provider visibility, no data should be returned
        # Only the associated provider to that group is changed
        new_provider = provider_factory()
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
class TestHasPermissions:
    def test_permissions_are_combined_across_roles(
        self, create_test_user_rbac_no_roles
    ):
        user = create_test_user_rbac_no_roles
        tenant = Membership.objects.get(user=user).tenant
        manage_users_role = Role.objects.create(
            name="manage_users_only",
            tenant=tenant,
            manage_users=True,
        )
        UserRoleRelationship.objects.create(
            user=user,
            role=manage_users_role,
            tenant=tenant,
        )
        request = Mock(user=user, tenant_id=tenant.id)
        view = Mock(
            required_permissions=[
                Permissions.MANAGE_USERS,
                Permissions.MANAGE_ACCOUNT,
            ]
        )
        permission = HasPermissions()

        assert not permission.has_permission(request, view)

        manage_account_role = Role.objects.create(
            name="manage_account_only",
            tenant=tenant,
            manage_account=True,
        )
        UserRoleRelationship.objects.create(
            user=user,
            role=manage_account_role,
            tenant=tenant,
        )

        assert permission.has_permission(request, view)


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


@pytest.mark.django_db
class TestCrossTenantRoleLeak:
    """Regression tests for get_role() cross-tenant privilege leak.

    get_role() must query admin_db (bypassing RLS) so that a user with a role
    in tenant A cannot accidentally pass role checks when authenticated against
    tenant B where they have no role.
    """

    def test_user_with_role_in_tenant_a_denied_in_tenant_b(self, tenants_fixture):
        """User has admin role in tenant A, membership in tenant B but no role.
        Hitting an RBAC-protected endpoint with a tenant-B token must return 403."""
        from rest_framework.test import APIClient

        tenant_a = tenants_fixture[0]
        tenant_b = tenants_fixture[1]

        user = User.objects.create_user(
            name="cross_tenant_user",
            email="cross_tenant@test.com",
            password=TEST_PASSWORD,
        )
        Membership.objects.create(
            user=user, tenant=tenant_a, role=Membership.RoleChoices.OWNER
        )
        Membership.objects.create(
            user=user, tenant=tenant_b, role=Membership.RoleChoices.OWNER
        )

        # Role only in tenant A
        role = Role.objects.create(
            name="admin",
            tenant_id=tenant_a.id,
            manage_users=True,
            manage_account=True,
            manage_billing=True,
            manage_providers=True,
            manage_integrations=True,
            manage_scans=True,
            unlimited_visibility=True,
        )
        UserRoleRelationship.objects.create(user=user, role=role, tenant_id=tenant_a.id)

        # Mint token scoped to tenant B (where user has NO role)
        serializer = TokenSerializer(
            data={
                "type": "tokens",
                "email": "cross_tenant@test.com",
                "password": TEST_PASSWORD,
                "tenant_id": tenant_b.id,
            }
        )
        serializer.is_valid(raise_exception=True)
        access_token = serializer.validated_data["access"]

        client = APIClient()
        client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"

        # user-list requires manage_users permission via HasPermissions
        response = client.get(reverse("user-list"))
        assert response.status_code == status.HTTP_403_FORBIDDEN
