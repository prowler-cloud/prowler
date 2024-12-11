import json
from datetime import datetime, timedelta, timezone
from unittest.mock import ANY, Mock, patch

import jwt
import pytest
from conftest import API_JSON_CONTENT_TYPE, TEST_PASSWORD, TEST_USER
from django.urls import reverse
from rest_framework import status

from api.models import (
    Invitation,
    Membership,
    Provider,
    ProviderGroup,
    ProviderGroupMembership,
    ProviderSecret,
    Scan,
    StateChoices,
    User,
)
from api.rls import Tenant

TODAY = str(datetime.today().date())


@pytest.mark.django_db
class TestUserViewSet:
    def test_users_list(self, authenticated_client, create_test_user):
        user = create_test_user
        user.refresh_from_db()
        response = authenticated_client.get(reverse("user-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["email"] == user.email
        assert response.json()["data"][0]["attributes"]["name"] == user.name
        assert (
            response.json()["data"][0]["attributes"]["company_name"]
            == user.company_name
        )

    def test_users_retrieve(self, authenticated_client, create_test_user):
        response = authenticated_client.get(
            reverse("user-detail", kwargs={"pk": create_test_user.id})
        )
        assert response.status_code == status.HTTP_200_OK

    def test_users_me(self, authenticated_client, create_test_user):
        response = authenticated_client.get(reverse("user-me"))
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["email"] == create_test_user.email

    @patch("api.db_router.MainRouter.admin_db", new="default")
    def test_users_create(self, client):
        valid_user_payload = {
            "name": "test",
            "password": "newpassword123",
            "email": "NeWuSeR@example.com",
        }
        response = client.post(
            reverse("user-list"), data=valid_user_payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert User.objects.filter(email__iexact=valid_user_payload["email"]).exists()
        assert (
            response.json()["data"]["attributes"]["email"]
            == valid_user_payload["email"].lower()
        )

    @patch("api.db_router.MainRouter.admin_db", new="default")
    def test_users_create_duplicated_email(self, client):
        # Create a user
        self.test_users_create(client)

        # Try to create it again and expect a 400
        with pytest.raises(AssertionError) as assertion_error:
            self.test_users_create(client)

        assert "Response status_code=400" in str(assertion_error)

    @pytest.mark.parametrize(
        "password",
        [
            # Fails MinimumLengthValidator (too short)
            "short",
            "1234567",
            # Fails CommonPasswordValidator (common passwords)
            "password",
            "12345678",
            "qwerty",
            "abc123",
            # Fails NumericPasswordValidator (entirely numeric)
            "12345678",
            "00000000",
            # Fails multiple validators
            "password1",  # Common password and too similar to a common password
            "dev12345",  # Similar to username
            ("querty12" * 9) + "a",  # Too long, 73 characters
        ],
    )
    def test_users_create_invalid_passwords(self, authenticated_client, password):
        invalid_user_payload = {
            "name": "test",
            "password": password,
            "email": "thisisafineemail@prowler.com",
        }
        response = authenticated_client.post(
            reverse("user-list"), data=invalid_user_payload, format="json"
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/password"
        )

    @pytest.mark.parametrize(
        "email",
        [
            # Same email, validation error
            "nonexistentemail@prowler.com",
            # Same email with capital letters, validation error
            "NonExistentEmail@prowler.com",
        ],
    )
    @patch("api.db_router.MainRouter.admin_db", new="default")
    def test_users_create_used_email(self, authenticated_client, email):
        # First user created; no errors should occur
        user_payload = {
            "name": "test_email_validator",
            "password": "newpassword123",
            "email": "nonexistentemail@prowler.com",
        }
        response = authenticated_client.post(
            reverse("user-list"), data=user_payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED

        user_payload = {
            "name": "test_email_validator",
            "password": "newpassword123",
            "email": email,
        }
        response = authenticated_client.post(
            reverse("user-list"), data=user_payload, format="json"
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/email"
        )
        assert (
            response.json()["errors"][0]["detail"]
            == "Please check the email address and try again."
        )

    def test_users_partial_update(self, authenticated_client, create_test_user):
        new_company_name = "new company test"
        payload = {
            "data": {
                "type": "users",
                "id": str(create_test_user.id),
                "attributes": {"company_name": new_company_name},
            },
        }
        response = authenticated_client.patch(
            reverse("user-detail", kwargs={"pk": create_test_user.id}),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        create_test_user.refresh_from_db()
        assert create_test_user.company_name == new_company_name

    def test_users_partial_update_invalid_content_type(
        self, authenticated_client, create_test_user
    ):
        response = authenticated_client.patch(
            reverse("user-detail", kwargs={"pk": create_test_user.id}), data={}
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_users_partial_update_invalid_content(
        self, authenticated_client, create_test_user
    ):
        payload = {"email": "newemail@example.com"}
        response = authenticated_client.patch(
            reverse("user-detail", kwargs={"pk": create_test_user.id}),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_users_partial_update_invalid_user(
        self, authenticated_client, create_test_user
    ):
        another_user = User.objects.create_user(
            password="otherpassword", email="other@example.com"
        )
        new_email = "new@example.com"
        payload = {
            "data": {
                "type": "users",
                "id": str(another_user.id),
                "attributes": {"email": new_email},
            },
        }
        response = authenticated_client.patch(
            reverse("user-detail", kwargs={"pk": another_user.id}),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        another_user.refresh_from_db()
        assert another_user.email != new_email

    @pytest.mark.parametrize(
        "password",
        [
            # Fails MinimumLengthValidator (too short)
            "short",
            "1234567",
            # Fails CommonPasswordValidator (common passwords)
            "password",
            "12345678",
            "qwerty",
            "abc123",
            # Fails NumericPasswordValidator (entirely numeric)
            "12345678",
            "00000000",
            # Fails UserAttributeSimilarityValidator (too similar to email)
            "dev12345",
            "test@prowler.com",
        ],
    )
    def test_users_partial_update_invalid_password(
        self, authenticated_client, create_test_user, password
    ):
        payload = {
            "data": {
                "type": "users",
                "id": str(create_test_user.id),
                "attributes": {"password": password},
            },
        }

        response = authenticated_client.patch(
            reverse("user-detail", kwargs={"pk": str(create_test_user.id)}),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/password"
        )

    def test_users_destroy(self, authenticated_client, create_test_user):
        response = authenticated_client.delete(
            reverse("user-detail", kwargs={"pk": create_test_user.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not User.objects.filter(id=create_test_user.id).exists()

    def test_users_destroy_invalid_user(self, authenticated_client, create_test_user):
        another_user = User.objects.create_user(
            password="otherpassword", email="other@example.com"
        )
        response = authenticated_client.delete(
            reverse("user-detail", kwargs={"pk": another_user.id})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert User.objects.filter(id=another_user.id).exists()

    @pytest.mark.parametrize(
        "attribute_key, attribute_value, error_field",
        [
            ("password", "", "password"),
            ("email", "invalidemail", "email"),
        ],
    )
    def test_users_create_invalid_fields(
        self, client, attribute_key, attribute_value, error_field
    ):
        invalid_payload = {
            "name": "test",
            "password": "testpassword",
            "email": "test@example.com",
        }
        invalid_payload[attribute_key] = attribute_value
        response = client.post(
            reverse("user-list"), data=invalid_payload, format="json"
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert error_field in response.json()["errors"][0]["source"]["pointer"]


@pytest.mark.django_db
class TestTenantViewSet:
    @pytest.fixture
    def valid_tenant_payload(self):
        return {
            "name": "Tenant Three",
            "inserted_at": "2023-01-05",
            "updated_at": "2023-01-06",
        }

    @pytest.fixture
    def invalid_tenant_payload(self):
        return {
            "name": "",
            "inserted_at": "2023-01-05",
            "updated_at": "2023-01-06",
        }

    @pytest.fixture
    def extra_users(self, tenants_fixture):
        _, tenant2, _ = tenants_fixture
        user2 = User.objects.create_user(
            name="testing2",
            password=TEST_PASSWORD,
            email="testing2@gmail.com",
        )
        user3 = User.objects.create_user(
            name="testing3",
            password=TEST_PASSWORD,
            email="testing3@gmail.com",
        )
        membership2 = Membership.objects.create(
            user=user2,
            tenant=tenant2,
            role=Membership.RoleChoices.OWNER,
        )
        membership3 = Membership.objects.create(
            user=user3,
            tenant=tenant2,
            role=Membership.RoleChoices.MEMBER,
        )
        return (user2, membership2), (user3, membership3)

    def test_tenants_list(self, authenticated_client, tenants_fixture):
        response = authenticated_client.get(reverse("tenant-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(tenants_fixture)

    def test_tenants_retrieve(self, authenticated_client, tenants_fixture):
        tenant1, *_ = tenants_fixture
        response = authenticated_client.get(
            reverse("tenant-detail", kwargs={"pk": tenant1.id})
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["name"] == tenant1.name

    def test_tenants_invalid_retrieve(self, authenticated_client):
        response = authenticated_client.get(
            reverse("tenant-detail", kwargs={"pk": "random_id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tenants_create(self, authenticated_client, valid_tenant_payload):
        response = authenticated_client.post(
            reverse("tenant-list"), data=valid_tenant_payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        # Two tenants from the fixture + the new one
        assert Tenant.objects.count() == 4
        assert (
            response.json()["data"]["attributes"]["name"]
            == valid_tenant_payload["name"]
        )

    def test_tenants_invalid_create(self, authenticated_client, invalid_tenant_payload):
        response = authenticated_client.post(
            reverse("tenant-list"),
            data=invalid_tenant_payload,
            format="json",
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_partial_update(self, authenticated_client, tenants_fixture):
        tenant1, *_ = tenants_fixture
        new_name = "This is the new name"
        payload = {
            "data": {
                "type": "tenants",
                "id": tenant1.id,
                "attributes": {"name": new_name},
            },
        }
        response = authenticated_client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_200_OK
        tenant1.refresh_from_db()
        assert tenant1.name == new_name

    def test_tenants_partial_update_invalid_content_type(
        self, authenticated_client, tenants_fixture
    ):
        tenant1, *_ = tenants_fixture
        response = authenticated_client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}), data={}
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_tenants_partial_update_invalid_content(
        self, authenticated_client, tenants_fixture
    ):
        tenant1, *_ = tenants_fixture
        new_name = "This is the new name"
        payload = {"name": new_name}
        response = authenticated_client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @patch("api.db_router.MainRouter.admin_db", new="default")
    @patch("api.v1.views.delete_tenant_task.apply_async")
    def test_tenants_delete(
        self, delete_tenant_mock, authenticated_client, tenants_fixture
    ):
        def _delete_tenant(kwargs):
            Tenant.objects.filter(pk=kwargs.get("tenant_id")).delete()

        delete_tenant_mock.side_effect = _delete_tenant
        tenant1, *_ = tenants_fixture
        response = authenticated_client.delete(
            reverse("tenant-detail", kwargs={"pk": tenant1.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert Tenant.objects.count() == len(tenants_fixture) - 1
        assert Membership.objects.filter(tenant_id=tenant1.id).count() == 0
        # User is not deleted because it has another membership
        assert User.objects.count() == 1

    def test_tenants_delete_invalid(self, authenticated_client):
        response = authenticated_client.delete(
            reverse("tenant-detail", kwargs={"pk": "random_id"})
        )
        # To change if we implement RBAC
        # (user might not have permissions to see if the tenant exists or not -> 200 empty)
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tenants_list_filter_search(self, authenticated_client, tenants_fixture):
        """Search is applied to tenants_fixture  name."""
        tenant1, *_ = tenants_fixture
        response = authenticated_client.get(
            reverse("tenant-list"), {"filter[search]": tenant1.name}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["name"] == tenant1.name

    def test_tenants_list_query_param_name(self, authenticated_client, tenants_fixture):
        tenant1, *_ = tenants_fixture
        response = authenticated_client.get(
            reverse("tenant-list"), {"name": tenant1.name}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_list_invalid_query_param(self, authenticated_client):
        response = authenticated_client.get(reverse("tenant-list"), {"random": "value"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        (
            [
                ("name", "Tenant One", 1),
                ("name.icontains", "Tenant", 3),
                ("inserted_at", TODAY, 3),
                ("inserted_at.gte", "2024-01-01", 3),
                ("inserted_at.lte", "2024-01-01", 0),
                ("updated_at.gte", "2024-01-01", 3),
                ("updated_at.lte", "2024-01-01", 0),
            ]
        ),
    )
    def test_tenants_filters(
        self,
        authenticated_client,
        tenants_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        response = authenticated_client.get(
            reverse("tenant-list"),
            {f"filter[{filter_name}]": filter_value},
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    def test_tenants_list_filter_invalid(self, authenticated_client):
        response = authenticated_client.get(
            reverse("tenant-list"), {"filter[invalid]": "whatever"}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_list_page_size(self, authenticated_client, tenants_fixture):
        page_size = 1

        response = authenticated_client.get(
            reverse("tenant-list"), {"page[size]": page_size}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == page_size
        assert response.json()["meta"]["pagination"]["page"] == 1
        assert response.json()["meta"]["pagination"]["pages"] == len(tenants_fixture)

    def test_tenants_list_page_number(self, authenticated_client, tenants_fixture):
        page_size = 1
        page_number = 2

        response = authenticated_client.get(
            reverse("tenant-list"),
            {"page[size]": page_size, "page[number]": page_number},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == page_size
        assert response.json()["meta"]["pagination"]["page"] == page_number
        assert response.json()["meta"]["pagination"]["pages"] == len(tenants_fixture)

    def test_tenants_list_sort_name(self, authenticated_client, tenants_fixture):
        _, tenant2, _ = tenants_fixture
        response = authenticated_client.get(reverse("tenant-list"), {"sort": "-name"})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 3
        assert response.json()["data"][0]["attributes"]["name"] == tenant2.name

    def test_tenants_list_memberships_as_owner(
        self, authenticated_client, tenants_fixture, extra_users
    ):
        _, tenant2, _ = tenants_fixture
        response = authenticated_client.get(
            reverse("tenant-membership-list", kwargs={"tenant_pk": tenant2.id})
        )
        assert response.status_code == status.HTTP_200_OK
        # Test user + 2 extra users for tenant 2
        assert len(response.json()["data"]) == 3

    def test_tenants_list_memberships_as_member(
        self, authenticated_client, tenants_fixture, extra_users
    ):
        _, tenant2, _ = tenants_fixture
        _, user3_membership = extra_users
        user3, membership3 = user3_membership
        token_response = authenticated_client.post(
            reverse("token-obtain"),
            data={"email": user3.email, "password": TEST_PASSWORD},
            format="json",
        )
        access_token = token_response.json()["data"]["attributes"]["access"]

        response = authenticated_client.get(
            reverse("tenant-membership-list", kwargs={"tenant_pk": tenant2.id}),
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert response.status_code == status.HTTP_200_OK
        # User is a member and can only see its own membership
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["id"] == str(membership3.id)

    def test_tenants_delete_own_membership_as_member(
        self, authenticated_client, tenants_fixture, extra_users
    ):
        tenant1, *_ = tenants_fixture
        membership = Membership.objects.get(tenant=tenant1, user__email=TEST_USER)

        response = authenticated_client.delete(
            reverse(
                "tenant-membership-detail",
                kwargs={"tenant_pk": tenant1.id, "pk": membership.id},
            )
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Membership.objects.filter(id=membership.id).exists()

    def test_tenants_delete_own_membership_as_owner(
        self, authenticated_client, tenants_fixture, extra_users
    ):
        # With extra_users, tenant2 has 2 owners
        _, tenant2, _ = tenants_fixture
        user_membership = Membership.objects.get(tenant=tenant2, user__email=TEST_USER)
        response = authenticated_client.delete(
            reverse(
                "tenant-membership-detail",
                kwargs={"tenant_pk": tenant2.id, "pk": user_membership.id},
            )
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Membership.objects.filter(id=user_membership.id).exists()

    def test_tenants_delete_own_membership_as_last_owner(
        self, authenticated_client, tenants_fixture
    ):
        _, tenant2, _ = tenants_fixture
        user_membership = Membership.objects.get(tenant=tenant2, user__email=TEST_USER)
        response = authenticated_client.delete(
            reverse(
                "tenant-membership-detail",
                kwargs={"tenant_pk": tenant2.id, "pk": user_membership.id},
            )
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert Membership.objects.filter(id=user_membership.id).exists()

    def test_tenants_delete_another_membership_as_owner(
        self, authenticated_client, tenants_fixture, extra_users
    ):
        _, tenant2, _ = tenants_fixture
        _, user3_membership = extra_users
        user3, membership3 = user3_membership

        response = authenticated_client.delete(
            reverse(
                "tenant-membership-detail",
                kwargs={"tenant_pk": tenant2.id, "pk": membership3.id},
            )
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Membership.objects.filter(id=membership3.id).exists()

    def test_tenants_delete_another_membership_as_member(
        self, authenticated_client, tenants_fixture, extra_users
    ):
        _, tenant2, _ = tenants_fixture
        _, user3_membership = extra_users
        user3, membership3 = user3_membership

        # Downgrade membership role manually
        user_membership = Membership.objects.get(tenant=tenant2, user__email=TEST_USER)
        user_membership.role = Membership.RoleChoices.MEMBER
        user_membership.save()

        response = authenticated_client.delete(
            reverse(
                "tenant-membership-detail",
                kwargs={"tenant_pk": tenant2.id, "pk": membership3.id},
            )
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert Membership.objects.filter(id=membership3.id).exists()

    def test_tenants_list_memberships_not_member_of_tenant(self, authenticated_client):
        # Create a tenant the user is not a member of
        tenant4 = Tenant.objects.create(name="Tenant Four")

        response = authenticated_client.get(
            reverse("tenant-membership-list", kwargs={"tenant_pk": tenant4.id})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestMembershipViewSet:
    def test_memberships_list(self, authenticated_client, tenants_fixture):
        user_id = authenticated_client.user.pk
        response = authenticated_client.get(
            reverse("user-membership-list", kwargs={"user_pk": user_id}),
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_memberships_retrieve(self, authenticated_client, tenants_fixture):
        user_id = authenticated_client.user.pk
        list_response = authenticated_client.get(
            reverse("user-membership-list", kwargs={"user_pk": user_id}),
        )
        assert list_response.status_code == status.HTTP_200_OK
        membership = list_response.json()["data"][0]

        response = authenticated_client.get(
            reverse(
                "user-membership-detail",
                kwargs={"user_pk": user_id, "pk": membership["id"]},
            ),
        )
        assert response.status_code == status.HTTP_200_OK
        assert (
            response.json()["data"]["relationships"]["tenant"]["data"]["id"]
            == membership["relationships"]["tenant"]["data"]["id"]
        )
        assert (
            response.json()["data"]["relationships"]["user"]["data"]["id"]
            == membership["relationships"]["user"]["data"]["id"]
        )

    def test_memberships_invalid_retrieve(self, authenticated_client):
        user_id = authenticated_client.user.pk
        response = authenticated_client.get(
            reverse(
                "user-membership-detail",
                kwargs={
                    "user_pk": user_id,
                    "pk": "b91c5eff-13f5-469c-9fd8-917b3a3037b6",
                },
            ),
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        [
            ("role", "owner", 1),
            ("role", "member", 1),
            ("date_joined", TODAY, 2),
            ("date_joined.gte", "2024-01-01", 2),
            ("date_joined.lte", "2024-01-01", 0),
        ],
    )
    def test_memberships_filters(
        self,
        authenticated_client,
        tenants_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        user_id = authenticated_client.user.pk
        response = authenticated_client.get(
            reverse("user-membership-list", kwargs={"user_pk": user_id}),
            {f"filter[{filter_name}]": filter_value},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    def test_memberships_filters_relationships(
        self, authenticated_client, tenants_fixture
    ):
        user_id = authenticated_client.user.pk
        tenant, *_ = tenants_fixture
        # No filter
        response = authenticated_client.get(
            reverse("user-membership-list", kwargs={"user_pk": user_id}),
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

        # Filter by tenant
        response = authenticated_client.get(
            reverse("user-membership-list", kwargs={"user_pk": user_id}),
            {"filter[tenant]": tenant.id},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1

    @pytest.mark.parametrize(
        "filter_name",
        [
            "role",  # Valid filter, invalid value
            "tenant",  # Valid filter, invalid value
            "invalid",  # Invalid filter
        ],
    )
    def test_memberships_filters_invalid(
        self, authenticated_client, tenants_fixture, filter_name
    ):
        user_id = authenticated_client.user.pk
        response = authenticated_client.get(
            reverse("user-membership-list", kwargs={"user_pk": user_id}),
            {f"filter[{filter_name}]": "whatever"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "sort_field",
        [
            "tenant",
            "role",
            "date_joined",
        ],
    )
    def test_memberships_sort(self, authenticated_client, tenants_fixture, sort_field):
        user_id = authenticated_client.user.pk
        response = authenticated_client.get(
            reverse("user-membership-list", kwargs={"user_pk": user_id}),
            {"sort": sort_field},
        )
        assert response.status_code == status.HTTP_200_OK

    def test_memberships_sort_invalid(self, authenticated_client, tenants_fixture):
        user_id = authenticated_client.user.pk
        response = authenticated_client.get(
            reverse("user-membership-list", kwargs={"user_pk": user_id}),
            {"sort": "invalid"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestProviderViewSet:
    @pytest.fixture(scope="function")
    def create_provider_group_relationship(
        self, tenants_fixture, providers_fixture, provider_groups_fixture
    ):
        tenant, *_ = tenants_fixture
        provider1, *_ = providers_fixture
        provider_group1, *_ = provider_groups_fixture
        provider_group_membership = ProviderGroupMembership.objects.create(
            tenant=tenant, provider=provider1, provider_group=provider_group1
        )
        return provider_group_membership

    def test_providers_list(self, authenticated_client, providers_fixture):
        response = authenticated_client.get(reverse("provider-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(providers_fixture)

    @pytest.mark.parametrize(
        "include_values, expected_resources",
        [
            ("provider_groups", ["provider-groups"]),
        ],
    )
    def test_providers_list_include(
        self,
        include_values,
        expected_resources,
        authenticated_client,
        providers_fixture,
        create_provider_group_relationship,
    ):
        response = authenticated_client.get(
            reverse("provider-list"), {"include": include_values}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(providers_fixture)
        assert "included" in response.json()

        included_data = response.json()["included"]
        for expected_type in expected_resources:
            assert any(
                d.get("type") == expected_type for d in included_data
            ), f"Expected type '{expected_type}' not found in included data"

    def test_providers_retrieve(self, authenticated_client, providers_fixture):
        provider1, *_ = providers_fixture
        response = authenticated_client.get(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["provider"] == provider1.provider
        assert response.json()["data"]["attributes"]["uid"] == provider1.uid
        assert response.json()["data"]["attributes"]["alias"] == provider1.alias

    def test_providers_invalid_retrieve(self, authenticated_client):
        response = authenticated_client.get(
            reverse("provider-detail", kwargs={"pk": "random_id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "provider_json_payload",
        (
            [
                {"provider": "aws", "uid": "111111111111", "alias": "test"},
                {"provider": "gcp", "uid": "a12322-test54321", "alias": "test"},
                {
                    "provider": "kubernetes",
                    "uid": "kubernetes-test-123456789",
                    "alias": "test",
                },
                {
                    "provider": "azure",
                    "uid": "8851db6b-42e5-4533-aa9e-30a32d67e875",
                    "alias": "test",
                },
            ]
        ),
    )
    def test_providers_create_valid(self, authenticated_client, provider_json_payload):
        response = authenticated_client.post(
            reverse("provider-list"), data=provider_json_payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Provider.objects.count() == 1
        assert Provider.objects.get().provider == provider_json_payload["provider"]
        assert Provider.objects.get().uid == provider_json_payload["uid"]
        assert Provider.objects.get().alias == provider_json_payload["alias"]

    @pytest.mark.parametrize(
        "provider_json_payload, error_code, error_pointer",
        (
            [
                (
                    {"provider": "aws", "uid": "1", "alias": "test"},
                    "min_length",
                    "uid",
                ),
                (
                    {
                        "provider": "aws",
                        "uid": "1111111111111",
                        "alias": "test",
                    },
                    "aws-uid",
                    "uid",
                ),
                (
                    {"provider": "aws", "uid": "aaaaaaaaaaaa", "alias": "test"},
                    "aws-uid",
                    "uid",
                ),
                (
                    {"provider": "gcp", "uid": "1234asdf", "alias": "test"},
                    "gcp-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "kubernetes",
                        "uid": "-1234asdf",
                        "alias": "test",
                    },
                    "kubernetes-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "azure",
                        "uid": "8851db6b-42e5-4533-aa9e-30a32d67e87",
                        "alias": "test",
                    },
                    "azure-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "does-not-exist",
                        "uid": "8851db6b-42e5-4533-aa9e-30a32d67e87",
                        "alias": "test",
                    },
                    "invalid_choice",
                    "provider",
                ),
            ]
        ),
    )
    def test_providers_invalid_create(
        self,
        authenticated_client,
        provider_json_payload,
        error_code,
        error_pointer,
    ):
        response = authenticated_client.post(
            reverse("provider-list"), data=provider_json_payload, format="json"
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == error_code
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == f"/data/attributes/{error_pointer}"
        )

    def test_providers_partial_update(self, authenticated_client, providers_fixture):
        provider1, *_ = providers_fixture
        new_alias = "This is the new name"
        payload = {
            "data": {
                "type": "providers",
                "id": provider1.id,
                "attributes": {"alias": new_alias},
            },
        }
        response = authenticated_client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_200_OK
        provider1.refresh_from_db()
        assert provider1.alias == new_alias

    def test_providers_partial_update_invalid_content_type(
        self, authenticated_client, providers_fixture
    ):
        provider1, *_ = providers_fixture
        response = authenticated_client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data={},
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_providers_partial_update_invalid_content(
        self, authenticated_client, providers_fixture
    ):
        provider1, *_ = providers_fixture
        new_name = "This is the new name"
        payload = {"alias": new_name}
        response = authenticated_client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "attribute_key, attribute_value",
        [
            ("provider", "aws"),
            ("uid", "123456789012"),
        ],
    )
    def test_providers_partial_update_invalid_fields(
        self,
        authenticated_client,
        providers_fixture,
        attribute_key,
        attribute_value,
    ):
        provider1, *_ = providers_fixture
        payload = {
            "data": {
                "type": "providers",
                "id": provider1.id,
                "attributes": {attribute_key: attribute_value},
            },
        }
        response = authenticated_client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.delete_provider_task.delay")
    def test_providers_delete(
        self,
        mock_delete_task,
        mock_task_get,
        authenticated_client,
        providers_fixture,
        tasks_fixture,
    ):
        prowler_task = tasks_fixture[0]
        task_mock = Mock()
        task_mock.id = prowler_task.id
        mock_delete_task.return_value = task_mock
        mock_task_get.return_value = prowler_task

        provider1, *_ = providers_fixture
        response = authenticated_client.delete(
            reverse("provider-detail", kwargs={"pk": provider1.id})
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        mock_delete_task.assert_called_once_with(
            provider_id=str(provider1.id), tenant_id=ANY
        )
        assert "Content-Location" in response.headers
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task_mock.id}"

    def test_providers_delete_invalid(self, authenticated_client):
        response = authenticated_client.delete(
            reverse("provider-detail", kwargs={"pk": "random_id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.check_provider_connection_task.delay")
    def test_providers_connection(
        self,
        mock_provider_connection,
        mock_task_get,
        authenticated_client,
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

        response = authenticated_client.post(
            reverse("provider-connection", kwargs={"pk": provider1.id})
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        mock_provider_connection.assert_called_once_with(
            provider_id=str(provider1.id), tenant_id=ANY
        )
        assert "Content-Location" in response.headers
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task_mock.id}"

    def test_providers_connection_invalid_provider(
        self, authenticated_client, providers_fixture
    ):
        response = authenticated_client.post(
            reverse("provider-connection", kwargs={"pk": "random_id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        (
            [
                ("provider", "aws", 2),
                ("provider.in", "azure,gcp", 2),
                ("uid", "123456789012", 1),
                ("uid.icontains", "1", 5),
                ("alias", "aws_testing_1", 1),
                ("alias.icontains", "aws", 2),
                ("inserted_at", TODAY, 5),
                ("inserted_at.gte", "2024-01-01", 5),
                ("inserted_at.lte", "2024-01-01", 0),
                ("updated_at.gte", "2024-01-01", 5),
                ("updated_at.lte", "2024-01-01", 0),
            ]
        ),
    )
    def test_providers_filters(
        self,
        authenticated_client,
        providers_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        response = authenticated_client.get(
            reverse("provider-list"),
            {f"filter[{filter_name}]": filter_value},
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    @pytest.mark.parametrize(
        "filter_name",
        (
            [
                "provider",  # Valid filter, invalid value
                "invalid",
            ]
        ),
    )
    def test_providers_filters_invalid(self, authenticated_client, filter_name):
        response = authenticated_client.get(
            reverse("provider-list"),
            {f"filter[{filter_name}]": "whatever"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "sort_field",
        (
            [
                "provider",
                "uid",
                "alias",
                "connected",
                "inserted_at",
                "updated_at",
            ]
        ),
    )
    def test_providers_sort(self, authenticated_client, sort_field):
        response = authenticated_client.get(
            reverse("provider-list"), {"sort": sort_field}
        )
        assert response.status_code == status.HTTP_200_OK

    def test_providers_sort_invalid(self, authenticated_client):
        response = authenticated_client.get(
            reverse("provider-list"), {"sort": "invalid"}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestProviderGroupViewSet:
    def test_provider_group_list(self, authenticated_client, provider_groups_fixture):
        response = authenticated_client.get(reverse("providergroup-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(provider_groups_fixture)

    def test_provider_group_retrieve(
        self, authenticated_client, provider_groups_fixture
    ):
        provider_group = provider_groups_fixture[0]
        response = authenticated_client.get(
            reverse("providergroup-detail", kwargs={"pk": provider_group.id})
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert data["id"] == str(provider_group.id)
        assert data["attributes"]["name"] == provider_group.name

    def test_provider_group_create(self, authenticated_client):
        data = {
            "data": {
                "type": "provider-groups",
                "attributes": {
                    "name": "Test Provider Group",
                },
            }
        }
        response = authenticated_client.post(
            reverse("providergroup-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()["data"]
        assert response_data["attributes"]["name"] == "Test Provider Group"
        assert ProviderGroup.objects.filter(name="Test Provider Group").exists()

    def test_provider_group_create_invalid(self, authenticated_client):
        data = {
            "data": {
                "type": "provider-groups",
                "attributes": {
                    # Name is missing
                },
            }
        }
        response = authenticated_client.post(
            reverse("providergroup-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert errors[0]["source"]["pointer"] == "/data/attributes/name"

    def test_provider_group_partial_update(
        self, authenticated_client, provider_groups_fixture
    ):
        provider_group = provider_groups_fixture[1]
        data = {
            "data": {
                "id": str(provider_group.id),
                "type": "provider-groups",
                "attributes": {
                    "name": "Updated Provider Group Name",
                },
            }
        }
        response = authenticated_client.patch(
            reverse("providergroup-detail", kwargs={"pk": provider_group.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        provider_group.refresh_from_db()
        assert provider_group.name == "Updated Provider Group Name"

    def test_provider_group_partial_update_invalid(
        self, authenticated_client, provider_groups_fixture
    ):
        provider_group = provider_groups_fixture[2]
        data = {
            "data": {
                "id": str(provider_group.id),
                "type": "provider-groups",
                "attributes": {
                    "name": "",  # Invalid name
                },
            }
        }
        response = authenticated_client.patch(
            reverse("providergroup-detail", kwargs={"pk": provider_group.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert errors[0]["source"]["pointer"] == "/data/attributes/name"

    def test_provider_group_destroy(
        self, authenticated_client, provider_groups_fixture
    ):
        provider_group = provider_groups_fixture[2]
        response = authenticated_client.delete(
            reverse("providergroup-detail", kwargs={"pk": provider_group.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not ProviderGroup.objects.filter(id=provider_group.id).exists()

    def test_provider_group_destroy_invalid(self, authenticated_client):
        response = authenticated_client.delete(
            reverse("providergroup-detail", kwargs={"pk": "non-existent-id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_provider_group_providers_update(
        self, authenticated_client, provider_groups_fixture, providers_fixture
    ):
        provider_group = provider_groups_fixture[0]
        provider_ids = [str(provider.id) for provider in providers_fixture]

        data = {
            "data": {
                "type": "provider-group-memberships",
                "id": str(provider_group.id),
                "attributes": {"provider_ids": provider_ids},
            }
        }

        response = authenticated_client.put(
            reverse("providergroup-providers", kwargs={"pk": provider_group.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        memberships = ProviderGroupMembership.objects.filter(
            provider_group=provider_group
        )
        assert memberships.count() == len(provider_ids)
        for membership in memberships:
            assert str(membership.provider_id) in provider_ids

    def test_provider_group_providers_update_non_existent_provider(
        self, authenticated_client, provider_groups_fixture, providers_fixture
    ):
        provider_group = provider_groups_fixture[0]
        provider_ids = [str(provider.id) for provider in providers_fixture]
        provider_ids[-1] = "1b59e032-3eb6-4694-93a5-df84cd9b3ce2"

        data = {
            "data": {
                "type": "provider-group-memberships",
                "id": str(provider_group.id),
                "attributes": {"provider_ids": provider_ids},
            }
        }

        response = authenticated_client.put(
            reverse("providergroup-providers", kwargs={"pk": provider_group.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert (
            errors[0]["detail"]
            == f"The following provider IDs do not exist: {provider_ids[-1]}"
        )

    def test_provider_group_providers_update_invalid_provider(
        self, authenticated_client, provider_groups_fixture
    ):
        provider_group = provider_groups_fixture[1]
        invalid_provider_id = "non-existent-id"
        data = {
            "data": {
                "type": "provider-group-memberships",
                "id": str(provider_group.id),
                "attributes": {"provider_ids": [invalid_provider_id]},
            }
        }

        response = authenticated_client.put(
            reverse("providergroup-providers", kwargs={"pk": provider_group.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert errors[0]["detail"] == "Must be a valid UUID."

    def test_provider_group_providers_update_invalid_payload(
        self, authenticated_client, provider_groups_fixture
    ):
        provider_group = provider_groups_fixture[2]
        data = {
            # Missing "provider_ids"
        }

        response = authenticated_client.put(
            reverse("providergroup-providers", kwargs={"pk": provider_group.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert errors[0]["detail"] == "Received document does not contain primary data"

    def test_provider_group_retrieve_not_found(self, authenticated_client):
        response = authenticated_client.get(
            reverse("providergroup-detail", kwargs={"pk": "non-existent-id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_provider_group_list_filters(
        self, authenticated_client, provider_groups_fixture
    ):
        provider_group = provider_groups_fixture[0]
        response = authenticated_client.get(
            reverse("providergroup-list"), {"filter[name]": provider_group.name}
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["attributes"]["name"] == provider_group.name

    def test_provider_group_list_sorting(
        self, authenticated_client, provider_groups_fixture
    ):
        response = authenticated_client.get(
            reverse("providergroup-list"), {"sort": "name"}
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        names = [item["attributes"]["name"] for item in data]
        assert names == sorted(names)

    def test_provider_group_invalid_method(self, authenticated_client):
        response = authenticated_client.put(reverse("providergroup-list"))
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


@pytest.mark.django_db
class TestProviderSecretViewSet:
    def test_provider_secrets_list(self, authenticated_client, provider_secret_fixture):
        response = authenticated_client.get(reverse("providersecret-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(provider_secret_fixture)

    def test_provider_secrets_retrieve(
        self, authenticated_client, provider_secret_fixture
    ):
        provider_secret1, *_ = provider_secret_fixture
        response = authenticated_client.get(
            reverse("providersecret-detail", kwargs={"pk": provider_secret1.id}),
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["name"] == provider_secret1.name
        assert (
            response.json()["data"]["attributes"]["secret_type"]
            == provider_secret1.secret_type
        )

    def test_provider_secrets_invalid_retrieve(self, authenticated_client):
        response = authenticated_client.get(
            reverse(
                "providersecret-detail",
                kwargs={"pk": "f498b103-c760-4785-9a3e-e23fafbb7b02"},
            )
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "provider_type, secret_type, secret_data",
        [
            # AWS with STATIC secret
            (
                Provider.ProviderChoices.AWS.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "aws_access_key_id": "value",
                    "aws_secret_access_key": "value",
                    "aws_session_token": "value",
                },
            ),
            # AWS with ROLE secret
            (
                Provider.ProviderChoices.AWS.value,
                ProviderSecret.TypeChoices.ROLE,
                {
                    "role_arn": "arn:aws:iam::123456789012:role/example-role",
                    # Optional fields
                    "external_id": "external-id",
                    "role_session_name": "session-name",
                    "session_duration": 3600,
                    "aws_access_key_id": "value",
                    "aws_secret_access_key": "value",
                    "aws_session_token": "value",
                },
            ),
            # Azure with STATIC secret
            (
                Provider.ProviderChoices.AZURE.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "client_id": "client-id",
                    "client_secret": "client-secret",
                    "tenant_id": "tenant-id",
                },
            ),
            # GCP with STATIC secret
            (
                Provider.ProviderChoices.GCP.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "client_id": "client-id",
                    "client_secret": "client-secret",
                    "refresh_token": "refresh-token",
                },
            ),
            # Kubernetes with STATIC secret
            (
                Provider.ProviderChoices.KUBERNETES.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "kubeconfig_content": "kubeconfig-content",
                },
            ),
        ],
    )
    def test_provider_secrets_create_valid(
        self,
        authenticated_client,
        providers_fixture,
        provider_type,
        secret_type,
        secret_data,
    ):
        # Get the provider from the fixture and set its type
        provider = Provider.objects.filter(provider=provider_type)[0]

        data = {
            "data": {
                "type": "provider-secrets",
                "attributes": {
                    "name": "My Secret",
                    "secret_type": secret_type,
                    "secret": secret_data,
                },
                "relationships": {
                    "provider": {"data": {"type": "providers", "id": str(provider.id)}}
                },
            }
        }
        response = authenticated_client.post(
            reverse("providersecret-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert ProviderSecret.objects.count() == 1
        provider_secret = ProviderSecret.objects.first()
        assert provider_secret.name == data["data"]["attributes"]["name"]
        assert provider_secret.secret_type == data["data"]["attributes"]["secret_type"]
        assert (
            str(provider_secret.provider.id)
            == data["data"]["relationships"]["provider"]["data"]["id"]
        )

    @pytest.mark.parametrize(
        "attributes, error_code, error_pointer",
        (
            [
                (
                    {
                        "name": "testing",
                        "secret_type": "static",
                        "secret": {"invalid": "test"},
                    },
                    "required",
                    "secret/aws_access_key_id",
                ),
                (
                    {
                        "name": "testing",
                        "secret_type": "invalid",
                        "secret": {"invalid": "test"},
                    },
                    "invalid_choice",
                    "secret_type",
                ),
                (
                    {
                        "name": "a" * 151,
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "value",
                            "aws_secret_access_key": "value",
                            "aws_session_token": "value",
                        },
                    },
                    "max_length",
                    "name",
                ),
            ]
        ),
    )
    def test_provider_secrets_invalid_create(
        self,
        providers_fixture,
        authenticated_client,
        attributes,
        error_code,
        error_pointer,
    ):
        provider, *_ = providers_fixture
        data = {
            "data": {
                "type": "provider-secrets",
                "attributes": attributes,
                "relationships": {
                    "provider": {"data": {"type": "providers", "id": str(provider.id)}}
                },
            }
        }
        response = authenticated_client.post(
            reverse("providersecret-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == error_code
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == f"/data/attributes/{error_pointer}"
        )

    def test_provider_secrets_partial_update(
        self, authenticated_client, provider_secret_fixture
    ):
        provider_secret, *_ = provider_secret_fixture
        data = {
            "data": {
                "type": "provider-secrets",
                "id": str(provider_secret.id),
                "attributes": {
                    "name": "new_name",
                    "secret": {
                        "aws_access_key_id": "new_value",
                        "aws_secret_access_key": "new_value",
                        "aws_session_token": "new_value",
                    },
                },
                "relationships": {
                    "provider": {
                        "data": {
                            "type": "providers",
                            "id": str(provider_secret.provider.id),
                        }
                    }
                },
            }
        }
        response = authenticated_client.patch(
            reverse("providersecret-detail", kwargs={"pk": provider_secret.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        provider_secret.refresh_from_db()
        assert provider_secret.name == "new_name"
        for value in provider_secret.secret.values():
            assert value == "new_value"

    def test_provider_secrets_partial_update_invalid_content_type(
        self, authenticated_client, provider_secret_fixture
    ):
        provider_secret, *_ = provider_secret_fixture
        response = authenticated_client.patch(
            reverse("providersecret-detail", kwargs={"pk": provider_secret.id}),
            data={},
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_provider_secrets_partial_update_invalid_content(
        self, authenticated_client, provider_secret_fixture
    ):
        provider_secret, *_ = provider_secret_fixture
        data = {
            "data": {
                "type": "provider-secrets",
                "id": str(provider_secret.id),
                "attributes": {"invalid_secret": "value"},
                "relationships": {
                    "provider": {
                        "data": {
                            "type": "providers",
                            "id": str(provider_secret.provider.id),
                        }
                    }
                },
            }
        }
        response = authenticated_client.patch(
            reverse("providersecret-detail", kwargs={"pk": provider_secret.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_provider_secrets_delete(
        self,
        authenticated_client,
        provider_secret_fixture,
    ):
        provider_secret, *_ = provider_secret_fixture
        response = authenticated_client.delete(
            reverse("providersecret-detail", kwargs={"pk": provider_secret.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_provider_secrets_delete_invalid(self, authenticated_client):
        response = authenticated_client.delete(
            reverse(
                "providersecret-detail",
                kwargs={"pk": "e67d0283-440f-48d1-b5f8-38d0763474f4"},
            )
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        (
            [
                ("name", "aws_testing_1", 1),
                ("name.icontains", "aws", 2),
            ]
        ),
    )
    def test_provider_secrets_filters(
        self,
        authenticated_client,
        provider_secret_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        response = authenticated_client.get(
            reverse("providersecret-list"),
            {f"filter[{filter_name}]": filter_value},
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    @pytest.mark.parametrize(
        "filter_name",
        (
            [
                "invalid",
            ]
        ),
    )
    def test_provider_secrets_filters_invalid(self, authenticated_client, filter_name):
        response = authenticated_client.get(
            reverse("providersecret-list"),
            {f"filter[{filter_name}]": "whatever"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "sort_field",
        (
            [
                "name",
                "inserted_at",
                "updated_at",
            ]
        ),
    )
    def test_provider_secrets_sort(self, authenticated_client, sort_field):
        response = authenticated_client.get(
            reverse("providersecret-list"), {"sort": sort_field}
        )
        assert response.status_code == status.HTTP_200_OK

    def test_provider_secrets_sort_invalid(self, authenticated_client):
        response = authenticated_client.get(
            reverse("providersecret-list"), {"sort": "invalid"}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestScanViewSet:
    def test_scans_list(self, authenticated_client, scans_fixture):
        response = authenticated_client.get(reverse("scan-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(scans_fixture)

    def test_scans_retrieve(self, authenticated_client, scans_fixture):
        scan1, *_ = scans_fixture
        response = authenticated_client.get(
            reverse("scan-detail", kwargs={"pk": scan1.id})
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["name"] == scan1.name
        assert response.json()["data"]["relationships"]["provider"]["data"][
            "id"
        ] == str(scan1.provider.id)

    def test_scans_invalid_retrieve(self, authenticated_client):
        response = authenticated_client.get(
            reverse("scan-detail", kwargs={"pk": "random_id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "scan_json_payload, expected_scanner_args",
        [
            # Case 1: No scanner_args in payload (should use provider's scanner_args)
            (
                {
                    "data": {
                        "type": "scans",
                        "attributes": {
                            "name": "New Scan",
                        },
                        "relationships": {
                            "provider": {
                                "data": {"type": "providers", "id": "provider-id-1"}
                            }
                        },
                    }
                },
                {"key1": "value1", "key2": {"key21": "value21"}},
            ),
            (
                {
                    "data": {
                        "type": "scans",
                        "attributes": {
                            "name": "New Scan",
                            "scanner_args": {
                                "key2": {"key21": "test21"},
                                "key3": "test3",
                            },
                        },
                        "relationships": {
                            "provider": {
                                "data": {"type": "providers", "id": "provider-id-1"}
                            }
                        },
                    }
                },
                {"key1": "value1", "key2": {"key21": "test21"}, "key3": "test3"},
            ),
        ],
    )
    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.perform_scan_task.apply_async")
    def test_scans_create_valid(
        self,
        mock_perform_scan_task,
        mock_task_get,
        authenticated_client,
        scan_json_payload,
        expected_scanner_args,
        providers_fixture,
        tasks_fixture,
    ):
        prowler_task = tasks_fixture[0]
        mock_perform_scan_task.return_value.id = prowler_task.id
        mock_task_get.return_value = prowler_task
        *_, provider5 = providers_fixture
        # Provider5 has these scanner_args
        # scanner_args={"key1": "value1", "key2": {"key21": "value21"}}

        # scanner_args will be disabled in the first release
        scan_json_payload["data"]["attributes"].pop("scanner_args", None)

        scan_json_payload["data"]["relationships"]["provider"]["data"]["id"] = str(
            provider5.id
        )

        response = authenticated_client.post(
            reverse("scan-list"),
            data=scan_json_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )

        assert response.status_code == status.HTTP_202_ACCEPTED
        assert Scan.objects.count() == 1

        scan = Scan.objects.get()
        assert scan.name == scan_json_payload["data"]["attributes"]["name"]
        assert scan.provider == provider5
        assert scan.trigger == Scan.TriggerChoices.MANUAL
        # assert scan.scanner_args == expected_scanner_args

    @pytest.mark.parametrize(
        "scan_json_payload, error_code",
        [
            (
                {
                    "data": {
                        "type": "scans",
                        "attributes": {
                            "name": "a",
                            "trigger": Scan.TriggerChoices.MANUAL,
                        },
                        "relationships": {
                            "provider": {
                                "data": {"type": "providers", "id": "provider-id-1"}
                            }
                        },
                    }
                },
                "min_length",
            ),
        ],
    )
    def test_scans_invalid_create(
        self,
        authenticated_client,
        scan_json_payload,
        providers_fixture,
        error_code,
    ):
        provider1, *_ = providers_fixture
        scan_json_payload["data"]["relationships"]["provider"]["data"]["id"] = str(
            provider1.id
        )
        response = authenticated_client.post(
            reverse("scan-list"),
            data=scan_json_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == error_code
        assert (
            response.json()["errors"][0]["source"]["pointer"] == "/data/attributes/name"
        )

    def test_scans_partial_update(self, authenticated_client, scans_fixture):
        scan1, *_ = scans_fixture
        new_name = "Updated Scan Name"
        payload = {
            "data": {
                "type": "scans",
                "id": scan1.id,
                "attributes": {"name": new_name},
            },
        }
        response = authenticated_client.patch(
            reverse("scan-detail", kwargs={"pk": scan1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_200_OK
        scan1.refresh_from_db()
        assert scan1.name == new_name

    def test_scans_partial_update_invalid_content_type(
        self, authenticated_client, scans_fixture
    ):
        scan1, *_ = scans_fixture
        response = authenticated_client.patch(
            reverse("scan-detail", kwargs={"pk": scan1.id}),
            data={},
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_scans_partial_update_invalid_content(
        self, authenticated_client, scans_fixture
    ):
        scan1, *_ = scans_fixture
        new_name = "Updated Scan Name"
        payload = {"name": new_name}
        response = authenticated_client.patch(
            reverse("scan-detail", kwargs={"pk": scan1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        (
            [
                ("provider_type", "aws", 3),
                ("provider_type.in", "gcp,azure", 0),
                ("provider_uid", "123456789012", 2),
                ("provider_uid.icontains", "1", 3),
                ("provider_uid.in", "123456789012,123456789013", 3),
                ("provider_alias", "aws_testing_1", 2),
                ("provider_alias.icontains", "aws", 3),
                ("provider_alias.in", "aws_testing_1,aws_testing_2", 3),
                ("name", "Scan 1", 1),
                ("name.icontains", "Scan", 3),
                ("started_at", "2024-01-02", 3),
                ("started_at.gte", "2024-01-01", 3),
                ("started_at.lte", "2024-01-01", 0),
                ("trigger", Scan.TriggerChoices.MANUAL, 1),
                ("state", StateChoices.AVAILABLE, 2),
                ("state", StateChoices.FAILED, 1),
                ("state.in", f"{StateChoices.FAILED},{StateChoices.AVAILABLE}", 3),
                ("trigger", Scan.TriggerChoices.MANUAL, 1),
            ]
        ),
    )
    def test_scans_filters(
        self,
        authenticated_client,
        scans_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        response = authenticated_client.get(
            reverse("scan-list"),
            {f"filter[{filter_name}]": filter_value},
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    @pytest.mark.parametrize(
        "filter_name",
        [
            "provider",  # Valid filter, invalid value
            "invalid",
        ],
    )
    def test_scans_filters_invalid(self, authenticated_client, filter_name):
        response = authenticated_client.get(
            reverse("scan-list"),
            {f"filter[{filter_name}]": "invalid_value"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_scan_filter_by_provider_id_exact(
        self, authenticated_client, scans_fixture
    ):
        response = authenticated_client.get(
            reverse("scan-list"),
            {"filter[provider]": scans_fixture[0].provider.id},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_scan_filter_by_provider_id_in(self, authenticated_client, scans_fixture):
        response = authenticated_client.get(
            reverse("scan-list"),
            {
                "filter[provider.in]": [
                    scans_fixture[0].provider.id,
                    scans_fixture[1].provider.id,
                ]
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    @pytest.mark.parametrize(
        "sort_field",
        [
            "name",
            "trigger",
            "inserted_at",
            "updated_at",
        ],
    )
    def test_scans_sort(self, authenticated_client, sort_field):
        response = authenticated_client.get(reverse("scan-list"), {"sort": sort_field})
        assert response.status_code == status.HTTP_200_OK

    def test_scans_sort_invalid(self, authenticated_client):
        response = authenticated_client.get(reverse("scan-list"), {"sort": "invalid"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestTaskViewSet:
    def test_tasks_list(self, authenticated_client, tasks_fixture):
        response = authenticated_client.get(reverse("task-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(tasks_fixture)

    def test_tasks_retrieve(self, authenticated_client, tasks_fixture):
        task1, *_ = tasks_fixture
        response = authenticated_client.get(
            reverse("task-detail", kwargs={"pk": task1.id}),
        )
        assert response.status_code == status.HTTP_200_OK
        assert (
            response.json()["data"]["attributes"]["name"]
            == task1.task_runner_task.task_name
        )

    def test_tasks_invalid_retrieve(self, authenticated_client):
        response = authenticated_client.get(
            reverse("task-detail", kwargs={"pk": "invalid_id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @patch("api.v1.views.AsyncResult", return_value=Mock())
    def test_tasks_revoke(self, mock_async_result, authenticated_client, tasks_fixture):
        _, task2 = tasks_fixture
        response = authenticated_client.delete(
            reverse("task-detail", kwargs={"pk": task2.id})
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task2.id}"
        mock_async_result.return_value.revoke.assert_called_once()

    def test_tasks_invalid_revoke(self, authenticated_client):
        response = authenticated_client.delete(
            reverse("task-detail", kwargs={"pk": "invalid_id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tasks_revoke_invalid_status(self, authenticated_client, tasks_fixture):
        task1, _ = tasks_fixture
        response = authenticated_client.delete(
            reverse("task-detail", kwargs={"pk": task1.id})
        )
        # Task status is SUCCESS
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestResourceViewSet:
    def test_resources_list_none(self, authenticated_client):
        response = authenticated_client.get(reverse("resource-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    def test_resources_list(self, authenticated_client, resources_fixture):
        response = authenticated_client.get(reverse("resource-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(resources_fixture)

    @pytest.mark.parametrize(
        "include_values, expected_resources",
        [
            ("provider", ["providers"]),
            ("findings", ["findings"]),
            ("provider,findings", ["providers", "findings"]),
        ],
    )
    def test_resources_list_include(
        self,
        include_values,
        expected_resources,
        authenticated_client,
        resources_fixture,
        findings_fixture,
    ):
        response = authenticated_client.get(
            reverse("resource-list"), {"include": include_values}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(resources_fixture)
        assert "included" in response.json()

        included_data = response.json()["included"]
        for expected_type in expected_resources:
            assert any(
                d.get("type") == expected_type for d in included_data
            ), f"Expected type '{expected_type}' not found in included data"

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        (
            [
                (
                    "uid",
                    "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
                    1,
                ),
                ("uid.icontains", "i-1234567890abcdef", 3),
                ("name", "My Instance 2", 1),
                ("name.icontains", "ce 2", 1),
                ("region", "eu-west-1", 1),
                ("region.icontains", "west", 1),
                ("service", "ec2", 2),
                ("service.icontains", "ec", 2),
                ("inserted_at.gte", "2024-01-01 00:00:00", 3),
                ("updated_at.lte", "2024-01-01 00:00:00", 0),
                ("type.icontains", "prowler", 2),
                # provider filters
                ("provider_type", "aws", 3),
                ("provider_type.in", "azure,gcp", 0),
                ("provider_uid", "123456789012", 2),
                ("provider_uid.in", "123456789012", 2),
                ("provider_uid.in", "123456789012,123456789012", 2),
                ("provider_uid.icontains", "1", 3),
                ("provider_alias", "aws_testing_1", 2),
                ("provider_alias.icontains", "aws", 3),
                # tags searching
                ("tag", "key3:value:value", 0),
                ("tag_key", "key3", 1),
                ("tag_value", "value2", 2),
                ("tag", "key3:multi word value3", 1),
                ("tags", "key3:multi word value3", 1),
                ("tags", "multi word", 1),
                # full text search on resource
                ("search", "arn", 3),
                ("search", "def1", 1),
                # full text search on resource tags
                ("search", "multi word", 1),
                ("search", "key2", 2),
            ]
        ),
    )
    def test_resource_filters(
        self,
        authenticated_client,
        resources_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        response = authenticated_client.get(
            reverse("resource-list"),
            {f"filter[{filter_name}]": filter_value},
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    def test_resource_filter_by_provider_id_in(
        self, authenticated_client, resources_fixture
    ):
        response = authenticated_client.get(
            reverse("resource-list"),
            {
                "filter[provider.in]": [
                    resources_fixture[0].provider.id,
                    resources_fixture[1].provider.id,
                ]
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    @pytest.mark.parametrize(
        "filter_name",
        (
            [
                "resource",  # Invalid filter name
                "invalid",
            ]
        ),
    )
    def test_resources_filters_invalid(self, authenticated_client, filter_name):
        response = authenticated_client.get(
            reverse("resource-list"),
            {f"filter[{filter_name}]": "whatever"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "sort_field",
        [
            "uid",
            "uid",
            "name",
            "region",
            "service",
            "type",
            "inserted_at",
            "updated_at",
        ],
    )
    def test_resources_sort(self, authenticated_client, sort_field):
        response = authenticated_client.get(
            reverse("resource-list"), {"sort": sort_field}
        )
        assert response.status_code == status.HTTP_200_OK

    def test_resources_sort_invalid(self, authenticated_client):
        response = authenticated_client.get(
            reverse("resource-list"), {"sort": "invalid"}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"
        assert response.json()["errors"][0]["source"]["pointer"] == "/data"
        assert (
            response.json()["errors"][0]["detail"] == "invalid sort parameter: invalid"
        )

    def test_resources_retrieve(self, authenticated_client, resources_fixture):
        resource_1, *_ = resources_fixture
        response = authenticated_client.get(
            reverse("resource-detail", kwargs={"pk": resource_1.id}),
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["uid"] == resource_1.uid
        assert response.json()["data"]["attributes"]["name"] == resource_1.name
        assert response.json()["data"]["attributes"]["region"] == resource_1.region
        assert response.json()["data"]["attributes"]["service"] == resource_1.service
        assert response.json()["data"]["attributes"]["type"] == resource_1.type
        assert response.json()["data"]["attributes"]["tags"] == resource_1.get_tags()

    def test_resources_invalid_retrieve(self, authenticated_client):
        response = authenticated_client.get(
            reverse("resource-detail", kwargs={"pk": "random_id"}),
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestFindingViewSet:
    def test_findings_list_none(self, authenticated_client):
        response = authenticated_client.get(reverse("finding-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    def test_findings_list(self, authenticated_client, findings_fixture):
        response = authenticated_client.get(reverse("finding-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(findings_fixture)
        assert (
            response.json()["data"][0]["attributes"]["status"]
            == findings_fixture[0].status
        )

    @pytest.mark.parametrize(
        "include_values, expected_resources",
        [
            ("resources", ["resources"]),
            ("scan", ["scans"]),
            ("resources.provider,scan", ["resources", "scans", "providers"]),
        ],
    )
    def test_findings_list_include(
        self, include_values, expected_resources, authenticated_client, findings_fixture
    ):
        response = authenticated_client.get(
            reverse("finding-list"), {"include": include_values}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(findings_fixture)
        assert "included" in response.json()

        included_data = response.json()["included"]
        for expected_type in expected_resources:
            assert any(
                d.get("type") == expected_type for d in included_data
            ), f"Expected type '{expected_type}' not found in included data"

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        (
            [
                ("delta", "new", 1),
                ("provider_type", "aws", 2),
                ("provider_uid", "123456789012", 2),
                (
                    "resource_uid",
                    "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
                    1,
                ),
                ("resource_uid.icontains", "i-1234567890abcdef", 2),
                ("resource_name", "My Instance 2", 1),
                ("resource_name.icontains", "ce 2", 1),
                ("region", "eu-west-1", 1),
                ("region.in", "eu-west-1,eu-west-2", 1),
                ("region.icontains", "east", 1),
                ("service", "ec2", 1),
                ("service.in", "ec2,s3", 2),
                ("service.icontains", "ec", 1),
                ("inserted_at", "2024-01-01", 0),
                ("inserted_at.date", "2024-01-01", 0),
                ("inserted_at.gte", "2024-01-01", 2),
                ("inserted_at.lte", "2024-12-31", 2),
                ("updated_at.lte", "2024-01-01", 0),
                ("resource_type.icontains", "prowler", 2),
                # full text search on finding
                ("search", "dev-qa", 1),
                ("search", "orange juice", 1),
                # full text search on resource
                ("search", "ec2", 2),
                # full text search on finding tags
                ("search", "value2", 2),
            ]
        ),
    )
    def test_finding_filters(
        self,
        authenticated_client,
        findings_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        response = authenticated_client.get(
            reverse("finding-list"),
            {f"filter[{filter_name}]": filter_value},
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    def test_finding_filter_by_scan_id(self, authenticated_client, findings_fixture):
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[scan]": findings_fixture[0].scan.id,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_finding_filter_by_scan_id_in(self, authenticated_client, findings_fixture):
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[scan.in]": [
                    findings_fixture[0].scan.id,
                    findings_fixture[1].scan.id,
                ]
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_finding_filter_by_provider(self, authenticated_client, findings_fixture):
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[provider]": findings_fixture[0].scan.provider.id,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_finding_filter_by_provider_id_in(
        self, authenticated_client, findings_fixture
    ):
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[provider.in]": [
                    findings_fixture[0].scan.provider.id,
                    findings_fixture[1].scan.provider.id,
                ]
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    @pytest.mark.parametrize(
        "filter_name",
        (
            [
                "finding",  # Invalid filter name
                "invalid",
            ]
        ),
    )
    def test_findings_filters_invalid(self, authenticated_client, filter_name):
        response = authenticated_client.get(
            reverse("finding-list"),
            {f"filter[{filter_name}]": "whatever"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "sort_field",
        [
            "status",
            "severity",
            "check_id",
            "inserted_at",
            "updated_at",
        ],
    )
    def test_findings_sort(self, authenticated_client, sort_field):
        response = authenticated_client.get(
            reverse("finding-list"), {"sort": sort_field}
        )
        assert response.status_code == status.HTTP_200_OK

    def test_findings_sort_invalid(self, authenticated_client):
        response = authenticated_client.get(
            reverse("finding-list"), {"sort": "invalid"}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"
        assert response.json()["errors"][0]["source"]["pointer"] == "/data"
        assert (
            response.json()["errors"][0]["detail"] == "invalid sort parameter: invalid"
        )

    def test_findings_retrieve(self, authenticated_client, findings_fixture):
        finding_1, *_ = findings_fixture
        response = authenticated_client.get(
            reverse("finding-detail", kwargs={"pk": finding_1.id}),
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["status"] == finding_1.status
        assert (
            response.json()["data"]["attributes"]["status_extended"]
            == finding_1.status_extended
        )
        assert response.json()["data"]["attributes"]["severity"] == finding_1.severity
        assert response.json()["data"]["attributes"]["check_id"] == finding_1.check_id

        assert response.json()["data"]["relationships"]["scan"]["data"]["id"] == str(
            finding_1.scan.id
        )

        assert response.json()["data"]["relationships"]["resources"]["data"][0][
            "id"
        ] == str(finding_1.resources.first().id)

    def test_findings_invalid_retrieve(self, authenticated_client):
        response = authenticated_client.get(
            reverse("finding-detail", kwargs={"pk": "random_id"}),
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_findings_services_regions_retrieve(
        self, authenticated_client, findings_fixture
    ):
        finding_1, *_ = findings_fixture
        response = authenticated_client.get(
            reverse("finding-findings_services_regions"),
            {"filter[inserted_at]": finding_1.updated_at.strftime("%Y-%m-%d")},
        )
        data = response.json()

        expected_services = {"ec2", "s3"}
        expected_regions = {"eu-west-1", "us-east-1"}

        assert data["data"]["type"] == "finding-dynamic-filters"
        assert data["data"]["id"] is None
        assert set(data["data"]["attributes"]["services"]) == expected_services
        assert set(data["data"]["attributes"]["regions"]) == expected_regions

    def test_findings_services_regions_severity_retrieve(
        self, authenticated_client, findings_fixture
    ):
        finding_1, *_ = findings_fixture
        response = authenticated_client.get(
            reverse("finding-findings_services_regions"),
            {
                "filter[severity__in]": ["low", "medium"],
                "filter[inserted_at]": finding_1.updated_at.strftime("%Y-%m-%d"),
            },
        )
        data = response.json()

        expected_services = {"s3"}
        expected_regions = {"eu-west-1"}

        assert data["data"]["type"] == "finding-dynamic-filters"
        assert data["data"]["id"] is None
        assert set(data["data"]["attributes"]["services"]) == expected_services
        assert set(data["data"]["attributes"]["regions"]) == expected_regions

    def test_findings_services_regions_future_date(self, authenticated_client):
        response = authenticated_client.get(
            reverse("finding-findings_services_regions"),
            {"filter[inserted_at]": "2048-01-01"},
        )
        data = response.json()
        assert data["data"]["type"] == "finding-dynamic-filters"
        assert data["data"]["id"] is None
        assert data["data"]["attributes"]["services"] == []
        assert data["data"]["attributes"]["regions"] == []

    def test_findings_services_regions_invalid_date(self, authenticated_client):
        response = authenticated_client.get(
            reverse("finding-findings_services_regions"),
            {"filter[inserted_at]": "2048-01-011"},
        )
        assert response.json() == {
            "errors": [
                {
                    "detail": "Enter a valid date.",
                    "status": "400",
                    "source": {"pointer": "/data/attributes/inserted_at"},
                    "code": "invalid",
                }
            ]
        }


@pytest.mark.django_db
class TestJWTFields:
    def test_jwt_fields(self, authenticated_client, create_test_user):
        data = {"type": "tokens", "email": TEST_USER, "password": TEST_PASSWORD}
        response = authenticated_client.post(
            reverse("token-obtain"), data, format="json"
        )

        assert (
            response.status_code == status.HTTP_200_OK
        ), f"Unexpected status code: {response.status_code}"

        access_token = response.data["attributes"]["access"]
        payload = jwt.decode(access_token, options={"verify_signature": False})

        expected_fields = {
            "typ": "access",
            "aud": "https://api.prowler.com",
            "iss": "https://api.prowler.com",
        }

        # Verify expected fields
        for field in expected_fields:
            assert field in payload, f"The field '{field}' is not in the JWT"
            assert (
                payload[field] == expected_fields[field]
            ), f"The value of '{field}' does not match"

        # Verify time fields are integers
        for time_field in ["exp", "iat", "nbf"]:
            assert time_field in payload, f"The field '{time_field}' is not in the JWT"
            assert isinstance(
                payload[time_field], int
            ), f"The field '{time_field}' is not an integer"

        # Verify identification fields are non-empty strings
        for id_field in ["jti", "sub", "tenant_id"]:
            assert id_field in payload, f"The field '{id_field}' is not in the JWT"
            assert (
                isinstance(payload[id_field], str) and payload[id_field]
            ), f"The field '{id_field}' is not a valid string"


@pytest.mark.django_db
class TestInvitationViewSet:
    TOMORROW = datetime.now(timezone.utc) + timedelta(days=1, hours=1)
    TOMORROW_ISO = TOMORROW.isoformat()

    def test_invitations_list(self, authenticated_client, invitations_fixture):
        response = authenticated_client.get(reverse("invitation-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(invitations_fixture)

    def test_invitations_retrieve(self, authenticated_client, invitations_fixture):
        invitation1, _ = invitations_fixture
        response = authenticated_client.get(
            reverse(
                "invitation-detail",
                kwargs={"pk": invitation1.id},
            ),
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["email"] == invitation1.email
        assert response.json()["data"]["attributes"]["state"] == invitation1.state
        assert response.json()["data"]["attributes"]["token"] == invitation1.token
        assert response.json()["data"]["relationships"]["inviter"]["data"]["id"] == str(
            invitation1.inviter.id
        )

    def test_invitations_invalid_retrieve(self, authenticated_client):
        response = authenticated_client.get(
            reverse(
                "invitation-detail",
                kwargs={
                    "pk": "f498b103-c760-4785-9a3e-e23fafbb7b02",
                },
            ),
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_invitations_create_valid(self, authenticated_client, create_test_user):
        user = create_test_user
        data = {
            "data": {
                "type": "invitations",
                "attributes": {
                    "email": "any_email@prowler.com",
                    "expires_at": self.TOMORROW_ISO,
                },
            }
        }
        response = authenticated_client.post(
            reverse("invitation-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Invitation.objects.count() == 1
        assert (
            response.json()["data"]["attributes"]["email"]
            == data["data"]["attributes"]["email"]
        )
        assert response.json()["data"]["attributes"]["expires_at"] == data["data"][
            "attributes"
        ]["expires_at"].replace("+00:00", "Z")
        assert (
            response.json()["data"]["attributes"]["state"]
            == Invitation.State.PENDING.value
        )
        assert response.json()["data"]["relationships"]["inviter"]["data"]["id"] == str(
            user.id
        )

    @pytest.mark.parametrize(
        "email",
        [
            "invalid_email",
            "invalid_email@",
            # There is a pending invitation with this email
            "testing@prowler.com",
            # User is already a member of the tenant
            TEST_USER,
        ],
    )
    def test_invitations_create_invalid_email(
        self, email, authenticated_client, invitations_fixture
    ):
        data = {
            "data": {
                "type": "invitations",
                "attributes": {
                    "email": email,
                    "expires_at": self.TOMORROW_ISO,
                },
            }
        }
        response = authenticated_client.post(
            reverse("invitation-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/email"
        )

    def test_invitations_create_invalid_expires_at(
        self, authenticated_client, invitations_fixture
    ):
        data = {
            "data": {
                "type": "invitations",
                "attributes": {
                    "email": "thisisarandomemail@prowler.com",
                    "expires_at": (
                        datetime.now(timezone.utc) + timedelta(hours=23)
                    ).isoformat(),
                },
            }
        }
        response = authenticated_client.post(
            reverse("invitation-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/expires_at"
        )

    def test_invitations_partial_update_valid(
        self, authenticated_client, invitations_fixture
    ):
        invitation, *_ = invitations_fixture
        new_email = "new_email@prowler.com"
        new_expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        new_expires_at_iso = new_expires_at.isoformat()
        data = {
            "data": {
                "id": str(invitation.id),
                "type": "invitations",
                "attributes": {
                    "email": new_email,
                    "expires_at": new_expires_at_iso,
                },
            }
        }
        assert invitation.email != new_email
        assert invitation.expires_at != new_expires_at

        response = authenticated_client.patch(
            reverse(
                "invitation-detail",
                kwargs={"pk": str(invitation.id)},
            ),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        invitation.refresh_from_db()

        assert invitation.email == new_email
        assert invitation.expires_at == new_expires_at

    @pytest.mark.parametrize(
        "email",
        [
            "invalid_email",
            "invalid_email@",
            # There is a pending invitation with this email
            "testing@prowler.com",
            # User is already a member of the tenant
            TEST_USER,
        ],
    )
    def test_invitations_partial_update_invalid_email(
        self, email, authenticated_client, invitations_fixture
    ):
        invitation, *_ = invitations_fixture
        data = {
            "data": {
                "id": str(invitation.id),
                "type": "invitations",
                "attributes": {
                    "email": email,
                    "expires_at": self.TOMORROW_ISO,
                },
            }
        }
        response = authenticated_client.patch(
            reverse(
                "invitation-detail",
                kwargs={"pk": str(invitation.id)},
            ),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/email"
        )

    def test_invitations_partial_update_invalid_expires_at(
        self, authenticated_client, invitations_fixture
    ):
        invitation, *_ = invitations_fixture
        data = {
            "data": {
                "id": str(invitation.id),
                "type": "invitations",
                "attributes": {
                    "expires_at": (
                        datetime.now(timezone.utc) + timedelta(hours=23)
                    ).isoformat(),
                },
            }
        }
        response = authenticated_client.patch(
            reverse(
                "invitation-detail",
                kwargs={"pk": str(invitation.id)},
            ),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/expires_at"
        )

    def test_invitations_partial_update_invalid_content_type(
        self, authenticated_client, invitations_fixture
    ):
        invitation, *_ = invitations_fixture
        response = authenticated_client.patch(
            reverse(
                "invitation-detail",
                kwargs={"pk": str(invitation.id)},
            ),
            data={},
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_invitations_partial_update_invalid_content(
        self, authenticated_client, invitations_fixture
    ):
        invitation, *_ = invitations_fixture
        response = authenticated_client.patch(
            reverse(
                "invitation-detail",
                kwargs={"pk": str(invitation.id)},
            ),
            data={"email": "invalid_email"},
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_invitations_partial_update_invalid_invitation(self, authenticated_client):
        response = authenticated_client.patch(
            reverse(
                "invitation-detail",
                kwargs={"pk": "54611fc8-b02e-4cc1-aaaa-34acae625629"},
            ),
            data={},
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_invitations_delete(self, authenticated_client, invitations_fixture):
        invitation, *_ = invitations_fixture
        assert invitation.state == Invitation.State.PENDING.value

        response = authenticated_client.delete(
            reverse(
                "invitation-detail",
                kwargs={"pk": str(invitation.id)},
            )
        )
        invitation.refresh_from_db()
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert invitation.state == Invitation.State.REVOKED.value

    def test_invitations_invalid_delete(self, authenticated_client):
        response = authenticated_client.delete(
            reverse(
                "invitation-detail",
                kwargs={"pk": "54611fc8-b02e-4cc1-aaaa-34acae625629"},
            )
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_invitations_invalid_delete_invalid_state(
        self, authenticated_client, invitations_fixture
    ):
        invitation, *_ = invitations_fixture
        invitation.state = Invitation.State.ACCEPTED.value
        invitation.save()

        response = authenticated_client.delete(
            reverse(
                "invitation-detail",
                kwargs={"pk": str(invitation.id)},
            )
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"
        assert response.json()["errors"][0]["source"]["pointer"] == "/data"
        assert (
            response.json()["errors"][0]["detail"]
            == "This invitation cannot be revoked."
        )

    @patch("api.db_router.MainRouter.admin_db", new="default")
    def test_invitations_accept_invitation_new_user(self, client, invitations_fixture):
        invitation, *_ = invitations_fixture

        data = {
            "name": "test",
            "password": "newpassword123",
            "email": invitation.email,
        }
        assert invitation.state == Invitation.State.PENDING.value
        assert not User.objects.filter(email__iexact=invitation.email).exists()

        response = client.post(
            reverse("user-list") + f"?invitation_token={invitation.token}",
            data=data,
            format="json",
        )

        invitation.refresh_from_db()
        assert response.status_code == status.HTTP_201_CREATED
        assert User.objects.filter(email__iexact=invitation.email).exists()
        assert invitation.state == Invitation.State.ACCEPTED.value
        assert Membership.objects.filter(
            user__email__iexact=invitation.email, tenant=invitation.tenant
        ).exists()

    @patch("api.db_router.MainRouter.admin_db", new="default")
    def test_invitations_accept_invitation_existing_user(
        self, authenticated_client, create_test_user, tenants_fixture
    ):
        *_, tenant = tenants_fixture
        user = create_test_user

        invitation = Invitation.objects.create(
            tenant=tenant,
            email=TEST_USER,
            inviter=user,
            expires_at=self.TOMORROW,
        )

        data = {
            "invitation_token": invitation.token,
        }

        assert not Membership.objects.filter(
            user__email__iexact=user.email, tenant=tenant
        ).exists()

        response = authenticated_client.post(
            reverse("invitation-accept"), data=data, format="json"
        )

        assert response.status_code == status.HTTP_201_CREATED
        invitation.refresh_from_db()
        assert Membership.objects.filter(
            user__email__iexact=user.email, tenant=tenant
        ).exists()
        assert invitation.state == Invitation.State.ACCEPTED.value

    @patch("api.db_router.MainRouter.admin_db", new="default")
    def test_invitations_accept_invitation_invalid_token(self, authenticated_client):
        data = {
            "invitation_token": "invalid_token",
        }

        response = authenticated_client.post(
            reverse("invitation-accept"), data=data, format="json"
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.json()["errors"][0]["code"] == "not_found"

    @patch("api.db_router.MainRouter.admin_db", new="default")
    def test_invitations_accept_invitation_invalid_token_expired(
        self, authenticated_client, invitations_fixture
    ):
        invitation, *_ = invitations_fixture
        invitation.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        invitation.email = TEST_USER
        invitation.save()

        data = {
            "invitation_token": invitation.token,
        }

        response = authenticated_client.post(
            reverse("invitation-accept"), data=data, format="json"
        )

        assert response.status_code == status.HTTP_410_GONE

    @patch("api.db_router.MainRouter.admin_db", new="default")
    def test_invitations_accept_invitation_invalid_token_expired_new_user(
        self, client, invitations_fixture
    ):
        new_email = "new_email@prowler.com"
        invitation, *_ = invitations_fixture
        invitation.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        invitation.email = new_email
        invitation.save()

        data = {
            "name": "test",
            "password": "newpassword123",
            "email": new_email,
        }

        response = client.post(
            reverse("user-list") + f"?invitation_token={invitation.token}",
            data=data,
            format="json",
        )

        assert response.status_code == status.HTTP_410_GONE

    @patch("api.db_router.MainRouter.admin_db", new="default")
    def test_invitations_accept_invitation_invalid_token_accepted(
        self, authenticated_client, invitations_fixture
    ):
        invitation, *_ = invitations_fixture
        invitation.state = Invitation.State.ACCEPTED.value
        invitation.email = TEST_USER
        invitation.save()

        data = {
            "invitation_token": invitation.token,
        }

        response = authenticated_client.post(
            reverse("invitation-accept"), data=data, format="json"
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"
        assert (
            response.json()["errors"][0]["detail"]
            == "This invitation is no longer valid."
        )

    @patch("api.db_router.MainRouter.admin_db", new="default")
    def test_invitations_accept_invitation_invalid_token_revoked(
        self, authenticated_client, invitations_fixture
    ):
        invitation, *_ = invitations_fixture
        invitation.state = Invitation.State.REVOKED.value
        invitation.email = TEST_USER
        invitation.save()

        data = {
            "invitation_token": invitation.token,
        }

        response = authenticated_client.post(
            reverse("invitation-accept"), data=data, format="json"
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            response.json()["errors"][0]["detail"]
            == "This invitation is no longer valid."
        )

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        (
            [
                ("inserted_at", TODAY, 2),
                ("inserted_at.gte", "2024-01-01", 2),
                ("inserted_at.lte", "2024-01-01", 0),
                ("updated_at.gte", "2024-01-01", 2),
                ("updated_at.lte", "2024-01-01", 0),
                ("expires_at.gte", TODAY, 1),
                ("expires_at.lte", TODAY, 1),
                ("expires_at", TODAY, 0),
                ("email", "testing@prowler.com", 2),
                ("email.icontains", "testing", 2),
                ("inviter", "", 2),
            ]
        ),
    )
    def test_invitations_filters(
        self,
        authenticated_client,
        create_test_user,
        invitations_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        user = create_test_user
        response = authenticated_client.get(
            reverse("invitation-list"),
            {
                f"filter[{filter_name}]": (
                    filter_value if filter_name != "inviter" else str(user.id)
                )
            },
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    def test_invitations_list_filter_invalid(self, authenticated_client):
        response = authenticated_client.get(
            reverse("invitation-list"),
            {"filter[invalid]": "whatever"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "sort_field",
        [
            "inserted_at",
            "updated_at",
            "expires_at",
            "state",
            "inviter",
        ],
    )
    def test_invitations_sort(self, authenticated_client, sort_field):
        response = authenticated_client.get(
            reverse("invitation-list"),
            {"sort": sort_field},
        )
        assert response.status_code == status.HTTP_200_OK

    def test_invitations_sort_invalid(self, authenticated_client):
        response = authenticated_client.get(
            reverse("invitation-list"),
            {"sort": "invalid"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestComplianceOverviewViewSet:
    def test_compliance_overview_list_none(self, authenticated_client):
        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {"filter[scan_id]": "8d20ac7d-4cbc-435e-85f4-359be37af821"},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    def test_compliance_overview_list(
        self, authenticated_client, compliance_overviews_fixture
    ):
        # List compliance overviews with existing data
        compliance_overview1, compliance_overview2 = compliance_overviews_fixture
        scan_id = str(compliance_overview1.scan.id)

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {"filter[scan_id]": scan_id},
        )
        assert response.status_code == status.HTTP_200_OK
        assert (
            len(response.json()["data"]) == 1
        )  # Due to the custom get_queryset method, only one compliance_id

    def test_compliance_overview_list_missing_scan_id(self, authenticated_client):
        # Attempt to list compliance overviews without providing filter[scan_id]
        response = authenticated_client.get(reverse("complianceoverview-list"))
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["source"]["pointer"] == "filter[scan_id]"
        assert response.json()["errors"][0]["code"] == "required"

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        [
            ("compliance_id", "aws_account_security_onboarding_aws", 1),
            ("compliance_id.icontains", "security_onboarding", 1),
            ("framework", "AWS-Account-Security-Onboarding", 1),
            ("framework.icontains", "security-onboarding", 1),
            ("version", "1.0", 1),
            ("version", "2.0", 0),
            ("version.icontains", "0", 1),
            ("region", "eu-west-1", 1),
            ("region.icontains", "west-1", 1),
            ("region.in", "eu-west-1,eu-west-2", 1),
            ("inserted_at.date", "2024-01-01", 0),
            ("inserted_at.date", TODAY, 1),
            ("inserted_at.gte", "2024-01-01", 1),
        ],
    )
    def test_compliance_overview_filters(
        self,
        authenticated_client,
        compliance_overviews_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        # Test filtering compliance overviews
        compliance_overview1 = compliance_overviews_fixture[0]
        scan_id = str(compliance_overview1.scan.id)

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {
                "filter[scan_id]": scan_id,
                f"filter[{filter_name}]": filter_value,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    @pytest.mark.parametrize(
        "filter_name",
        ["invalid_filter", "unknown_field"],
    )
    def test_compliance_overview_filters_invalid(
        self, authenticated_client, compliance_overviews_fixture, filter_name
    ):
        # Test handling of invalid filters
        compliance_overview1 = compliance_overviews_fixture[0]
        scan_id = str(compliance_overview1.scan.id)

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {
                "filter[scan_id]": scan_id,
                f"filter[{filter_name}]": "some_value",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "sort_field",
        ["inserted_at", "-inserted_at", "compliance_id", "-compliance_id"],
    )
    def test_compliance_overview_sort(
        self, authenticated_client, compliance_overviews_fixture, sort_field
    ):
        # Test sorting compliance overviews
        compliance_overview1 = compliance_overviews_fixture[0]
        scan_id = str(compliance_overview1.scan.id)

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {
                "filter[scan_id]": scan_id,
                "sort": sort_field,
            },
        )
        assert response.status_code == status.HTTP_200_OK

    def test_compliance_overview_sort_invalid(
        self, authenticated_client, compliance_overviews_fixture
    ):
        # Test handling of invalid sort parameters
        compliance_overview1 = compliance_overviews_fixture[0]
        scan_id = str(compliance_overview1.scan.id)

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {
                "filter[scan_id]": scan_id,
                "sort": "invalid_field",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"
        assert "invalid sort parameter" in response.json()["errors"][0]["detail"]

    def test_compliance_overview_retrieve(
        self, authenticated_client, compliance_overviews_fixture
    ):
        # Retrieve a specific compliance overview
        compliance_overview1 = compliance_overviews_fixture[0]

        response = authenticated_client.get(
            reverse(
                "complianceoverview-detail",
                kwargs={"pk": compliance_overview1.id},
            ),
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert data["id"] == str(compliance_overview1.id)
        attributes = data["attributes"]
        assert attributes["compliance_id"] == compliance_overview1.compliance_id
        assert attributes["framework"] == compliance_overview1.framework
        assert attributes["version"] == compliance_overview1.version
        assert attributes["region"] == compliance_overview1.region
        assert attributes["description"] == compliance_overview1.description
        assert "requirements" in attributes

    def test_compliance_overview_invalid_retrieve(self, authenticated_client):
        # Attempt to retrieve a compliance overview with an invalid ID
        response = authenticated_client.get(
            reverse(
                "complianceoverview-detail",
                kwargs={"pk": "invalid-id"},
            ),
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_compliance_overview_list_queryset(
        self, authenticated_client, compliance_overviews_fixture
    ):
        compliance_overview1, compliance_overview2 = compliance_overviews_fixture
        scan_id = str(compliance_overview1.scan.id)

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {"filter[scan_id]": scan_id},
        )
        # No filters, most fails should be returned
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["id"] == str(compliance_overview2.id)

        compliance_overview1.requirements_failed = 5
        compliance_overview1.save()

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {"filter[scan_id]": scan_id},
        )
        # No filters, now compliance_overview1 has more fails
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["id"] == str(compliance_overview1.id)


@pytest.mark.django_db
class TestOverviewViewSet:
    def test_overview_list_invalid_method(self, authenticated_client):
        response = authenticated_client.put(reverse("overview-list"))
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_overview_providers_list(
        self, authenticated_client, findings_fixture, resources_fixture
    ):
        response = authenticated_client.get(reverse("overview-providers"))
        assert response.status_code == status.HTTP_200_OK
        # Only findings from one provider
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["findings"]["total"] == len(
            findings_fixture
        )
        assert response.json()["data"][0]["attributes"]["findings"]["pass"] == 0
        assert response.json()["data"][0]["attributes"]["findings"]["fail"] == 2
        assert response.json()["data"][0]["attributes"]["findings"]["manual"] == 0
        assert response.json()["data"][0]["attributes"]["resources"]["total"] == len(
            resources_fixture
        )

    # TODO Add more tests for the rest of overviews


@pytest.mark.django_db
class TestScheduleViewSet:
    @pytest.mark.parametrize("method", ["get", "post"])
    def test_schedule_invalid_method_list(self, method, authenticated_client):
        response = getattr(authenticated_client, method)(reverse("schedule-list"))
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.schedule_provider_scan")
    def test_schedule_daily(
        self,
        mock_schedule_scan,
        mock_task_get,
        authenticated_client,
        providers_fixture,
        tasks_fixture,
    ):
        provider, *_ = providers_fixture
        prowler_task = tasks_fixture[0]
        mock_schedule_scan.return_value.id = prowler_task.id
        mock_task_get.return_value = prowler_task
        json_payload = {
            "provider_id": str(provider.id),
        }
        response = authenticated_client.post(
            reverse("schedule-daily"), data=json_payload, format="json"
        )
        assert response.status_code == status.HTTP_202_ACCEPTED

    def test_schedule_daily_provider_does_not_exist(self, authenticated_client):
        json_payload = {
            "provider_id": "4846c2f9-84b2-442b-94dd-3082e8eb9584",
        }
        response = authenticated_client.post(
            reverse("schedule-daily"), data=json_payload, format="json"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
