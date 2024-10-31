import json
from datetime import datetime
from unittest.mock import ANY, Mock, patch

import jwt
import pytest
from api.models import Membership, Provider, ProviderSecret, Scan, User
from api.rls import Tenant
from conftest import (
    API_JSON_CONTENT_TYPE,
    TEST_PASSWORD,
    TEST_USER,
)
from django.urls import reverse
from rest_framework import status

TODAY = str(datetime.today().date())


@pytest.mark.django_db
class TestUserViewSet:
    def test_users_list_not_allowed(self, authenticated_client):
        response = authenticated_client.get(reverse("user-list"))
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_users_retrieve(self, authenticated_client, create_test_user):
        response = authenticated_client.get(
            reverse("user-detail", kwargs={"pk": create_test_user.id})
        )
        assert response.status_code == status.HTTP_200_OK

    def test_users_me(self, authenticated_client, create_test_user):
        response = authenticated_client.get(reverse("user-me"))
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["email"] == create_test_user.email

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
                "type": "User",
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
                "type": "User",
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
                "type": "User",
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
        _, tenant2 = tenants_fixture
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
        tenant1, _ = tenants_fixture
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
        assert Tenant.objects.count() == 3
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
        tenant1, _ = tenants_fixture
        new_name = "This is the new name"
        payload = {
            "data": {
                "type": "Tenant",
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
        tenant1, _ = tenants_fixture
        response = authenticated_client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}), data={}
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_tenants_partial_update_invalid_content(
        self, authenticated_client, tenants_fixture
    ):
        tenant1, _ = tenants_fixture
        new_name = "This is the new name"
        payload = {"name": new_name}
        response = authenticated_client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_delete(self, authenticated_client, tenants_fixture):
        tenant1, _ = tenants_fixture
        response = authenticated_client.delete(
            reverse("tenant-detail", kwargs={"pk": tenant1.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert Tenant.objects.count() == 1

    def test_tenants_delete_invalid(self, authenticated_client):
        response = authenticated_client.delete(
            reverse("tenant-detail", kwargs={"pk": "random_id"})
        )
        # To change if we implement RBAC
        # (user might not have permissions to see if the tenant exists or not -> 200 empty)
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tenants_list_filter_search(self, authenticated_client, tenants_fixture):
        """Search is applied to tenants_fixture  name."""
        tenant1, _ = tenants_fixture
        response = authenticated_client.get(
            reverse("tenant-list"), {"filter[search]": tenant1.name}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["name"] == tenant1.name

    def test_tenants_list_query_param_name(self, authenticated_client, tenants_fixture):
        tenant1, _ = tenants_fixture
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
                ("name.icontains", "Tenant", 2),
                ("inserted_at", TODAY, 2),
                ("inserted_at.gte", "2024-01-01", 2),
                ("inserted_at.lte", "2024-01-01", 0),
                ("updated_at.gte", "2024-01-01", 2),
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
        _, tenant2 = tenants_fixture
        response = authenticated_client.get(reverse("tenant-list"), {"sort": "-name"})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2
        assert response.json()["data"][0]["attributes"]["name"] == tenant2.name

    def test_tenants_list_memberships_as_owner(
        self, authenticated_client, tenants_fixture, extra_users
    ):
        _, tenant2 = tenants_fixture
        response = authenticated_client.get(
            reverse("tenant-membership-list", kwargs={"tenant_pk": tenant2.id})
        )
        assert response.status_code == status.HTTP_200_OK
        # Test user + 2 extra users for tenant 2
        assert len(response.json()["data"]) == 3

    def test_tenants_list_memberships_as_member(
        self, authenticated_client, tenants_fixture, extra_users
    ):
        _, tenant2 = tenants_fixture
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
        tenant1, _ = tenants_fixture
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
        _, tenant2 = tenants_fixture
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
        _, tenant2 = tenants_fixture
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
        _, tenant2 = tenants_fixture
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
        _, tenant2 = tenants_fixture
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
        tenant3 = Tenant.objects.create(name="Tenant Three")

        response = authenticated_client.get(
            reverse("tenant-membership-list", kwargs={"tenant_pk": tenant3.id})
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
        assert len(response.json()["data"]) == len(tenants_fixture)

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
    def test_providers_list(self, authenticated_client, providers_fixture):
        response = authenticated_client.get(reverse("provider-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(providers_fixture)

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
                "type": "Provider",
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
                "type": "Provider",
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
                "type": "ProviderSecret",
                "attributes": {
                    "name": "My Secret",
                    "secret_type": secret_type,
                    "secret": secret_data,
                },
                "relationships": {
                    "provider": {"data": {"type": "Provider", "id": str(provider.id)}}
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
                "type": "ProviderSecret",
                "attributes": attributes,
                "relationships": {
                    "provider": {"data": {"type": "Provider", "id": str(provider.id)}}
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
                "type": "ProviderSecret",
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
                            "type": "Provider",
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
                "type": "ProviderSecret",
                "id": str(provider_secret.id),
                "attributes": {"invalid_secret": "value"},
                "relationships": {
                    "provider": {
                        "data": {
                            "type": "Provider",
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
                        "type": "Scan",
                        "attributes": {
                            "name": "New Scan",
                        },
                        "relationships": {
                            "provider": {
                                "data": {"type": "Provider", "id": "provider-id-1"}
                            }
                        },
                    }
                },
                {"key1": "value1", "key2": {"key21": "value21"}},
            ),
            (
                {
                    "data": {
                        "type": "Scan",
                        "attributes": {
                            "name": "New Scan",
                            "scanner_args": {
                                "key2": {"key21": "test21"},
                                "key3": "test3",
                            },
                        },
                        "relationships": {
                            "provider": {
                                "data": {"type": "Provider", "id": "provider-id-1"}
                            }
                        },
                    }
                },
                {"key1": "value1", "key2": {"key21": "test21"}, "key3": "test3"},
            ),
        ],
    )
    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.perform_scan_task.delay")
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
        assert scan.scanner_args == expected_scanner_args

    @pytest.mark.parametrize(
        "scan_json_payload, error_code",
        [
            (
                {
                    "data": {
                        "type": "Scan",
                        "attributes": {
                            "name": "a",
                            "trigger": Scan.TriggerChoices.MANUAL,
                        },
                        "relationships": {
                            "provider": {
                                "data": {"type": "Provider", "id": "provider-id-1"}
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
                "type": "Scan",
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
            ("provider", ["Provider"]),
            ("findings", ["Finding"]),
            ("provider,findings", ["Provider", "Finding"]),
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
            ("resources", ["Resource"]),
            ("scan", ["Scan"]),
            ("resources.provider,scan", ["Resource", "Scan", "Provider"]),
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


@pytest.mark.django_db
class TestJWTFields:
    def test_jwt_fields(self, authenticated_client, create_test_user):
        data = {"type": "Token", "email": TEST_USER, "password": TEST_PASSWORD}
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
