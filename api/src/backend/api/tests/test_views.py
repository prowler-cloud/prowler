import glob
import io
import json
import os
import tempfile
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock, Mock, patch
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import jwt
import pytest
from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount, SocialApp
from botocore.exceptions import ClientError, NoCredentialsError
from conftest import (
    API_JSON_CONTENT_TYPE,
    TEST_PASSWORD,
    TEST_USER,
    TODAY,
    today_after_n_days,
)
from django.conf import settings
from django.db.models import Count
from django.http import JsonResponse
from django.test import RequestFactory
from django.urls import reverse
from django_celery_results.models import TaskResult
from rest_framework import status
from rest_framework.response import Response

from api.attack_paths import (
    AttackPathsQueryDefinition,
    AttackPathsQueryParameterDefinition,
)
from api.compliance import get_compliance_frameworks
from api.db_router import MainRouter
from api.models import (
    AttackSurfaceOverview,
    ComplianceOverviewSummary,
    ComplianceRequirementOverview,
    DailySeveritySummary,
    Finding,
    Integration,
    Invitation,
    LighthouseProviderConfiguration,
    LighthouseProviderModels,
    LighthouseTenantConfiguration,
    Membership,
    Processor,
    Provider,
    ProviderGroup,
    ProviderGroupMembership,
    ProviderSecret,
    Resource,
    Role,
    RoleProviderGroupRelationship,
    SAMLConfiguration,
    SAMLToken,
    Scan,
    ScanSummary,
    StateChoices,
    StatusChoices,
    Task,
    TenantAPIKey,
    ThreatScoreSnapshot,
    User,
    UserRoleRelationship,
)
from api.rls import Tenant
from api.v1.serializers import TokenSerializer
from api.v1.views import ComplianceOverviewViewSet, TenantFinishACSView
from prowler.lib.check.models import Severity
from prowler.lib.outputs.finding import Status


class TestViewSet:
    def test_security_headers(self, client):
        response = client.get("/")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


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

    def test_users_create(self, client):
        valid_user_payload = {
            "name": "test",
            "password": "NewPassword123!",
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
            "NewPassword123",  # No special character
            "newpassword123@",  # No uppercase letter
            "NEWPASSWORD123",  # No lowercase letter
            "NewPassword@",  # No number
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
            "password": "Newpassword123@",
            "email": "nonexistentemail@prowler.com",
        }
        response = authenticated_client.post(
            reverse("user-list"), data=user_payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED

        user_payload = {
            "name": "test_email_validator",
            "password": "Newpassword123@",
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
            "NewPassword123",  # No special character
            "newpassword123@",  # No uppercase letter
            "NEWPASSWORD123",  # No lowercase letter
            "NewPassword@",  # No number
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

    def test_users_destroy_other_user(
        self, authenticated_client, create_test_user, users_fixture
    ):
        user = users_fixture[2]
        response = authenticated_client.delete(
            reverse("user-detail", kwargs={"pk": str(user.id)})
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert User.objects.filter(id=create_test_user.id).exists()

    def test_users_destroy_invalid_user(self, authenticated_client, create_test_user):
        another_user = User.objects.create_user(
            password="otherpassword", email="other@example.com"
        )
        response = authenticated_client.delete(
            reverse("user-detail", kwargs={"pk": another_user.id})
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert User.objects.filter(id=another_user.id).exists()

    def test_users_destroy_cascades_allauth_and_memberships(
        self, authenticated_client, create_test_user
    ):
        # Create related admin-side objects (email + SocialAccount)
        EmailAddress.objects.create(
            user=create_test_user,
            email=create_test_user.email,
            primary=True,
            verified=True,
        )
        SocialAccount.objects.create(
            user=create_test_user, provider="fake-provider", uid="uid-fake-provider"
        )

        # Sanity check pre-conditions
        assert EmailAddress.objects.filter(user=create_test_user).exists()
        assert SocialAccount.objects.filter(user=create_test_user).exists()
        assert Membership.objects.filter(user=create_test_user).exists()
        assert UserRoleRelationship.objects.filter(user=create_test_user).exists()

        # Delete current user
        response = authenticated_client.delete(
            reverse("user-detail", kwargs={"pk": str(create_test_user.id)})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Assert user and related objects are gone
        assert not User.objects.filter(id=create_test_user.id).exists()
        assert not EmailAddress.objects.filter(user_id=create_test_user.id).exists()
        assert not SocialAccount.objects.filter(user_id=create_test_user.id).exists()
        assert not Membership.objects.filter(user_id=create_test_user.id).exists()
        assert not UserRoleRelationship.objects.filter(
            user_id=create_test_user.id
        ).exists()

    def test_users_destroy_with_saml_configuration_and_memberships(
        self, authenticated_client, create_test_user, saml_setup
    ):
        # Ensure SAML configuration exists for tenant (from saml_setup fixture)
        domain = saml_setup["domain"]
        config = SAMLConfiguration.objects.get(email_domain=domain)

        # Attach a SAML SocialAccount to the user
        SocialAccount.objects.create(
            user=create_test_user, provider="saml", uid="uid-saml"
        )

        # Sanity check pre-conditions
        assert SocialAccount.objects.filter(
            user=create_test_user, provider="saml"
        ).exists()
        assert Membership.objects.filter(user=create_test_user).exists()
        assert UserRoleRelationship.objects.filter(user=create_test_user).exists()

        # Delete current user
        response = authenticated_client.delete(
            reverse("user-detail", kwargs={"pk": str(create_test_user.id)})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Assert user-related rows are removed
        assert not User.objects.filter(id=create_test_user.id).exists()
        assert not SocialAccount.objects.filter(user_id=create_test_user.id).exists()
        assert not Membership.objects.filter(user_id=create_test_user.id).exists()
        assert not UserRoleRelationship.objects.filter(
            user_id=create_test_user.id
        ).exists()

        # Tenant-level SAML configuration should remain intact
        assert SAMLConfiguration.objects.filter(id=config.id).exists()
        assert SocialApp.objects.filter(provider="saml", client_id=domain).exists()

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
        assert len(response.json()["data"]) == 2  # Test user belongs to 2 tenants

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
        assert (
            response.json()["meta"]["pagination"]["pages"] == 2
        )  # Test user belongs to 2 tenants

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
        assert response.json()["meta"]["pagination"]["pages"] == 2

    def test_tenants_list_sort_name(self, authenticated_client, tenants_fixture):
        _, tenant2, _ = tenants_fixture
        response = authenticated_client.get(reverse("tenant-list"), {"sort": "-name"})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2
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

    @patch("api.v1.views.TenantMembersViewSet.required_permissions", [])
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

    def test_providers_filter_provider_type(
        self, authenticated_client, providers_fixture
    ):
        response = authenticated_client.get(
            reverse("provider-list"), {"filter[provider_type]": "aws"}
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 2
        assert all(item["attributes"]["provider"] == "aws" for item in data)

    def test_providers_filter_provider_type_in(
        self, authenticated_client, providers_fixture
    ):
        response = authenticated_client.get(
            reverse("provider-list"), {"filter[provider_type__in]": "aws,gcp"}
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 3
        assert {"aws", "gcp"} >= {item["attributes"]["provider"] for item in data}

    def test_providers_filter_provider_type_invalid(
        self, authenticated_client, providers_fixture
    ):
        response = authenticated_client.get(
            reverse("provider-list"), {"filter[provider_type]": "invalid"}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_providers_disable_pagination(
        self, authenticated_client, providers_fixture, tenants_fixture
    ):
        tenant, *_ = tenants_fixture
        existing_count = Provider.objects.filter(tenant_id=tenant.id).count()
        target_total = settings.REST_FRAMEWORK["PAGE_SIZE"] + 1
        additional_needed = max(0, target_total - existing_count)

        base_uid = 200000000000
        for index in range(additional_needed):
            Provider.objects.create(
                tenant_id=tenant.id,
                provider=Provider.ProviderChoices.AWS,
                uid=f"{base_uid + index:012d}",
                alias=f"aws_extra_{index}",
            )

        total_providers = Provider.objects.filter(tenant_id=tenant.id).count()

        paginated_response = authenticated_client.get(reverse("provider-list"))
        assert paginated_response.status_code == status.HTTP_200_OK
        paginated_data = paginated_response.json()["data"]
        assert len(paginated_data) == min(
            settings.REST_FRAMEWORK["PAGE_SIZE"], total_providers
        )
        paginated_meta = paginated_response.json().get("meta", {})
        assert "pagination" in paginated_meta
        assert paginated_meta["pagination"]["count"] == total_providers

        unpaginated_response = authenticated_client.get(
            reverse("provider-list"), {"page[disable]": "true"}
        )
        assert unpaginated_response.status_code == status.HTTP_200_OK
        unpaginated_data = unpaginated_response.json()["data"]
        assert len(unpaginated_data) == total_providers
        unpaginated_meta = unpaginated_response.json().get("meta", {})
        assert "pagination" not in unpaginated_meta

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
                    "provider": "gcp",
                    "uid": "example.com:my-project-123456",
                    "alias": "legacy-gcp",
                },
                {
                    "provider": "kubernetes",
                    "uid": "kubernetes-test-123456789",
                    "alias": "test",
                },
                {
                    "provider": "kubernetes",
                    "uid": "arn:aws:eks:us-east-1:111122223333:cluster/test-cluster-long-name-123456789",
                    "alias": "EKS",
                },
                {
                    "provider": "kubernetes",
                    "uid": "gke_aaaa-dev_europe-test1_dev-aaaa-test-cluster-long-name-123456789",
                    "alias": "GKE",
                },
                {
                    "provider": "kubernetes",
                    "uid": "gke_project/cluster-name",
                    "alias": "GKE",
                },
                {
                    "provider": "kubernetes",
                    "uid": "admin@k8s-demo",
                    "alias": "test",
                },
                {
                    "provider": "azure",
                    "uid": "8851db6b-42e5-4533-aa9e-30a32d67e875",
                    "alias": "test",
                },
                {
                    "provider": "m365",
                    "uid": "TestingPro.onmicrosoft.com",
                    "alias": "test",
                },
                {
                    "provider": "m365",
                    "uid": "subdomain.domain.es",
                    "alias": "test",
                },
                {
                    "provider": "m365",
                    "uid": "microsoft.net",
                    "alias": "test",
                },
                {
                    "provider": "m365",
                    "uid": "subdomain1.subdomain2.subdomain3.subdomain4.domain.net",
                    "alias": "test",
                },
                {
                    "provider": "github",
                    "uid": "test-user",
                    "alias": "test",
                },
                {
                    "provider": "github",
                    "uid": "test-organization",
                    "alias": "GitHub Org",
                },
                {
                    "provider": "github",
                    "uid": "prowler-cloud",
                    "alias": "Prowler",
                },
                {
                    "provider": "github",
                    "uid": "microsoft",
                    "alias": "Microsoft",
                },
                {
                    "provider": "github",
                    "uid": "a12345678901234567890123456789012345678",
                    "alias": "Long Username",
                },
                {
                    "provider": "iac",
                    "uid": "https://github.com/user/repo.git",
                    "alias": "Git Repo",
                },
                {
                    "provider": "iac",
                    "uid": "https://gitlab.com/user/project",
                    "alias": "GitLab Repo",
                },
                {
                    "provider": "mongodbatlas",
                    "uid": "64b1d3c0e4b03b1234567890",
                    "alias": "Atlas Organization",
                },
                {
                    "provider": "alibabacloud",
                    "uid": "1234567890123456",
                    "alias": "Alibaba Cloud Account",
                },
                {
                    "provider": "cloudflare",
                    "uid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                    "alias": "Cloudflare Account",
                },
                {
                    "provider": "openstack",
                    "uid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "alias": "OpenStack Project",
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
        "provider_json_payload",
        (
            [
                {"provider": "aws", "uid": "111111111111", "alias": "test"},
                {"provider": "gcp", "uid": "a12322-test54321", "alias": "test"},
                {
                    "provider": "gcp",
                    "uid": "example.com:my-project-123456",
                    "alias": "legacy-gcp",
                },
                {
                    "provider": "kubernetes",
                    "uid": "kubernetes-test-123456789",
                    "alias": "test",
                },
                {
                    "provider": "kubernetes",
                    "uid": "arn:aws:eks:us-east-1:111122223333:cluster/test-cluster-long-name-123456789",
                    "alias": "EKS",
                },
                {
                    "provider": "kubernetes",
                    "uid": "gke_aaaa-dev_europe-test1_dev-aaaa-test-cluster-long-name-123456789",
                    "alias": "GKE",
                },
                {
                    "provider": "kubernetes",
                    "uid": "gke_project/cluster-name",
                    "alias": "GKE",
                },
                {
                    "provider": "kubernetes",
                    "uid": "admin@k8s-demo",
                    "alias": "test",
                },
                {
                    "provider": "azure",
                    "uid": "8851db6b-42e5-4533-aa9e-30a32d67e875",
                    "alias": "test",
                },
                {
                    "provider": "m365",
                    "uid": "TestingPro.onmicrosoft.com",
                    "alias": "test",
                },
                {
                    "provider": "m365",
                    "uid": "subdomain.domain.es",
                    "alias": "test",
                },
                {
                    "provider": "m365",
                    "uid": "microsoft.net",
                    "alias": "test",
                },
                {
                    "provider": "m365",
                    "uid": "subdomain1.subdomain2.subdomain3.subdomain4.domain.net",
                    "alias": "test",
                },
                {
                    "provider": "github",
                    "uid": "test-user",
                    "alias": "test",
                },
                {
                    "provider": "github",
                    "uid": "test-organization",
                    "alias": "GitHub Org",
                },
                {
                    "provider": "github",
                    "uid": "prowler-cloud",
                    "alias": "Prowler",
                },
                {
                    "provider": "github",
                    "uid": "microsoft",
                    "alias": "Microsoft",
                },
                {
                    "provider": "github",
                    "uid": "a12345678901234567890123456789012345678",
                    "alias": "Long Username",
                },
            ]
        ),
    )
    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.delete_provider_task.delay")
    def test_providers_soft_delete(
        self,
        mock_delete_task,
        mock_task_get,
        authenticated_client,
        provider_json_payload,
        tasks_fixture,
    ):
        # Mock the Celery task response
        prowler_task = tasks_fixture[0]
        task_mock = Mock()
        task_mock.id = prowler_task.id
        mock_delete_task.return_value = task_mock
        mock_task_get.return_value = prowler_task

        # 1.Create a provider
        response = authenticated_client.post(
            reverse("provider-list"), data=provider_json_payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Provider.objects.count() == 1
        provider_id = response.json()["data"]["id"]

        # 2. Soft delete the provider using the actual API endpoint
        response = authenticated_client.delete(
            reverse("provider-detail", kwargs={"pk": provider_id})
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert Provider.objects.count() == 0
        assert Provider.all_objects.count() == 1

        mock_delete_task.assert_called_once_with(
            provider_id=str(provider_id), tenant_id=ANY
        )

        # 3. Create a provider with the same UID should succeed (since the old one is soft deleted)
        response = authenticated_client.post(
            reverse("provider-list"), data=provider_json_payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Provider.objects.count() == 1
        assert Provider.all_objects.count() == 2
        provider_id = response.json()["data"]["id"]

        # 4. Creating another provider with the same UID should fail (duplicate)
        response = authenticated_client.post(
            reverse("provider-list"), data=provider_json_payload, format="json"
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        mock_delete_task.reset_mock()
        mock_delete_task.return_value = task_mock

        # 5. Delete the second provider
        response = authenticated_client.delete(
            reverse("provider-detail", kwargs={"pk": provider_id})
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert Provider.objects.count() == 0
        assert Provider.all_objects.count() == 2

        # 6. Creating a provider with the same UID should succeed again
        response = authenticated_client.post(
            reverse("provider-list"), data=provider_json_payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Provider.objects.count() == 1
        assert Provider.all_objects.count() == 3

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
                (
                    {
                        "provider": "m365",
                        "uid": "https://test.com",
                        "alias": "test",
                    },
                    "m365-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "m365",
                        "uid": "thisisnotadomain",
                        "alias": "test",
                    },
                    "m365-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "m365",
                        "uid": "http://test.com",
                        "alias": "test",
                    },
                    "m365-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "m365",
                        "uid": f"{'a' * 64}.domain.com",
                        "alias": "test",
                    },
                    "m365-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "m365",
                        "uid": f"subdomain.{'a' * 64}.com",
                        "alias": "test",
                    },
                    "m365-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "github",
                        "uid": "-invalid-start",
                        "alias": "test",
                    },
                    "github-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "github",
                        "uid": "invalid@username",
                        "alias": "test",
                    },
                    "github-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "github",
                        "uid": "invalid_username",
                        "alias": "test",
                    },
                    "github-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "github",
                        "uid": "a" * 40,
                        "alias": "test",
                    },
                    "github-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "iac",
                        "uid": "not-a-url",
                        "alias": "test",
                    },
                    "iac-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "iac",
                        "uid": "ftp://invalid-protocol.com/repo",
                        "alias": "test",
                    },
                    "iac-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "iac",
                        "uid": "http://",
                        "alias": "test",
                    },
                    "iac-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "mongodbatlas",
                        "uid": "64b1d3c0e4b03b123456789g",
                        "alias": "test",
                    },
                    "mongodbatlas-uid",
                    "uid",
                ),
                (
                    {
                        "provider": "mongodbatlas",
                        "uid": "1234",
                        "alias": "test",
                    },
                    "mongodbatlas-uid",
                    "uid",
                ),
                # Alibaba Cloud UID validation - too short (not 16 digits)
                (
                    {
                        "provider": "alibabacloud",
                        "uid": "123456789012345",
                        "alias": "test",
                    },
                    "alibabacloud-uid",
                    "uid",
                ),
                # Alibaba Cloud UID validation - too long (not 16 digits)
                (
                    {
                        "provider": "alibabacloud",
                        "uid": "12345678901234567",
                        "alias": "test",
                    },
                    "alibabacloud-uid",
                    "uid",
                ),
                # Alibaba Cloud UID validation - contains non-digits
                (
                    {
                        "provider": "alibabacloud",
                        "uid": "123456789012345a",
                        "alias": "test",
                    },
                    "alibabacloud-uid",
                    "uid",
                ),
                # Cloudflare UID validation - too short (not 32 hex chars)
                (
                    {
                        "provider": "cloudflare",
                        "uid": "abc123",
                        "alias": "test",
                    },
                    "cloudflare-uid",
                    "uid",
                ),
                # Cloudflare UID validation - uppercase hex (must be lowercase)
                (
                    {
                        "provider": "cloudflare",
                        "uid": "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4",
                        "alias": "test",
                    },
                    "cloudflare-uid",
                    "uid",
                ),
                # Cloudflare UID validation - non-hex characters
                (
                    {
                        "provider": "cloudflare",
                        "uid": "g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                        "alias": "test",
                    },
                    "cloudflare-uid",
                    "uid",
                ),
                # Cloudflare UID validation - too long (33 chars)
                (
                    {
                        "provider": "cloudflare",
                        "uid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e",
                        "alias": "test",
                    },
                    "cloudflare-uid",
                    "uid",
                ),
                # OpenStack UID validation - starts with special character
                (
                    {
                        "provider": "openstack",
                        "uid": "-invalid-project",
                        "alias": "test",
                    },
                    "openstack-uid",
                    "uid",
                ),
                # OpenStack UID validation - too short (below min_length)
                (
                    {
                        "provider": "openstack",
                        "uid": "ab",
                        "alias": "test",
                    },
                    "min_length",
                    "uid",
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
                (
                    "uid.icontains",
                    "1",
                    10,
                ),
                ("alias", "aws_testing_1", 1),
                ("alias.icontains", "aws", 2),
                ("inserted_at", TODAY, 11),
                (
                    "inserted_at.gte",
                    "2024-01-01",
                    11,
                ),
                ("inserted_at.lte", "2024-01-01", 0),
                (
                    "updated_at.gte",
                    "2024-01-01",
                    11,
                ),
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

    def test_provider_group_create_with_relationships(
        self, authenticated_client, providers_fixture, roles_fixture
    ):
        provider1, provider2, *_ = providers_fixture
        role1, role2, *_ = roles_fixture

        data = {
            "data": {
                "type": "provider-groups",
                "attributes": {"name": "Test Provider Group with relationships"},
                "relationships": {
                    "providers": {
                        "data": [
                            {"type": "providers", "id": str(provider1.id)},
                            {"type": "providers", "id": str(provider2.id)},
                        ]
                    },
                    "roles": {
                        "data": [
                            {"type": "roles", "id": str(role1.id)},
                            {"type": "roles", "id": str(role2.id)},
                        ]
                    },
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
        group = ProviderGroup.objects.get(id=response_data["id"])
        assert group.name == "Test Provider Group with relationships"
        assert set(group.providers.all()) == {provider1, provider2}
        assert set(group.roles.all()) == {role1, role2}

    def test_provider_group_update_relationships(
        self,
        authenticated_client,
        provider_groups_fixture,
        providers_fixture,
        roles_fixture,
    ):
        group = provider_groups_fixture[0]
        provider3 = providers_fixture[2]
        provider4 = providers_fixture[3]
        role3 = roles_fixture[2]
        role4 = roles_fixture[3]

        data = {
            "data": {
                "id": str(group.id),
                "type": "provider-groups",
                "relationships": {
                    "providers": {
                        "data": [
                            {"type": "providers", "id": str(provider3.id)},
                            {"type": "providers", "id": str(provider4.id)},
                        ]
                    },
                    "roles": {
                        "data": [
                            {"type": "roles", "id": str(role3.id)},
                            {"type": "roles", "id": str(role4.id)},
                        ]
                    },
                },
            }
        }

        response = authenticated_client.patch(
            reverse("providergroup-detail", kwargs={"pk": group.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == status.HTTP_200_OK
        group.refresh_from_db()
        assert set(group.providers.all()) == {provider3, provider4}
        assert set(group.roles.all()) == {role3, role4}

    def test_provider_group_clear_relationships(
        self, authenticated_client, providers_fixture, provider_groups_fixture
    ):
        group = provider_groups_fixture[0]
        provider3 = providers_fixture[2]
        provider4 = providers_fixture[3]

        data = {
            "data": {
                "id": str(group.id),
                "type": "provider-groups",
                "relationships": {
                    "providers": {
                        "data": [
                            {"type": "providers", "id": str(provider3.id)},
                            {"type": "providers", "id": str(provider4.id)},
                        ]
                    }
                },
            }
        }

        response = authenticated_client.patch(
            reverse("providergroup-detail", kwargs={"pk": group.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == status.HTTP_200_OK

        data = {
            "data": {
                "id": str(group.id),
                "type": "provider-groups",
                "relationships": {
                    "providers": {"data": []},  # Removing all providers
                    "roles": {"data": []},  # Removing all roles
                },
            }
        }

        response = authenticated_client.patch(
            reverse("providergroup-detail", kwargs={"pk": group.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == status.HTTP_200_OK
        group.refresh_from_db()
        assert group.providers.count() == 0
        assert group.roles.count() == 0

    def test_provider_group_create_with_invalid_relationships(
        self, authenticated_client
    ):
        invalid_provider_id = "non-existent-id"
        data = {
            "data": {
                "type": "provider-groups",
                "attributes": {"name": "Invalid relationships test"},
                "relationships": {
                    "providers": {
                        "data": [{"type": "providers", "id": invalid_provider_id}]
                    }
                },
            }
        }

        response = authenticated_client.post(
            reverse("providergroup-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code in [status.HTTP_400_BAD_REQUEST]


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
            # GCP with Service Account Key secret
            (
                Provider.ProviderChoices.GCP.value,
                ProviderSecret.TypeChoices.SERVICE_ACCOUNT,
                {
                    "service_account_key": {
                        "type": "service_account",
                        "project_id": "project-id",
                        "private_key_id": "private-key-id",
                        "private_key": "private-key",
                        "client_email": "client-email",
                        "client_id": "client-id",
                        "auth_uri": "auth-uri",
                        "token_uri": "token-uri",
                        "auth_provider_x509_cert_url": "auth-provider-x509-cert-url",
                        "client_x509_cert_url": "client-x509-cert-url",
                        "universe_domain": "universe-domain",
                    },
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
            # M365 client secret credentials
            (
                Provider.ProviderChoices.M365.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "client_id": "client-id",
                    "client_secret": "client-secret",
                    "tenant_id": "tenant-id",
                    "user": "test@domain.com",
                    "password": "supersecret",
                },
            ),
            # M365 certificate credentials (valid base64)
            (
                Provider.ProviderChoices.M365.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "client_id": "client-id",
                    "tenant_id": "tenant-id",
                    "certificate_content": "VGVzdCBjZXJ0aWZpY2F0ZSBjb250ZW50",
                    "user": "test@domain.com",
                    "password": "supersecret",
                },
            ),
            # OCI with API key credentials (with key_content)
            (
                Provider.ProviderChoices.ORACLECLOUD.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "user": "ocid1.user.oc1..aaaaaaaakldibrbov4ubh25aqdeiroklxjngwka7u6w7no3glmdq3n5sxtkq",
                    "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                    "key_content": "-----BEGIN RSA PRIVATE KEY-----\ntest-key-content\n-----END RSA PRIVATE KEY-----",
                    "tenancy": "ocid1.tenancy.oc1..aaaaaaaa3dwoazoox4q7wrvriywpokp5grlhgnkwtyt6dmwyou7no6mdmzda",
                    "region": "us-ashburn-1",
                },
            ),
            # OCI with API key credentials (with key_file)
            (
                Provider.ProviderChoices.ORACLECLOUD.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "user": "ocid1.user.oc1..aaaaaaaakldibrbov4ubh25aqdeiroklxjngwka7u6w7no3glmdq3n5sxtkq",
                    "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                    "key_file": "/path/to/oci_api_key.pem",
                    "tenancy": "ocid1.tenancy.oc1..aaaaaaaa3dwoazoox4q7wrvriywpokp5grlhgnkwtyt6dmwyou7no6mdmzda",
                    "region": "us-ashburn-1",
                },
            ),
            # OCI with API key credentials (with passphrase)
            (
                Provider.ProviderChoices.ORACLECLOUD.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "user": "ocid1.user.oc1..aaaaaaaakldibrbov4ubh25aqdeiroklxjngwka7u6w7no3glmdq3n5sxtkq",
                    "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                    "key_content": "-----BEGIN RSA PRIVATE KEY-----\ntest-encrypted-key\n-----END RSA PRIVATE KEY-----",
                    "tenancy": "ocid1.tenancy.oc1..aaaaaaaa3dwoazoox4q7wrvriywpokp5grlhgnkwtyt6dmwyou7no6mdmzda",
                    "region": "us-ashburn-1",
                    "pass_phrase": "my-secure-passphrase",
                },
            ),
            # MongoDB Atlas credentials
            (
                Provider.ProviderChoices.MONGODBATLAS.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "atlas_public_key": "public-key",
                    "atlas_private_key": "private-key",
                },
            ),
            # Alibaba Cloud credentials (with access key only)
            (
                Provider.ProviderChoices.ALIBABACLOUD.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "access_key_id": "LTAI5t1234567890abcdef",
                    "access_key_secret": "my-secret-access-key",
                },
            ),
            # Alibaba Cloud credentials (with STS security token)
            (
                Provider.ProviderChoices.ALIBABACLOUD.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "access_key_id": "LTAI5t1234567890abcdef",
                    "access_key_secret": "my-secret-access-key",
                    "security_token": "my-security-token-for-sts",
                },
            ),
            # Alibaba Cloud RAM Role Assumption (minimal required fields)
            (
                Provider.ProviderChoices.ALIBABACLOUD.value,
                ProviderSecret.TypeChoices.ROLE,
                {
                    "role_arn": "acs:ram::1234567890123456:role/ProwlerRole",
                    "access_key_id": "LTAI5t1234567890abcdef",
                    "access_key_secret": "my-secret-access-key",
                },
            ),
            # Alibaba Cloud RAM Role Assumption (with optional role_session_name)
            (
                Provider.ProviderChoices.ALIBABACLOUD.value,
                ProviderSecret.TypeChoices.ROLE,
                {
                    "role_arn": "acs:ram::1234567890123456:role/ProwlerRole",
                    "access_key_id": "LTAI5t1234567890abcdef",
                    "access_key_secret": "my-secret-access-key",
                    "role_session_name": "ProwlerAuditSession",
                },
            ),
            # Cloudflare with API Token
            (
                Provider.ProviderChoices.CLOUDFLARE.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "api_token": "fake-cloudflare-api-token-for-testing",
                },
            ),
            # Cloudflare with API Key + Email
            (
                Provider.ProviderChoices.CLOUDFLARE.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "api_key": "fake-cloudflare-api-key-for-testing",
                    "api_email": "user@example.com",
                },
            ),
            # OpenStack with clouds.yaml content
            (
                Provider.ProviderChoices.OPENSTACK.value,
                ProviderSecret.TypeChoices.STATIC,
                {
                    "clouds_yaml_content": "clouds:\n  mycloud:\n    auth:\n      auth_url: https://openstack.example.com:5000/v3\n",
                    "clouds_yaml_cloud": "mycloud",
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
        try:
            provider = Provider.objects.filter(provider=provider_type)[0]
        except IndexError:
            print(f"Provider {provider_type} not found")

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

    def test_provider_secrets_partial_update_with_secret_type(
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
                        "service_account_key": {},
                    },
                    "secret_type": "service_account",
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
        assert provider_secret.secret == {"service_account_key": {}}

    def test_provider_secrets_partial_update_with_invalid_secret_type(
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
                        "service_account_key": {},
                    },
                    "secret_type": "static",
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
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_provider_secrets_partial_update_without_secret_type_but_different(
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
                        "service_account_key": {},
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
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_m365_provider_secrets_invalid_certificate_base64(
        self, authenticated_client, providers_fixture
    ):
        """Test M365 provider secret creation with invalid base64 certificate content"""
        # Find M365 provider from fixture
        m365_provider = None
        for provider in providers_fixture:
            if provider.provider == Provider.ProviderChoices.M365.value:
                m365_provider = provider
                break

        assert m365_provider is not None, "M365 provider not found in fixture"

        data = {
            "data": {
                "type": "provider-secrets",
                "attributes": {
                    "name": "M365 Certificate Invalid Base64",
                    "secret_type": "static",
                    "secret": {
                        "client_id": "client-id",
                        "tenant_id": "tenant-id",
                        "certificate_content": "invalid-base64-content!@#$%",
                        "user": "test@domain.com",
                        "password": "supersecret",
                    },
                },
                "relationships": {
                    "provider": {
                        "data": {"type": "providers", "id": str(m365_provider.id)}
                    }
                },
            }
        }
        response = authenticated_client.post(
            reverse("providersecret-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "certificate content is not valid base64 encoded data" in str(
            response.json()
        )


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
                ("state", StateChoices.AVAILABLE, 1),
                ("state", StateChoices.FAILED, 1),
                ("state.in", f"{StateChoices.FAILED},{StateChoices.AVAILABLE}", 2),
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

    def test_report_executing(self, authenticated_client, scans_fixture):
        """
        When the scan is still executing (state == EXECUTING), the view should return
        the task data with HTTP 202 and a Content-Location header.
        """
        scan = scans_fixture[0]
        scan.state = StateChoices.EXECUTING
        scan.save()

        task = Task.objects.create(tenant_id=scan.tenant_id)
        dummy_task_data = {"id": str(task.id), "state": StateChoices.EXECUTING}

        scan.task = task
        scan.save()

        with patch(
            "api.v1.views.TaskSerializer",
            return_value=type("DummySerializer", (), {"data": dummy_task_data}),
        ):
            url = reverse("scan-report", kwargs={"pk": scan.id})
            response = authenticated_client.get(url)
            assert response.status_code == status.HTTP_202_ACCEPTED
            assert "Content-Location" in response
            assert dummy_task_data["id"] in response["Content-Location"]

    def test_report_celery_task_executing(self, authenticated_client, scans_fixture):
        """
        When the scan is not executing but a related celery task exists and is running,
        the view should return that task data with HTTP 202.
        """
        scan = scans_fixture[0]
        scan.state = StateChoices.COMPLETED
        scan.output_location = "dummy"
        scan.save()

        dummy_task = Task.objects.create(tenant_id=scan.tenant_id)
        dummy_task.id = "dummy-task-id"
        dummy_task_data = {"id": dummy_task.id, "state": StateChoices.EXECUTING}

        with (
            patch("api.v1.views.Task.objects.get", return_value=dummy_task),
            patch(
                "api.v1.views.TaskSerializer",
                return_value=type("DummySerializer", (), {"data": dummy_task_data}),
            ),
        ):
            url = reverse("scan-report", kwargs={"pk": scan.id})
            response = authenticated_client.get(url)
            assert response.status_code == status.HTTP_202_ACCEPTED
            assert "Content-Location" in response
            assert dummy_task_data["id"] in response["Content-Location"]

    def test_report_no_output_location(self, authenticated_client, scans_fixture):
        """
        If the scan does not have an output_location, the view should return a 404.
        """
        scan = scans_fixture[0]
        scan.state = StateChoices.COMPLETED
        scan.output_location = ""
        scan.save()

        url = reverse("scan-report", kwargs={"pk": scan.id})
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert (
            response.json()["errors"]["detail"]
            == "The scan has no reports, or the report generation task has not started yet."
        )

    def test_report_s3_no_credentials(
        self, authenticated_client, scans_fixture, monkeypatch
    ):
        """
        When output_location is an S3 URL and get_s3_client() raises a credentials exception,
        the view should return HTTP 403 with the proper error message.
        """
        scan = scans_fixture[0]
        bucket = "test-bucket"
        key = "report.zip"
        scan.output_location = f"s3://{bucket}/{key}"
        scan.state = StateChoices.COMPLETED
        scan.save()

        def fake_get_s3_client():
            raise NoCredentialsError()

        monkeypatch.setattr("api.v1.views.get_s3_client", fake_get_s3_client)

        url = reverse("scan-report", kwargs={"pk": scan.id})
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert (
            response.json()["errors"]["detail"]
            == "There is a problem with credentials."
        )

    @patch("api.v1.views.ScanViewSet._get_task_status")
    @patch("api.v1.views.get_s3_client")
    @patch("api.v1.views.env.str")
    def test_threatscore_s3_wildcard(
        self,
        mock_env_str,
        mock_get_s3_client,
        mock_get_task_status,
        authenticated_client,
        scans_fixture,
    ):
        """
        When the threatscore endpoint is called with an S3 output_location,
        the view should list objects in S3 using wildcard pattern matching,
        retrieve the matching PDF file, and return it with HTTP 200 and proper headers.
        """
        scan = scans_fixture[0]
        scan.state = StateChoices.COMPLETED
        bucket = "test-bucket"
        zip_key = "tenant-id/scan-id/prowler-output-foo.zip"
        scan.output_location = f"s3://{bucket}/{zip_key}"
        scan.save()

        pdf_key = os.path.join(
            os.path.dirname(zip_key),
            "threatscore",
            "prowler-output-123_threatscore_report.pdf",
        )

        mock_s3_client = Mock()
        mock_s3_client.list_objects_v2.return_value = {"Contents": [{"Key": pdf_key}]}
        mock_s3_client.get_object.return_value = {"Body": io.BytesIO(b"pdf-bytes")}

        mock_env_str.return_value = bucket
        mock_get_s3_client.return_value = mock_s3_client
        mock_get_task_status.return_value = None

        url = reverse("scan-threatscore", kwargs={"pk": scan.id})
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response["Content-Type"] == "application/pdf"
        assert response["Content-Disposition"].endswith(
            '"prowler-output-123_threatscore_report.pdf"'
        )
        assert response.content == b"pdf-bytes"
        mock_s3_client.list_objects_v2.assert_called_once()
        mock_s3_client.get_object.assert_called_once_with(Bucket=bucket, Key=pdf_key)

    def test_report_s3_success(self, authenticated_client, scans_fixture, monkeypatch):
        """
        When output_location is an S3 URL and the S3 client returns the file successfully,
        the view should return the ZIP file with HTTP 200 and proper headers.
        """
        scan = scans_fixture[0]
        bucket = "test-bucket"
        key = "report.zip"
        scan.output_location = f"s3://{bucket}/{key}"
        scan.state = StateChoices.COMPLETED
        scan.save()

        monkeypatch.setattr(
            "api.v1.views.env",
            type("env", (), {"str": lambda self, *args, **kwargs: "test-bucket"})(),
        )

        class FakeS3Client:
            def get_object(self, Bucket, Key):
                assert Bucket == bucket
                assert Key == key
                return {"Body": io.BytesIO(b"s3 zip content")}

        monkeypatch.setattr("api.v1.views.get_s3_client", lambda: FakeS3Client())

        url = reverse("scan-report", kwargs={"pk": scan.id})
        response = authenticated_client.get(url)
        assert response.status_code == 200
        expected_filename = os.path.basename("report.zip")
        content_disposition = response.get("Content-Disposition")
        assert content_disposition.startswith('attachment; filename="')
        assert f'filename="{expected_filename}"' in content_disposition
        assert response.content == b"s3 zip content"

    def test_report_s3_success_no_local_files(
        self, authenticated_client, scans_fixture, monkeypatch
    ):
        """
        When output_location is a local path and glob.glob returns an empty list,
        the view should return HTTP 404 with detail "The scan has no reports, or the report generation task has not started yet."
        """
        scan = scans_fixture[0]
        scan.output_location = "/tmp/nonexistent_report_pattern.zip"
        scan.state = StateChoices.COMPLETED
        scan.save()
        monkeypatch.setattr("api.v1.views.glob.glob", lambda pattern: [])

        url = reverse("scan-report", kwargs={"pk": scan.id})
        response = authenticated_client.get(url)

        assert response.status_code == 404
        assert (
            response.json()["errors"]["detail"]
            == "The scan has no reports, or the report generation task has not started yet."
        )

    def test_report_local_file(self, authenticated_client, scans_fixture, monkeypatch):
        scan = scans_fixture[0]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            base_tmp = tmp_path / "report_local_file"
            base_tmp.mkdir(parents=True, exist_ok=True)

            file_content = b"local zip file content"
            file_path = base_tmp / "report.zip"
            file_path.write_bytes(file_content)

            scan.output_location = str(file_path)
            scan.state = StateChoices.COMPLETED
            scan.save()

            monkeypatch.setattr(
                glob,
                "glob",
                lambda pattern: [str(file_path)] if pattern == str(file_path) else [],
            )

            url = reverse("scan-report", kwargs={"pk": scan.id})
            response = authenticated_client.get(url)
            assert response.status_code == 200
            assert response.content == file_content
            content_disposition = response.get("Content-Disposition")
            assert content_disposition.startswith('attachment; filename="')
            assert f'filename="{file_path.name}"' in content_disposition

    def test_compliance_invalid_framework(self, authenticated_client, scans_fixture):
        scan = scans_fixture[0]
        scan.state = StateChoices.COMPLETED
        scan.output_location = "dummy"
        scan.save()

        url = reverse("scan-compliance", kwargs={"pk": scan.id, "name": "invalid"})
        resp = authenticated_client.get(url)
        assert resp.status_code == status.HTTP_404_NOT_FOUND
        assert resp.json()["errors"]["detail"] == "Compliance 'invalid' not found."

    def test_compliance_executing(
        self, authenticated_client, scans_fixture, monkeypatch
    ):
        scan = scans_fixture[0]
        scan.state = StateChoices.EXECUTING
        scan.save()
        task = Task.objects.create(tenant_id=scan.tenant_id)
        scan.task = task
        scan.save()
        dummy = {"id": str(task.id), "state": StateChoices.EXECUTING}

        monkeypatch.setattr(
            "api.v1.views.TaskSerializer",
            lambda *args, **kwargs: type("S", (), {"data": dummy}),
        )

        framework = get_compliance_frameworks(scan.provider.provider)[0]
        url = reverse("scan-compliance", kwargs={"pk": scan.id, "name": framework})
        resp = authenticated_client.get(url)
        assert resp.status_code == status.HTTP_202_ACCEPTED
        assert "Content-Location" in resp
        assert dummy["id"] in resp["Content-Location"]

    def test_compliance_no_output(self, authenticated_client, scans_fixture):
        scan = scans_fixture[0]
        scan.state = StateChoices.COMPLETED
        scan.output_location = ""
        scan.save()

        framework = get_compliance_frameworks(scan.provider.provider)[0]
        url = reverse("scan-compliance", kwargs={"pk": scan.id, "name": framework})
        resp = authenticated_client.get(url)
        assert resp.status_code == status.HTTP_404_NOT_FOUND
        assert (
            resp.json()["errors"]["detail"]
            == "The scan has no reports, or the report generation task has not started yet."
        )

    def test_compliance_s3_no_credentials(
        self, authenticated_client, scans_fixture, monkeypatch
    ):
        scan = scans_fixture[0]
        bucket = "bucket"
        key = "file.zip"
        scan.output_location = f"s3://{bucket}/{key}"
        scan.state = StateChoices.COMPLETED
        scan.save()

        monkeypatch.setattr(
            "api.v1.views.get_s3_client",
            lambda: (_ for _ in ()).throw(NoCredentialsError()),
        )

        framework = get_compliance_frameworks(scan.provider.provider)[0]
        url = reverse("scan-compliance", kwargs={"pk": scan.id, "name": framework})
        resp = authenticated_client.get(url)
        assert resp.status_code == status.HTTP_403_FORBIDDEN
        assert resp.json()["errors"]["detail"] == "There is a problem with credentials."

    def test_compliance_s3_success(
        self, authenticated_client, scans_fixture, monkeypatch
    ):
        scan = scans_fixture[0]
        bucket = "bucket"
        prefix = "path/scan.zip"
        scan.output_location = f"s3://{bucket}/{prefix}"
        scan.state = StateChoices.COMPLETED
        scan.save()

        monkeypatch.setattr(
            "api.v1.views.env",
            type("env", (), {"str": lambda self, *args, **kwargs: "test-bucket"})(),
        )

        match_key = "path/compliance/mitre_attack_aws.csv"

        class FakeS3Client:
            def list_objects_v2(self, Bucket, Prefix):
                return {"Contents": [{"Key": match_key}]}

            def get_object(self, Bucket, Key):
                return {"Body": io.BytesIO(b"ignored")}

        monkeypatch.setattr("api.v1.views.get_s3_client", lambda: FakeS3Client())

        framework = match_key.split("/")[-1].split(".")[0]
        url = reverse("scan-compliance", kwargs={"pk": scan.id, "name": framework})
        resp = authenticated_client.get(url)
        assert resp.status_code == status.HTTP_200_OK
        cd = resp["Content-Disposition"]
        assert cd.startswith('attachment; filename="')
        assert cd.endswith('filename="mitre_attack_aws.csv"')

    def test_compliance_s3_not_found(
        self, authenticated_client, scans_fixture, monkeypatch
    ):
        scan = scans_fixture[0]
        bucket = "bucket"
        scan.output_location = f"s3://{bucket}/x/scan.zip"
        scan.state = StateChoices.COMPLETED
        scan.save()

        monkeypatch.setattr(
            "api.v1.views.env",
            type("env", (), {"str": lambda self, *args, **kwargs: "test-bucket"})(),
        )

        class FakeS3Client:
            def list_objects_v2(self, Bucket, Prefix):
                return {"Contents": []}

            def get_object(self, Bucket, Key):
                return {"Body": io.BytesIO(b"ignored")}

        monkeypatch.setattr("api.v1.views.get_s3_client", lambda: FakeS3Client())

        url = reverse("scan-compliance", kwargs={"pk": scan.id, "name": "cis_1.4_aws"})
        resp = authenticated_client.get(url)
        assert resp.status_code == status.HTTP_404_NOT_FOUND
        assert (
            resp.json()["errors"]["detail"]
            == "No compliance file found for name 'cis_1.4_aws'."
        )

    def test_compliance_local_file(
        self, authenticated_client, scans_fixture, monkeypatch
    ):
        scan = scans_fixture[0]
        scan.state = StateChoices.COMPLETED

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            base = tmp_path / "reports"
            comp_dir = base / "compliance"
            comp_dir.mkdir(parents=True, exist_ok=True)
            fname = comp_dir / "scan_cis.csv"
            fname.write_bytes(b"ignored")

            scan.output_location = str(base / "scan.zip")
            scan.save()

            monkeypatch.setattr(
                glob,
                "glob",
                lambda p: [str(fname)] if p.endswith("*_cis_1.4_aws.csv") else [],
            )

            url = reverse(
                "scan-compliance", kwargs={"pk": scan.id, "name": "cis_1.4_aws"}
            )
            resp = authenticated_client.get(url)
            assert resp.status_code == status.HTTP_200_OK
            cd = resp["Content-Disposition"]
            assert cd.startswith('attachment; filename="')
            assert cd.endswith(f'filename="{fname.name}"')

    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.TaskSerializer")
    def test__get_task_status_returns_none_if_task_not_executing(
        self, mock_task_serializer, mock_task_get, authenticated_client, scans_fixture
    ):
        scan = scans_fixture[0]
        scan.state = StateChoices.COMPLETED
        scan.output_location = "dummy"
        scan.save()

        task = Task.objects.create(tenant_id=scan.tenant_id)
        mock_task_get.return_value = task
        mock_task_serializer.return_value.data = {
            "id": str(task.id),
            "state": StateChoices.COMPLETED,
        }

        url = reverse("scan-report", kwargs={"pk": scan.id})
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_404_NOT_FOUND

    @patch("api.v1.views.TaskSerializer")
    def test__get_task_status_finds_task_using_kwargs(
        self, mock_task_serializer, authenticated_client, scans_fixture
    ):
        scan = scans_fixture[0]
        scan.state = StateChoices.COMPLETED
        scan.output_location = "dummy"
        scan.save()

        task_result = TaskResult.objects.create(
            task_name="scan-report",
            task_kwargs={"scan_id": str(scan.id)},
        )

        task = Task.objects.create(
            tenant_id=scan.tenant_id,
            task_runner_task=task_result,
        )

        mock_task_serializer.return_value.data = {
            "id": str(task.id),
            "state": StateChoices.EXECUTING,
        }

        url = reverse("scan-report", kwargs={"pk": scan.id})
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_202_ACCEPTED
        assert response.data["id"] == str(task.id)

    @patch("api.v1.views.get_s3_client")
    @patch("api.v1.views.sentry_sdk.capture_exception")
    def test_compliance_list_objects_client_error(
        self,
        mock_sentry_capture,
        mock_get_s3_client,
        authenticated_client,
        scans_fixture,
    ):
        scan = scans_fixture[0]
        scan.output_location = "s3://test-bucket/path/to/scan.zip"
        scan.state = StateChoices.COMPLETED
        scan.save()

        fake_client = MagicMock()
        fake_client.list_objects_v2.side_effect = ClientError(
            {"Error": {"Code": "InternalError"}}, "ListObjectsV2"
        )
        mock_get_s3_client.return_value = fake_client

        framework = get_compliance_frameworks(scan.provider.provider)[0]
        url = reverse("scan-compliance", kwargs={"pk": scan.id, "name": framework})
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_502_BAD_GATEWAY
        assert (
            response.json()["errors"]["detail"]
            == "Unable to list compliance files in S3: encountered an AWS error."
        )
        mock_sentry_capture.assert_called()

    @patch("api.v1.views.get_s3_client")
    def test_report_s3_nosuchkey(
        self, mock_get_s3_client, authenticated_client, scans_fixture
    ):
        scan = scans_fixture[0]
        scan.output_location = "s3://test-bucket/report.zip"
        scan.state = StateChoices.COMPLETED
        scan.save()

        fake_client = MagicMock()
        fake_client.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey"}}, "GetObject"
        )
        mock_get_s3_client.return_value = fake_client

        url = reverse("scan-report", kwargs={"pk": scan.id})
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert (
            response.json()["errors"]["detail"]
            == "The scan has no reports, or the report generation task has not started yet."
        )

    @patch("api.v1.views.get_s3_client")
    def test_report_s3_client_error_other(
        self, mock_get_s3_client, authenticated_client, scans_fixture
    ):
        scan = scans_fixture[0]
        scan.output_location = "s3://test-bucket/report.zip"
        scan.state = StateChoices.COMPLETED
        scan.save()

        fake_client = MagicMock()
        fake_client.get_object.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "GetObject"
        )
        mock_get_s3_client.return_value = fake_client

        url = reverse("scan-report", kwargs={"pk": scan.id})
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert (
            response.json()["errors"]["detail"]
            == "There is a problem with credentials."
        )


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
class TestAttackPathsScanViewSet:
    @staticmethod
    def _run_payload(query_id="aws-rds", parameters=None):
        return {
            "data": {
                "type": "attack-paths-query-run-requests",
                "attributes": {
                    "id": query_id,
                    "parameters": parameters or {},
                },
            }
        }

    def test_attack_paths_scans_list_returns_latest_entry_per_provider(
        self,
        authenticated_client,
        providers_fixture,
        scans_fixture,
        create_attack_paths_scan,
    ):
        provider = providers_fixture[0]
        other_provider = providers_fixture[1]

        older_scan = create_attack_paths_scan(
            provider,
            scan=scans_fixture[0],
            state=StateChoices.AVAILABLE,
            progress=10,
        )
        latest_scan = create_attack_paths_scan(
            provider,
            scan=scans_fixture[0],
            state=StateChoices.COMPLETED,
            progress=95,
        )
        other_provider_scan = create_attack_paths_scan(
            other_provider,
            scan=scans_fixture[2],
            state=StateChoices.FAILED,
            progress=50,
        )

        response = authenticated_client.get(reverse("attack-paths-scans-list"))

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        ids = {item["id"] for item in data}
        assert ids == {str(latest_scan.id), str(other_provider_scan.id)}
        assert str(older_scan.id) not in ids

        provider_entry = next(
            item
            for item in data
            if item["relationships"]["provider"]["data"]["id"] == str(provider.id)
        )

        first_attributes = provider_entry["attributes"]
        assert first_attributes["provider_alias"] == provider.alias
        assert first_attributes["provider_type"] == provider.provider
        assert first_attributes["provider_uid"] == provider.uid

    def test_attack_paths_scans_list_respects_provider_group_visibility(
        self,
        authenticated_client_no_permissions_rbac,
        providers_fixture,
        create_attack_paths_scan,
    ):
        client = authenticated_client_no_permissions_rbac
        limited_user = client.user
        membership = Membership.objects.filter(user=limited_user).first()
        tenant = membership.tenant

        allowed_provider = providers_fixture[0]
        denied_provider = providers_fixture[1]

        allowed_scan = create_attack_paths_scan(allowed_provider)
        create_attack_paths_scan(denied_provider)

        provider_group = ProviderGroup.objects.create(
            name="limited-group",
            tenant_id=tenant.id,
        )
        ProviderGroupMembership.objects.create(
            tenant_id=tenant.id,
            provider_group=provider_group,
            provider=allowed_provider,
        )
        limited_role = limited_user.roles.first()
        RoleProviderGroupRelationship.objects.create(
            tenant_id=tenant.id,
            role=limited_role,
            provider_group=provider_group,
        )

        response = client.get(reverse("attack-paths-scans-list"))

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["id"] == str(allowed_scan.id)

    def test_attack_paths_scan_retrieve(
        self,
        authenticated_client,
        providers_fixture,
        scans_fixture,
        create_attack_paths_scan,
    ):
        provider = providers_fixture[0]
        attack_paths_scan = create_attack_paths_scan(
            provider,
            scan=scans_fixture[0],
            state=StateChoices.COMPLETED,
            progress=80,
        )

        response = authenticated_client.get(
            reverse("attack-paths-scans-detail", kwargs={"pk": attack_paths_scan.id})
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert data["id"] == str(attack_paths_scan.id)
        assert data["relationships"]["provider"]["data"]["id"] == str(provider.id)
        assert data["attributes"]["state"] == StateChoices.COMPLETED

    def test_attack_paths_scan_retrieve_not_found_for_foreign_tenant(
        self, authenticated_client, create_attack_paths_scan
    ):
        other_tenant = Tenant.objects.create(name="Foreign AttackPaths Tenant")
        foreign_provider = Provider.objects.create(
            provider="aws",
            uid="333333333333",
            alias="foreign",
            tenant_id=other_tenant.id,
        )
        foreign_scan = create_attack_paths_scan(foreign_provider)

        response = authenticated_client.get(
            reverse("attack-paths-scans-detail", kwargs={"pk": foreign_scan.id})
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_attack_paths_queries_returns_catalog(
        self,
        authenticated_client,
        providers_fixture,
        scans_fixture,
        create_attack_paths_scan,
    ):
        provider = providers_fixture[0]
        attack_paths_scan = create_attack_paths_scan(
            provider,
            scan=scans_fixture[0],
        )

        definitions = [
            AttackPathsQueryDefinition(
                id="aws-rds",
                name="RDS inventory",
                short_description="List account RDS assets.",
                description="List account RDS assets",
                provider=provider.provider,
                cypher="MATCH (n) RETURN n",
                parameters=[
                    AttackPathsQueryParameterDefinition(name="ip", label="IP address")
                ],
            )
        ]

        with patch(
            "api.v1.views.get_queries_for_provider", return_value=definitions
        ) as mock_get_queries:
            response = authenticated_client.get(
                reverse(
                    "attack-paths-scans-queries", kwargs={"pk": attack_paths_scan.id}
                )
            )

        assert response.status_code == status.HTTP_200_OK
        mock_get_queries.assert_called_once_with(provider.provider)
        payload = response.json()["data"]
        assert len(payload) == 1
        assert payload[0]["id"] == "aws-rds"
        assert payload[0]["attributes"]["name"] == "RDS inventory"
        assert payload[0]["attributes"]["parameters"][0]["name"] == "ip"

    def test_attack_paths_queries_returns_404_when_catalog_missing(
        self,
        authenticated_client,
        providers_fixture,
        scans_fixture,
        create_attack_paths_scan,
    ):
        provider = providers_fixture[0]
        attack_paths_scan = create_attack_paths_scan(provider, scan=scans_fixture[0])

        with patch("api.v1.views.get_queries_for_provider", return_value=[]):
            response = authenticated_client.get(
                reverse(
                    "attack-paths-scans-queries", kwargs={"pk": attack_paths_scan.id}
                )
            )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "No queries found" in str(response.json())

    def test_run_attack_paths_query_returns_graph(
        self,
        authenticated_client,
        providers_fixture,
        scans_fixture,
        create_attack_paths_scan,
    ):
        provider = providers_fixture[0]
        attack_paths_scan = create_attack_paths_scan(
            provider,
            scan=scans_fixture[0],
            graph_data_ready=True,
        )
        query_definition = AttackPathsQueryDefinition(
            id="aws-rds",
            name="RDS inventory",
            short_description="List account RDS assets.",
            description="List account RDS assets",
            provider=provider.provider,
            cypher="MATCH (n) RETURN n",
            parameters=[],
        )
        prepared_parameters = {"provider_uid": provider.uid}
        graph_payload = {
            "nodes": [
                {
                    "id": "node-1",
                    "labels": ["AWSAccount"],
                    "properties": {"name": "root"},
                }
            ],
            "relationships": [
                {
                    "id": "rel-1",
                    "label": "OWNS",
                    "source": "node-1",
                    "target": "node-2",
                    "properties": {},
                }
            ],
        }

        expected_db_name = f"db-tenant-{attack_paths_scan.provider.tenant_id}"

        with (
            patch(
                "api.v1.views.get_query_by_id", return_value=query_definition
            ) as mock_get_query,
            patch(
                "api.v1.views.graph_database.get_database_name",
                return_value=expected_db_name,
            ) as mock_get_db_name,
            patch(
                "api.v1.views.attack_paths_views_helpers.prepare_query_parameters",
                return_value=prepared_parameters,
            ) as mock_prepare,
            patch(
                "api.v1.views.attack_paths_views_helpers.execute_attack_paths_query",
                return_value=graph_payload,
            ) as mock_execute,
            patch("api.v1.views.graph_database.clear_cache") as mock_clear_cache,
        ):
            response = authenticated_client.post(
                reverse(
                    "attack-paths-scans-queries-run",
                    kwargs={"pk": attack_paths_scan.id},
                ),
                data=self._run_payload("aws-rds"),
                content_type=API_JSON_CONTENT_TYPE,
            )

        assert response.status_code == status.HTTP_200_OK
        mock_get_query.assert_called_once_with("aws-rds")
        mock_get_db_name.assert_called_once_with(attack_paths_scan.provider.tenant_id)
        provider_id = str(attack_paths_scan.provider_id)
        mock_prepare.assert_called_once_with(
            query_definition,
            {},
            attack_paths_scan.provider.uid,
            provider_id,
        )
        mock_execute.assert_called_once_with(
            expected_db_name,
            query_definition,
            prepared_parameters,
            provider_id,
        )
        mock_clear_cache.assert_called_once_with(expected_db_name)
        result = response.json()["data"]
        attributes = result["attributes"]
        assert attributes["nodes"] == graph_payload["nodes"]
        assert attributes["relationships"] == graph_payload["relationships"]

    def test_run_attack_paths_query_blocks_when_graph_data_not_ready(
        self,
        authenticated_client,
        providers_fixture,
        scans_fixture,
        create_attack_paths_scan,
    ):
        provider = providers_fixture[0]
        attack_paths_scan = create_attack_paths_scan(
            provider,
            scan=scans_fixture[0],
            state=StateChoices.EXECUTING,
            graph_data_ready=False,
        )

        response = authenticated_client.post(
            reverse(
                "attack-paths-scans-queries-run", kwargs={"pk": attack_paths_scan.id}
            ),
            data=self._run_payload(),
            content_type=API_JSON_CONTENT_TYPE,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "not available" in response.json()["errors"][0]["detail"]

    def test_run_attack_paths_query_allows_executing_scan_when_graph_data_ready(
        self,
        authenticated_client,
        providers_fixture,
        scans_fixture,
        create_attack_paths_scan,
    ):
        provider = providers_fixture[0]
        attack_paths_scan = create_attack_paths_scan(
            provider,
            scan=scans_fixture[0],
            state=StateChoices.EXECUTING,
            graph_data_ready=True,
        )
        query_definition = AttackPathsQueryDefinition(
            id="aws-test",
            name="Test",
            short_description="Test query.",
            description="Test query",
            provider=provider.provider,
            cypher="MATCH (n) RETURN n",
            parameters=[],
        )

        with (
            patch("api.v1.views.get_query_by_id", return_value=query_definition),
            patch(
                "api.v1.views.attack_paths_views_helpers.prepare_query_parameters",
                return_value={"provider_uid": provider.uid},
            ),
            patch(
                "api.v1.views.attack_paths_views_helpers.execute_attack_paths_query",
                return_value={
                    "nodes": [{"id": "n1", "labels": ["AWSAccount"], "properties": {}}],
                    "relationships": [],
                },
            ),
            patch("api.v1.views.graph_database.clear_cache"),
            patch(
                "api.v1.views.graph_database.get_database_name", return_value="db-test"
            ),
        ):
            response = authenticated_client.post(
                reverse(
                    "attack-paths-scans-queries-run",
                    kwargs={"pk": attack_paths_scan.id},
                ),
                data=self._run_payload("aws-test"),
                content_type=API_JSON_CONTENT_TYPE,
            )

        assert response.status_code == status.HTTP_200_OK

    def test_run_attack_paths_query_allows_failed_scan_when_graph_data_ready(
        self,
        authenticated_client,
        providers_fixture,
        scans_fixture,
        create_attack_paths_scan,
    ):
        provider = providers_fixture[0]
        attack_paths_scan = create_attack_paths_scan(
            provider,
            scan=scans_fixture[0],
            state=StateChoices.FAILED,
            graph_data_ready=True,
        )
        query_definition = AttackPathsQueryDefinition(
            id="aws-test",
            name="Test",
            short_description="Test query.",
            description="Test query",
            provider=provider.provider,
            cypher="MATCH (n) RETURN n",
            parameters=[],
        )

        with (
            patch("api.v1.views.get_query_by_id", return_value=query_definition),
            patch(
                "api.v1.views.attack_paths_views_helpers.prepare_query_parameters",
                return_value={"provider_uid": provider.uid},
            ),
            patch(
                "api.v1.views.attack_paths_views_helpers.execute_attack_paths_query",
                return_value={
                    "nodes": [{"id": "n1", "labels": ["AWSAccount"], "properties": {}}],
                    "relationships": [],
                },
            ),
            patch("api.v1.views.graph_database.clear_cache"),
            patch(
                "api.v1.views.graph_database.get_database_name", return_value="db-test"
            ),
        ):
            response = authenticated_client.post(
                reverse(
                    "attack-paths-scans-queries-run",
                    kwargs={"pk": attack_paths_scan.id},
                ),
                data=self._run_payload("aws-test"),
                content_type=API_JSON_CONTENT_TYPE,
            )

        assert response.status_code == status.HTTP_200_OK

    def test_run_attack_paths_query_unknown_query(
        self,
        authenticated_client,
        providers_fixture,
        scans_fixture,
        create_attack_paths_scan,
    ):
        provider = providers_fixture[0]
        attack_paths_scan = create_attack_paths_scan(
            provider,
            scan=scans_fixture[0],
            graph_data_ready=True,
        )

        with patch("api.v1.views.get_query_by_id", return_value=None):
            response = authenticated_client.post(
                reverse(
                    "attack-paths-scans-queries-run",
                    kwargs={"pk": attack_paths_scan.id},
                ),
                data=self._run_payload("unknown-query"),
                content_type=API_JSON_CONTENT_TYPE,
            )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Unknown Attack Paths query" in response.json()["errors"][0]["detail"]

    def test_run_attack_paths_query_returns_404_when_no_nodes_found(
        self,
        authenticated_client,
        providers_fixture,
        scans_fixture,
        create_attack_paths_scan,
    ):
        provider = providers_fixture[0]
        attack_paths_scan = create_attack_paths_scan(
            provider,
            scan=scans_fixture[0],
            graph_data_ready=True,
        )
        query_definition = AttackPathsQueryDefinition(
            id="aws-empty",
            name="empty",
            short_description="",
            description="",
            provider=provider.provider,
            cypher="MATCH (n) RETURN n",
        )

        with (
            patch("api.v1.views.get_query_by_id", return_value=query_definition),
            patch(
                "api.v1.views.attack_paths_views_helpers.prepare_query_parameters",
                return_value={"provider_uid": provider.uid},
            ),
            patch(
                "api.v1.views.attack_paths_views_helpers.execute_attack_paths_query",
                return_value={"nodes": [], "relationships": []},
            ),
            patch("api.v1.views.graph_database.clear_cache"),
        ):
            response = authenticated_client.post(
                reverse(
                    "attack-paths-scans-queries-run",
                    kwargs={"pk": attack_paths_scan.id},
                ),
                data=self._run_payload("aws-empty"),
                content_type=API_JSON_CONTENT_TYPE,
            )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        payload = response.json()
        if "data" in payload:
            attributes = payload["data"].get("attributes", {})
            assert attributes.get("nodes") == []
            assert attributes.get("relationships") == []
        else:
            assert "errors" in payload


@pytest.mark.django_db
class TestResourceViewSet:
    def test_resources_list_none(self, authenticated_client):
        response = authenticated_client.get(
            reverse("resource-list"), {"filter[updated_at]": TODAY}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    def test_resources_list_no_date_filter(self, authenticated_client):
        response = authenticated_client.get(reverse("resource-list"))
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "required"

    def test_resources_list(self, authenticated_client, resources_fixture):
        response = authenticated_client.get(
            reverse("resource-list"), {"filter[updated_at]": TODAY}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(resources_fixture)
        assert "metadata" in response.json()["data"][0]["attributes"]
        assert "details" in response.json()["data"][0]["attributes"]
        assert "partition" in response.json()["data"][0]["attributes"]
        assert "groups" in response.json()["data"][0]["attributes"]

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
            reverse("resource-list"),
            {"include": include_values, "filter[updated_at]": TODAY},
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
                ("inserted_at.gte", today_after_n_days(-1), 3),
                ("updated_at.gte", today_after_n_days(-1), 3),
                ("updated_at.lte", today_after_n_days(1), 3),
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
                # To improve search efficiency, full text search is not fully applicable
                # ("search", "def1", 1),
                # full text search on resource tags
                ("search", "multi word", 1),
                ("search", "key2", 2),
                # groups filter (ArrayField)
                ("groups", "compute", 2),
                ("groups", "storage", 1),
                ("groups.in", "compute,storage", 3),
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
        filters = {f"filter[{filter_name}]": filter_value}
        if "updated_at" not in filter_name:
            filters["filter[updated_at]"] = TODAY
        response = authenticated_client.get(
            reverse("resource-list"),
            filters,
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    def test_resource_filter_by_scan_id(
        self, authenticated_client, resources_fixture, scans_fixture
    ):
        response = authenticated_client.get(
            reverse("resource-list"),
            {"filter[scan]": scans_fixture[0].id},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_resource_filter_by_scan_id_in(
        self, authenticated_client, resources_fixture, scans_fixture
    ):
        response = authenticated_client.get(
            reverse("resource-list"),
            {
                "filter[scan.in]": [
                    scans_fixture[0].id,
                    scans_fixture[1].id,
                ]
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_resource_filter_by_provider_id_in(
        self, authenticated_client, resources_fixture
    ):
        response = authenticated_client.get(
            reverse("resource-list"),
            {
                "filter[provider.in]": [
                    resources_fixture[0].provider.id,
                    resources_fixture[1].provider.id,
                ],
                "filter[updated_at]": TODAY,
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
            reverse("resource-list"), {"filter[updated_at]": TODAY, "sort": sort_field}
        )
        assert response.status_code == status.HTTP_200_OK

    def test_resources_sort_invalid(self, authenticated_client):
        response = authenticated_client.get(
            reverse("resource-list"), {"filter[updated_at]": TODAY, "sort": "invalid"}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"
        assert response.json()["errors"][0]["source"]["pointer"] == "/data"
        assert (
            response.json()["errors"][0]["detail"] == "invalid sort parameter: invalid"
        )

    def test_resources_retrieve(
        self, authenticated_client, tenants_fixture, resources_fixture
    ):
        tenant = tenants_fixture[0]
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
        assert response.json()["data"]["attributes"]["tags"] == resource_1.get_tags(
            tenant_id=str(tenant.id)
        )

    def test_resources_invalid_retrieve(self, authenticated_client):
        response = authenticated_client.get(
            reverse("resource-detail", kwargs={"pk": "random_id"}),
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_resources_metadata_retrieve(
        self, authenticated_client, resources_fixture, backfill_scan_metadata_fixture
    ):
        resource_1, *_ = resources_fixture
        response = authenticated_client.get(
            reverse("resource-metadata"),
            {"filter[updated_at]": resource_1.updated_at.strftime("%Y-%m-%d")},
        )
        data = response.json()

        expected_services = {"ec2", "s3"}
        expected_regions = {"us-east-1", "eu-west-1"}
        expected_resource_types = {"prowler-test"}
        expected_groups = {"compute", "storage"}

        assert data["data"]["type"] == "resources-metadata"
        assert data["data"]["id"] is None
        assert set(data["data"]["attributes"]["services"]) == expected_services
        assert set(data["data"]["attributes"]["regions"]) == expected_regions
        assert set(data["data"]["attributes"]["types"]) == expected_resource_types
        assert set(data["data"]["attributes"]["groups"]) == expected_groups

    def test_resources_metadata_resource_filter_retrieve(
        self, authenticated_client, resources_fixture, backfill_scan_metadata_fixture
    ):
        resource_1, *_ = resources_fixture
        response = authenticated_client.get(
            reverse("resource-metadata"),
            {
                "filter[region]": "eu-west-1",
                "filter[updated_at]": resource_1.updated_at.strftime("%Y-%m-%d"),
            },
        )
        data = response.json()

        expected_services = {"s3"}
        expected_regions = {"eu-west-1"}
        expected_resource_types = {"prowler-test"}

        assert data["data"]["type"] == "resources-metadata"
        assert data["data"]["id"] is None
        assert set(data["data"]["attributes"]["services"]) == expected_services
        assert set(data["data"]["attributes"]["regions"]) == expected_regions
        assert set(data["data"]["attributes"]["types"]) == expected_resource_types

    def test_resources_metadata_future_date(self, authenticated_client):
        response = authenticated_client.get(
            reverse("resource-metadata"),
            {"filter[updated_at]": "2048-01-01"},
        )
        data = response.json()
        assert data["data"]["type"] == "resources-metadata"
        assert data["data"]["id"] is None
        assert data["data"]["attributes"]["services"] == []
        assert data["data"]["attributes"]["regions"] == []
        assert data["data"]["attributes"]["types"] == []
        assert data["data"]["attributes"]["groups"] == []

    def test_resources_metadata_invalid_date(self, authenticated_client):
        response = authenticated_client.get(
            reverse("resource-metadata"),
            {"filter[updated_at]": "2048-01-011"},
        )
        assert response.json() == {
            "errors": [
                {
                    "detail": "Enter a valid date.",
                    "status": "400",
                    "source": {"pointer": "/data/attributes/updated_at"},
                    "code": "invalid",
                }
            ]
        }

    def test_resources_latest(self, authenticated_client, latest_scan_resource):
        response = authenticated_client.get(
            reverse("resource-latest"),
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert (
            response.json()["data"][0]["attributes"]["uid"] == latest_scan_resource.uid
        )

    def test_resources_metadata_latest(
        self, authenticated_client, latest_scan_resource
    ):
        response = authenticated_client.get(
            reverse("resource-metadata_latest"),
        )
        assert response.status_code == status.HTTP_200_OK
        attributes = response.json()["data"]["attributes"]

        assert attributes["services"] == [latest_scan_resource.service]
        assert attributes["regions"] == [latest_scan_resource.region]
        assert attributes["types"] == [latest_scan_resource.type]
        assert "groups" in attributes

    def test_resources_latest_filter_by_provider_id(
        self, authenticated_client, latest_scan_resource
    ):
        """Test that provider_id filter works on latest resources endpoint."""
        provider = latest_scan_resource.provider
        response = authenticated_client.get(
            reverse("resource-latest"),
            {"filter[provider_id]": str(provider.id)},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert (
            response.json()["data"][0]["attributes"]["uid"] == latest_scan_resource.uid
        )

    def test_resources_latest_filter_by_provider_id_in(
        self, authenticated_client, latest_scan_resource
    ):
        """Test that provider_id__in filter works on latest resources endpoint."""
        provider = latest_scan_resource.provider
        response = authenticated_client.get(
            reverse("resource-latest"),
            {"filter[provider_id__in]": str(provider.id)},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert (
            response.json()["data"][0]["attributes"]["uid"] == latest_scan_resource.uid
        )

    def test_resources_latest_filter_by_provider_id_in_multiple(
        self, authenticated_client, providers_fixture
    ):
        """Test that provider_id__in filter works with multiple provider IDs."""
        provider1, provider2 = providers_fixture[0], providers_fixture[1]
        tenant_id = str(provider1.tenant_id)

        # Create completed scans for both providers
        Scan.objects.create(
            name="scan for provider 1",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant_id=tenant_id,
        )
        Scan.objects.create(
            name="scan for provider 2",
            provider=provider2,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant_id=tenant_id,
        )

        # Create resources for each provider
        resource1 = Resource.objects.create(
            tenant_id=tenant_id,
            provider=provider1,
            uid="resource_provider_1",
            name="Resource Provider 1",
            region="us-east-1",
            service="ec2",
            type="instance",
        )
        Resource.objects.create(
            tenant_id=tenant_id,
            provider=provider2,
            uid="resource_provider_2",
            name="Resource Provider 2",
            region="us-west-2",
            service="s3",
            type="bucket",
        )

        # Test filtering by both providers
        response = authenticated_client.get(
            reverse("resource-latest"),
            {"filter[provider_id__in]": f"{provider1.id},{provider2.id}"},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

        # Test filtering by single provider returns only that provider's resource
        response = authenticated_client.get(
            reverse("resource-latest"),
            {"filter[provider_id__in]": str(provider1.id)},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["uid"] == resource1.uid

    def test_resources_latest_filter_by_provider_id_no_match(
        self, authenticated_client, latest_scan_resource
    ):
        """Test that provider_id filter returns empty when no match."""
        non_existent_id = str(uuid4())
        response = authenticated_client.get(
            reverse("resource-latest"),
            {"filter[provider_id]": non_existent_id},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    # Events endpoint tests
    def test_events_non_aws_provider(self, authenticated_client, providers_fixture):
        """Test events endpoint rejects non-AWS providers."""
        from api.models import Resource

        azure_provider = providers_fixture[4]  # Azure provider from fixture

        resource = Resource.objects.create(
            uid="test-resource-id",
            name="Test Resource",
            type="test-type",
            region="us-east-1",
            service="test-service",
            provider=azure_provider,
            tenant_id=azure_provider.tenant_id,
        )

        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id})
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Verify JSON:API error structure
        error = response.json()["errors"][0]
        assert error["code"] == "invalid_provider"
        assert error["status"] == "400"  # Must be string per JSON:API spec
        assert error["source"]["pointer"] == "/data/attributes/provider"
        assert "AWS" in error["detail"]

    @pytest.mark.parametrize(
        "lookback_days,expected_status,expected_code,expected_detail_contains",
        [
            ("abc", status.HTTP_400_BAD_REQUEST, "invalid", "valid integer"),
            ("0", status.HTTP_400_BAD_REQUEST, "out_of_range", "between 1 and 90"),
            ("91", status.HTTP_400_BAD_REQUEST, "out_of_range", "between 1 and 90"),
            ("-5", status.HTTP_400_BAD_REQUEST, "out_of_range", "between 1 and 90"),
        ],
    )
    def test_events_invalid_lookback_days(
        self,
        authenticated_client,
        providers_fixture,
        lookback_days,
        expected_status,
        expected_code,
        expected_detail_contains,
    ):
        """Test events endpoint validates lookback_days with JSON:API compliant errors."""
        from api.models import Resource

        aws_provider = providers_fixture[0]  # AWS provider from fixture

        resource = Resource.objects.create(
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-test",
            name="Test Instance",
            type="instance",
            region="us-east-1",
            service="ec2",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id}),
            {"lookback_days": lookback_days},
        )

        assert response.status_code == expected_status

        # Verify JSON:API error structure
        error = response.json()["errors"][0]
        assert error["code"] == expected_code
        assert error["status"] == "400"  # Must be string per JSON:API spec
        assert error["source"]["parameter"] == "lookback_days"
        assert expected_detail_contains in error["detail"]

    @pytest.mark.parametrize(
        "page_size,expected_status,expected_code,expected_detail_contains",
        [
            ("abc", status.HTTP_400_BAD_REQUEST, "invalid", "valid integer"),
            ("0", status.HTTP_400_BAD_REQUEST, "out_of_range", "between 1 and 50"),
            ("51", status.HTTP_400_BAD_REQUEST, "out_of_range", "between 1 and 50"),
            ("-1", status.HTTP_400_BAD_REQUEST, "out_of_range", "between 1 and 50"),
        ],
    )
    def test_events_invalid_page_size(
        self,
        authenticated_client,
        providers_fixture,
        page_size,
        expected_status,
        expected_code,
        expected_detail_contains,
    ):
        """Test events endpoint validates page[size] with JSON:API compliant errors."""
        from api.models import Resource

        aws_provider = providers_fixture[0]  # AWS provider from fixture

        resource = Resource.objects.create(
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-pagesize-test",
            name="Test Instance",
            type="instance",
            region="us-east-1",
            service="ec2",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id}),
            {"page[size]": page_size},
        )

        assert response.status_code == expected_status

        # Verify JSON:API error structure
        error = response.json()["errors"][0]
        assert error["code"] == expected_code
        assert error["status"] == "400"  # Must be string per JSON:API spec
        assert error["source"]["parameter"] == "page[size]"
        assert expected_detail_contains in error["detail"]

    @pytest.mark.parametrize(
        "invalid_params,expected_invalid_param",
        [
            ({"filter[service]": "ec2"}, "filter[service]"),
            ({"filter[region]": "us-east-1"}, "filter[region]"),
            ({"sort": "-name"}, "sort"),
            ({"unknown_param": "value"}, "unknown_param"),
            ({"filter[servic]": "ec2"}, "filter[servic]"),  # Typo in filter name
        ],
    )
    def test_events_invalid_query_parameter(
        self,
        authenticated_client,
        providers_fixture,
        invalid_params,
        expected_invalid_param,
    ):
        """Test events endpoint rejects unknown query parameters with JSON:API compliant errors."""
        from api.models import Resource

        aws_provider = providers_fixture[0]  # AWS provider from fixture

        resource = Resource.objects.create(
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-test",
            name="Test Instance",
            type="instance",
            region="us-east-1",
            service="ec2",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id}),
            invalid_params,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Verify JSON:API error structure
        errors = response.json()["errors"]
        assert len(errors) >= 1

        # Find the error for our expected invalid param
        error = next(
            (e for e in errors if e["source"]["parameter"] == expected_invalid_param),
            None,
        )
        assert (
            error is not None
        ), f"Expected error for parameter '{expected_invalid_param}'"
        assert error["code"] == "invalid"
        assert error["status"] == "400"  # Must be string per JSON:API spec
        assert expected_invalid_param in error["detail"]

    def test_events_multiple_invalid_query_parameters(
        self,
        authenticated_client,
        providers_fixture,
    ):
        """Test events endpoint returns error for first unknown parameter."""
        from api.models import Resource

        aws_provider = providers_fixture[0]

        resource = Resource.objects.create(
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-test",
            name="Test Instance",
            type="instance",
            region="us-east-1",
            service="ec2",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        # Send multiple invalid parameters - only first one triggers error
        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id}),
            {"filter[service]": "ec2", "sort": "-name", "unknown": "value"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Should have one error for the first invalid parameter encountered
        errors = response.json()["errors"]
        assert len(errors) == 1
        assert errors[0]["code"] == "invalid"
        assert errors[0]["status"] == "400"
        assert errors[0]["source"]["parameter"] in {
            "filter[service]",
            "sort",
            "unknown",
        }

    @patch("api.v1.views.initialize_prowler_provider")
    @patch("api.v1.views.CloudTrailTimeline")
    def test_events_success(
        self,
        mock_cloudtrail_timeline,
        mock_initialize_provider,
        authenticated_client,
        providers_fixture,
    ):
        """Test successful events retrieval."""
        from api.models import Resource

        aws_provider = providers_fixture[0]  # AWS provider from fixture

        # Create test resource
        resource = Resource.objects.create(
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-test123",
            name="Test EC2 Instance",
            type="instance",
            region="us-east-1",
            service="ec2",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        # Mock provider session
        mock_session = Mock()
        mock_provider = Mock()
        mock_provider._session.current_session = mock_session
        mock_initialize_provider.return_value = mock_provider

        # Mock CloudTrail timeline response - events need event_id for serializer
        mock_timeline_instance = Mock()
        mock_events = [
            {
                "event_id": "event-1-id",
                "event_time": "2024-01-15T10:30:00Z",
                "event_name": "RunInstances",
                "event_source": "ec2.amazonaws.com",
                "actor": "admin@example.com",
                "actor_type": "IAMUser",
                "source_ip_address": "203.0.113.1",
                "user_agent": "aws-cli/2.0.0",
            },
            {
                "event_id": "event-2-id",
                "event_time": "2024-01-16T14:20:00Z",
                "event_name": "StopInstances",
                "event_source": "ec2.amazonaws.com",
                "actor": "operator@example.com",
                "actor_type": "IAMUser",
            },
        ]
        mock_timeline_instance.get_resource_timeline.return_value = mock_events
        mock_cloudtrail_timeline.return_value = mock_timeline_instance

        # Make request with lookback_days parameter
        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id}),
            {"lookback_days": "30"},
        )

        # Assertions - response is wrapped by JSON:API renderer
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        events = response_data["data"]

        assert len(events) == 2

        # Verify JSON:API structure: type and id are present
        assert events[0]["type"] == "resource-events"
        assert events[0]["id"] == "event-1-id"
        assert events[1]["type"] == "resource-events"
        assert events[1]["id"] == "event-2-id"

        # Verify attributes
        assert events[0]["attributes"]["event_name"] == "RunInstances"
        assert events[0]["attributes"]["actor"] == "admin@example.com"
        assert events[1]["attributes"]["event_name"] == "StopInstances"

        # Verify CloudTrail was called with correct parameters
        mock_cloudtrail_timeline.assert_called_once_with(
            session=mock_session,
            lookback_days=30,
            max_results=50,  # Default page size
            write_events_only=True,  # Default: exclude read events
        )
        mock_timeline_instance.get_resource_timeline.assert_called_once_with(
            region=resource.region,
            resource_uid=resource.uid,
        )

    @patch("api.v1.views.initialize_prowler_provider")
    @patch("api.v1.views.CloudTrailTimeline")
    def test_events_default_lookback_days(
        self,
        mock_cloudtrail_timeline,
        mock_initialize_provider,
        authenticated_client,
        providers_fixture,
    ):
        """Test events uses default lookback_days (90) when not provided."""
        from api.models import Resource

        aws_provider = providers_fixture[0]  # AWS provider from fixture

        resource = Resource.objects.create(
            uid="arn:aws:s3:::test-bucket",
            name="Test Bucket",
            type="bucket",
            region="us-east-1",
            service="s3",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        # Mock provider session
        mock_session = Mock()
        mock_provider = Mock()
        mock_provider._session.current_session = mock_session
        mock_initialize_provider.return_value = mock_provider

        # Mock CloudTrail timeline response
        mock_timeline_instance = Mock()
        mock_timeline_instance.get_resource_timeline.return_value = []
        mock_cloudtrail_timeline.return_value = mock_timeline_instance

        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id})
        )

        assert response.status_code == status.HTTP_200_OK

        # Verify default lookback_days (90) was used
        mock_cloudtrail_timeline.assert_called_once_with(
            session=mock_session,
            lookback_days=90,  # Default
            max_results=50,
            write_events_only=True,
        )

    @patch("api.v1.views.initialize_prowler_provider")
    def test_events_no_credentials_error(
        self, mock_initialize_provider, authenticated_client, providers_fixture
    ):
        """Test events handles missing credentials errors."""
        from api.models import Resource

        aws_provider = providers_fixture[0]  # AWS provider from fixture

        resource = Resource.objects.create(
            uid="arn:aws:rds:us-west-2:123456789012:db:test-db",
            name="Test Database",
            type="db-instance",
            region="us-west-2",
            service="rds",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        mock_initialize_provider.side_effect = NoCredentialsError()

        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id})
        )

        # 502 because this is an upstream auth failure, not API auth failure
        assert response.status_code == status.HTTP_502_BAD_GATEWAY

        # Verify JSON:API error structure
        error = response.json()["errors"][0]
        assert error["code"] == "upstream_auth_failed"
        assert error["status"] == "502"  # Must be string per JSON:API spec
        assert "detail" in error

    @patch("api.v1.views.initialize_prowler_provider")
    @patch("api.v1.views.CloudTrailTimeline")
    def test_events_access_denied_error(
        self,
        mock_cloudtrail_timeline,
        mock_initialize_provider,
        authenticated_client,
        providers_fixture,
    ):
        """Test events handles AccessDenied errors from AWS."""
        from api.models import Resource

        aws_provider = providers_fixture[0]  # AWS provider from fixture

        resource = Resource.objects.create(
            uid="arn:aws:lambda:eu-west-1:123456789012:function:test-func",
            name="Test Function",
            type="function",
            region="eu-west-1",
            service="lambda",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        # Mock provider
        mock_session = Mock()
        mock_provider = Mock()
        mock_provider._session.current_session = mock_session
        mock_initialize_provider.return_value = mock_provider

        # Mock ClientError with AccessDenied
        mock_timeline_instance = Mock()
        mock_timeline_instance.get_resource_timeline.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "LookupEvents",
        )
        mock_cloudtrail_timeline.return_value = mock_timeline_instance

        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id})
        )

        # AccessDenied returns 502 (upstream error, not user's fault)
        assert response.status_code == status.HTTP_502_BAD_GATEWAY

        # Verify JSON:API error structure
        error = response.json()["errors"][0]
        assert error["code"] == "upstream_access_denied"
        assert error["status"] == "502"  # Must be string per JSON:API spec
        assert "detail" in error

    @patch("api.v1.views.initialize_prowler_provider")
    @patch("api.v1.views.CloudTrailTimeline")
    def test_events_service_unavailable_error(
        self,
        mock_cloudtrail_timeline,
        mock_initialize_provider,
        authenticated_client,
        providers_fixture,
    ):
        """Test events handles generic AWS API errors as 503."""
        from api.models import Resource

        aws_provider = providers_fixture[0]  # AWS provider from fixture

        resource = Resource.objects.create(
            uid="arn:aws:lambda:eu-west-1:123456789012:function:test-func2",
            name="Test Function 2",
            type="function",
            region="eu-west-1",
            service="lambda",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        # Mock provider
        mock_session = Mock()
        mock_provider = Mock()
        mock_provider._session.current_session = mock_session
        mock_initialize_provider.return_value = mock_provider

        # Mock ClientError with non-AccessDenied error
        mock_timeline_instance = Mock()
        mock_timeline_instance.get_resource_timeline.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable", "Message": "Service unavailable"}},
            "LookupEvents",
        )
        mock_cloudtrail_timeline.return_value = mock_timeline_instance

        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id})
        )

        # Non-AccessDenied errors return 503
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

        # Verify JSON:API error structure
        error = response.json()["errors"][0]
        assert error["code"] == "service_unavailable"
        assert error["status"] == "503"  # Must be string per JSON:API spec
        assert "detail" in error

    @patch("api.v1.views.initialize_prowler_provider")
    def test_events_assume_role_access_denied(
        self,
        mock_initialize_provider,
        authenticated_client,
        providers_fixture,
    ):
        """Test events handles AWSAssumeRoleError during provider init.

        This tests the scenario from CLOUD-API-3HJ where the API task role
        cannot assume the customer's ProwlerScan role due to IAM permissions.
        The error happens during initialize_prowler_provider, which wraps
        the ClientError in AWSAssumeRoleError.
        """
        from api.models import Resource
        from prowler.providers.aws.exceptions.exceptions import AWSAssumeRoleError

        aws_provider = providers_fixture[0]  # AWS provider from fixture

        resource = Resource.objects.create(
            uid="arn:aws:lambda:eu-west-1:123456789012:function:assume-role-test",
            name="AssumeRole Test Function",
            type="function",
            region="eu-west-1",
            service="lambda",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        # Mock initialize_prowler_provider raising AWSAssumeRoleError
        # (this is what aws_provider.py actually raises when AssumeRole fails)
        original_error = ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": (
                        "User: arn:aws:sts::123456789012:assumed-role/api-task-role/xxx "
                        "is not authorized to perform: sts:AssumeRole on resource: "
                        "arn:aws:iam::123456789012:role/ProwlerScan"
                    ),
                }
            },
            "AssumeRole",
        )
        mock_initialize_provider.side_effect = AWSAssumeRoleError(
            original_exception=original_error,
            file="aws_provider.py",
        )

        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id})
        )

        # AWSAssumeRoleError returns 502 (upstream auth failure)
        assert response.status_code == status.HTTP_502_BAD_GATEWAY

        # Verify JSON:API error structure
        error = response.json()["errors"][0]
        assert error["code"] == "upstream_access_denied"
        assert error["status"] == "502"
        assert "detail" in error

    def test_events_unauthenticated_returns_401(self, providers_fixture):
        """Test events endpoint returns 401 when no credentials are provided.

        This ensures the endpoint follows API conventions where missing authentication
        returns 401 Unauthorized, not 404 Not Found.
        """
        from rest_framework.test import APIClient

        from api.models import Resource

        aws_provider = providers_fixture[0]  # AWS provider from fixture

        resource = Resource.objects.create(
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-unauth-test",
            name="Test Instance",
            type="instance",
            region="us-east-1",
            service="ec2",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        # Use unauthenticated client (no JWT token)
        unauthenticated_client = APIClient()

        response = unauthenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id})
        )

        # Must return 401 Unauthorized, not 404 Not Found
        assert response.status_code == status.HTTP_401_UNAUTHORIZED, (
            f"Expected 401 Unauthorized but got {response.status_code}. "
            "Unauthenticated requests should return 401, not 404."
        )

    def test_events_cross_tenant_returns_404(
        self, authenticated_client, tenants_fixture
    ):
        """Test events endpoint returns 404 for resources in other tenants (RLS).

        Users cannot access resources belonging to other tenants due to
        Row-Level Security. The resource should appear to not exist.
        """
        from api.models import Provider, Resource

        # tenant3 (tenants_fixture[2]) has no membership for the test user
        isolated_tenant = tenants_fixture[2]

        # Create provider in the isolated tenant
        other_tenant_provider = Provider.objects.create(
            provider="aws",
            uid="999999999999",
            alias="other_tenant_aws",
            tenant_id=isolated_tenant.id,
        )

        # Create resource in the OTHER tenant (not the authenticated user's tenant)
        resource = Resource.objects.create(
            uid="arn:aws:ec2:us-east-1:999999999999:instance/i-other-tenant",
            name="Other Tenant Resource",
            type="instance",
            region="us-east-1",
            service="ec2",
            provider=other_tenant_provider,
            tenant_id=isolated_tenant.id,
        )

        response = authenticated_client.get(
            reverse("resource-events", kwargs={"pk": resource.id})
        )

        # RLS hides resources from other tenants - should appear as not found
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_events_expired_token_returns_401(self, providers_fixture, tenants_fixture):
        """Test events endpoint returns 401 when JWT token is expired.

        Expired tokens should return 401 Unauthorized, not 404 Not Found.
        This ensures authentication errors are properly distinguished from
        resource not found errors.
        """
        from rest_framework.test import APIClient

        from api.models import Resource

        aws_provider = providers_fixture[0]

        resource = Resource.objects.create(
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-expired-test",
            name="Test Instance",
            type="instance",
            region="us-east-1",
            service="ec2",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        # Create an expired JWT token
        tenant = tenants_fixture[0]
        expired_payload = {
            "token_type": "access",
            "exp": datetime.now(timezone.utc)
            - timedelta(hours=1),  # Expired 1 hour ago
            "iat": datetime.now(timezone.utc) - timedelta(hours=2),
            "jti": str(uuid4()),
            "user_id": str(uuid4()),
            "tenant_id": str(tenant.id),
        }
        expired_token = jwt.encode(
            expired_payload, settings.SECRET_KEY, algorithm="HS256"
        )

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {expired_token}")

        response = client.get(reverse("resource-events", kwargs={"pk": resource.id}))

        # Must return 401 Unauthorized, not 404 Not Found
        assert response.status_code == status.HTTP_401_UNAUTHORIZED, (
            f"Expected 401 Unauthorized but got {response.status_code}. "
            "Expired tokens should return 401, not 404."
        )

    def test_events_invalid_token_returns_401(self, providers_fixture):
        """Test events endpoint returns 401 when JWT token is completely invalid.

        Malformed or invalid tokens should return 401 Unauthorized, not 404 Not Found.
        """
        from rest_framework.test import APIClient

        from api.models import Resource

        aws_provider = providers_fixture[0]

        resource = Resource.objects.create(
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-invalid-test",
            name="Test Instance",
            type="instance",
            region="us-east-1",
            service="ec2",
            provider=aws_provider,
            tenant_id=aws_provider.tenant_id,
        )

        client = APIClient()

        # Test with completely malformed token
        client.credentials(HTTP_AUTHORIZATION="Bearer not.a.valid.jwt.token")
        response = client.get(reverse("resource-events", kwargs={"pk": resource.id}))
        assert (
            response.status_code == status.HTTP_401_UNAUTHORIZED
        ), f"Expected 401 for malformed token but got {response.status_code}"

        # Test with empty bearer token
        client.credentials(HTTP_AUTHORIZATION="Bearer ")
        response = client.get(reverse("resource-events", kwargs={"pk": resource.id}))
        assert (
            response.status_code == status.HTTP_401_UNAUTHORIZED
        ), f"Expected 401 for empty bearer token but got {response.status_code}"


@pytest.mark.django_db
class TestFindingViewSet:
    def test_findings_list_none(self, authenticated_client):
        response = authenticated_client.get(
            reverse("finding-list"), {"filter[inserted_at]": TODAY}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    def test_findings_list_no_date_filter(self, authenticated_client):
        response = authenticated_client.get(reverse("finding-list"))
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "required"

    def test_findings_date_range_too_large(self, authenticated_client):
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[inserted_at.lte]": today_after_n_days(
                    -(settings.FINDINGS_MAX_DAYS_IN_RANGE + 1)
                ),
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"

    def test_findings_list(self, authenticated_client, findings_fixture):
        response = authenticated_client.get(
            reverse("finding-list"), {"filter[inserted_at]": TODAY}
        )
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
            ("resources,scan.provider", ["resources", "scans", "providers"]),
        ],
    )
    def test_findings_list_include(
        self, include_values, expected_resources, authenticated_client, findings_fixture
    ):
        response = authenticated_client.get(
            reverse("finding-list"),
            {"include": include_values, "filter[inserted_at]": TODAY},
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
                ("inserted_at.gte", today_after_n_days(-1), 2),
                (
                    "inserted_at.lte",
                    today_after_n_days(1),
                    2,
                ),
                ("updated_at.lte", today_after_n_days(-1), 0),
                ("resource_type.icontains", "prowler", 2),
                # full text search on finding
                ("search", "dev-qa", 1),
                ("search", "orange juice", 1),
                # full text search on resource
                ("search", "ec2", 1),
                # full text search on finding tags (disabled for now)
                # ("search", "value2", 2),
                # Temporary disabled until we implement tag filtering in the UI
                # ("resource_tag_key", "key", 2),
                # ("resource_tag_key__in", "key,key2", 2),
                # ("resource_tag_key__icontains", "key", 2),
                # ("resource_tag_value", "value", 2),
                # ("resource_tag_value__in", "value,value2", 2),
                # ("resource_tag_value__icontains", "value", 2),
                # ("resource_tags", "key:value", 2),
                # ("resource_tags", "not:exists", 0),
                # ("resource_tags", "not:exists,key:value", 2),
                ("muted", True, 1),
                ("muted", False, 1),
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
        filters = {f"filter[{filter_name}]": filter_value}
        if "inserted_at" not in filter_name:
            filters["filter[inserted_at]"] = TODAY

        response = authenticated_client.get(
            reverse("finding-list"),
            filters,
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    def test_finding_filter_by_scan_id(self, authenticated_client, findings_fixture):
        response = authenticated_client.get(
            reverse("finding-list"),
            {"filter[scan]": findings_fixture[0].scan.id},
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
                "filter[inserted_at]": TODAY,
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
                ],
                "filter[inserted_at]": TODAY,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_finding_filter_by_provider_id_alias(
        self, authenticated_client, findings_fixture
    ):
        """Test that provider_id filter alias works identically to provider filter."""
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[provider_id]": findings_fixture[0].scan.provider.id,
                "filter[inserted_at]": TODAY,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_finding_filter_by_provider_id_in_alias(
        self, authenticated_client, findings_fixture
    ):
        """Test that provider_id__in filter alias works identically to provider__in filter."""
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[provider_id__in]": [
                    findings_fixture[0].scan.provider.id,
                    findings_fixture[1].scan.provider.id,
                ],
                "filter[inserted_at]": TODAY,
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
            reverse("finding-list"), {"sort": sort_field, "filter[inserted_at]": TODAY}
        )
        assert response.status_code == status.HTTP_200_OK

    def test_findings_sort_invalid(self, authenticated_client):
        response = authenticated_client.get(
            reverse("finding-list"), {"sort": "invalid", "filter[inserted_at]": TODAY}
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

    def test_findings_metadata_retrieve(
        self, authenticated_client, findings_fixture, backfill_scan_metadata_fixture
    ):
        finding_1, *_ = findings_fixture
        response = authenticated_client.get(
            reverse("finding-metadata"),
            {"filter[inserted_at]": finding_1.updated_at.strftime("%Y-%m-%d")},
        )
        data = response.json()

        expected_services = {"ec2", "s3"}
        expected_regions = {"eu-west-1", "us-east-1"}
        # Temporarily disabled until we implement tag filtering in the UI
        # expected_tags = {"key": ["value"], "key2": ["value2"]}
        expected_resource_types = {"prowler-test"}

        assert data["data"]["type"] == "findings-metadata"
        assert data["data"]["id"] is None
        assert set(data["data"]["attributes"]["services"]) == expected_services
        assert set(data["data"]["attributes"]["regions"]) == expected_regions
        assert (
            set(data["data"]["attributes"]["resource_types"]) == expected_resource_types
        )
        # assert data["data"]["attributes"]["tags"] == expected_tags

    def test_findings_metadata_resource_filter_retrieve(
        self, authenticated_client, findings_fixture, backfill_scan_metadata_fixture
    ):
        finding_1, *_ = findings_fixture
        response = authenticated_client.get(
            reverse("finding-metadata"),
            {
                "filter[region]": "eu-west-1",
                "filter[inserted_at]": finding_1.inserted_at.strftime("%Y-%m-%d"),
            },
        )
        data = response.json()

        expected_services = {"s3"}
        expected_regions = {"eu-west-1"}
        # Temporary disabled until we implement tag filtering in the UI
        # expected_tags = {"key": ["value"], "key2": ["value2"]}
        expected_resource_types = {"prowler-test"}

        assert data["data"]["type"] == "findings-metadata"
        assert data["data"]["id"] is None
        assert set(data["data"]["attributes"]["services"]) == expected_services
        assert set(data["data"]["attributes"]["regions"]) == expected_regions
        assert (
            set(data["data"]["attributes"]["resource_types"]) == expected_resource_types
        )
        # assert data["data"]["attributes"]["tags"] == expected_tags

    def test_findings_metadata_future_date(self, authenticated_client):
        response = authenticated_client.get(
            reverse("finding-metadata"),
            {"filter[inserted_at]": "2048-01-01"},
        )
        data = response.json()
        assert data["data"]["type"] == "findings-metadata"
        assert data["data"]["id"] is None
        assert data["data"]["attributes"]["services"] == []
        assert data["data"]["attributes"]["regions"] == []
        # Temporary disabled until we implement tag filtering in the UI
        # assert data["data"]["attributes"]["tags"] == {}
        assert data["data"]["attributes"]["resource_types"] == []

    def test_findings_metadata_invalid_date(self, authenticated_client):
        response = authenticated_client.get(
            reverse("finding-metadata"),
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

    def test_findings_metadata_backfill(
        self, authenticated_client, scans_fixture, findings_fixture
    ):
        scan = scans_fixture[0]
        scan.unique_resource_count = 1
        scan.save()

        with patch(
            "api.v1.views.backfill_scan_resource_summaries_task.apply_async"
        ) as mock_backfill_task:
            response = authenticated_client.get(
                reverse("finding-metadata"),
                {"filter[scan]": str(scan.id)},
            )
        assert response.status_code == status.HTTP_200_OK
        mock_backfill_task.assert_called()

    def test_findings_metadata_backfill_no_resources(
        self, authenticated_client, scans_fixture
    ):
        scan_id = str(scans_fixture[0].id)
        with patch(
            "api.v1.views.backfill_scan_resource_summaries_task.apply_async"
        ) as mock_backfill_task:
            response = authenticated_client.get(
                reverse("finding-metadata"),
                {"filter[scan]": scan_id},
            )
        assert response.status_code == status.HTTP_200_OK
        mock_backfill_task.assert_not_called()

    def test_findings_metadata_latest_backfill(
        self, authenticated_client, scans_fixture, findings_fixture
    ):
        scan = scans_fixture[0]
        scan.unique_resource_count = 1
        scan.save()

        with patch(
            "api.v1.views.backfill_scan_resource_summaries_task.apply_async"
        ) as mock_backfill_task:
            response = authenticated_client.get(reverse("finding-metadata_latest"))
        assert response.status_code == status.HTTP_200_OK
        mock_backfill_task.assert_called()

    def test_findings_metadata_latest_backfill_no_resources(
        self, authenticated_client, scans_fixture
    ):
        with patch(
            "api.v1.views.backfill_scan_resource_summaries_task.apply_async"
        ) as mock_backfill_task:
            response = authenticated_client.get(reverse("finding-metadata_latest"))
        assert response.status_code == status.HTTP_200_OK
        mock_backfill_task.assert_not_called()

    def test_findings_latest(self, authenticated_client, latest_scan_finding):
        response = authenticated_client.get(
            reverse("finding-latest"),
        )
        assert response.status_code == status.HTTP_200_OK
        # The latest scan only has one finding, in comparison with `GET /findings`
        assert len(response.json()["data"]) == 1
        assert (
            response.json()["data"][0]["attributes"]["status"]
            == latest_scan_finding.status
        )

    def test_findings_latest_filter_by_provider_id_alias(
        self, authenticated_client, latest_scan_finding
    ):
        """Test that provider_id filter alias works on latest findings endpoint."""
        response = authenticated_client.get(
            reverse("finding-latest"),
            {"filter[provider_id]": latest_scan_finding.scan.provider.id},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1

    def test_findings_latest_filter_by_provider_id_in_alias(
        self, authenticated_client, latest_scan_finding
    ):
        """Test that provider_id__in filter alias works on latest findings endpoint."""
        response = authenticated_client.get(
            reverse("finding-latest"),
            {"filter[provider_id__in]": str(latest_scan_finding.scan.provider.id)},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1

    def test_findings_metadata_latest(self, authenticated_client, latest_scan_finding):
        response = authenticated_client.get(
            reverse("finding-metadata_latest"),
        )
        assert response.status_code == status.HTTP_200_OK
        attributes = response.json()["data"]["attributes"]

        assert attributes["services"] == latest_scan_finding.resource_services
        assert attributes["regions"] == latest_scan_finding.resource_regions
        assert attributes["resource_types"] == latest_scan_finding.resource_types

    def test_findings_metadata_categories(
        self, authenticated_client, findings_with_categories
    ):
        finding = findings_with_categories
        response = authenticated_client.get(
            reverse("finding-metadata"),
            {"filter[inserted_at]": finding.inserted_at.strftime("%Y-%m-%d")},
        )
        assert response.status_code == status.HTTP_200_OK
        attributes = response.json()["data"]["attributes"]
        assert set(attributes["categories"]) == {"gen-ai", "security"}

    def test_findings_metadata_latest_categories(
        self, authenticated_client, latest_scan_finding_with_categories
    ):
        response = authenticated_client.get(
            reverse("finding-metadata_latest"),
        )
        assert response.status_code == status.HTTP_200_OK
        attributes = response.json()["data"]["attributes"]
        assert set(attributes["categories"]) == {"gen-ai", "iam"}

    def test_findings_metadata_latest_groups(
        self, authenticated_client, latest_scan_finding_with_categories
    ):
        response = authenticated_client.get(
            reverse("finding-metadata_latest"),
        )
        assert response.status_code == status.HTTP_200_OK
        attributes = response.json()["data"]["attributes"]
        assert "groups" in attributes
        assert "ai_ml" in attributes["groups"]

    def test_findings_filter_by_category(
        self, authenticated_client, findings_with_categories
    ):
        finding = findings_with_categories
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[category]": "gen-ai",
                "filter[inserted_at]": finding.inserted_at.strftime("%Y-%m-%d"),
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert set(response.json()["data"][0]["attributes"]["categories"]) == {
            "gen-ai",
            "security",
        }

    def test_findings_filter_by_category_in(
        self, authenticated_client, findings_with_multiple_categories
    ):
        finding1, _ = findings_with_multiple_categories
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[category__in]": "gen-ai,iam",
                "filter[inserted_at]": finding1.inserted_at.strftime("%Y-%m-%d"),
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_findings_filter_by_category_no_match(
        self, authenticated_client, findings_with_categories
    ):
        finding = findings_with_categories
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[category]": "nonexistent",
                "filter[inserted_at]": finding.inserted_at.strftime("%Y-%m-%d"),
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    def test_findings_filter_by_resource_groups(
        self, authenticated_client, findings_with_group
    ):
        finding = findings_with_group
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[resource_groups]": "storage",
                "filter[inserted_at]": finding.inserted_at.strftime("%Y-%m-%d"),
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["resource_groups"] == "storage"

    def test_findings_filter_by_resource_groups_in(
        self, authenticated_client, findings_with_multiple_groups
    ):
        finding1, _ = findings_with_multiple_groups
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[resource_groups__in]": "storage,security",
                "filter[inserted_at]": finding1.inserted_at.strftime("%Y-%m-%d"),
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_findings_filter_by_resource_groups_no_match(
        self, authenticated_client, findings_with_group
    ):
        finding = findings_with_group
        response = authenticated_client.get(
            reverse("finding-list"),
            {
                "filter[resource_groups]": "nonexistent",
                "filter[inserted_at]": finding.inserted_at.strftime("%Y-%m-%d"),
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0


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

    def test_invitations_create_valid(
        self, authenticated_client, create_test_user, roles_fixture
    ):
        user = create_test_user
        data = {
            "data": {
                "type": "invitations",
                "attributes": {
                    "email": "any_email@prowler.com",
                    "expires_at": self.TOMORROW_ISO,
                },
                "relationships": {
                    "roles": {
                        "data": [{"type": "roles", "id": str(roles_fixture[0].id)}]
                    }
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
        assert response.json()["errors"][1]["code"] == "required"
        assert (
            response.json()["errors"][1]["source"]["pointer"]
            == "/data/relationships/roles"
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
        assert response.json()["errors"][1]["code"] == "required"
        assert (
            response.json()["errors"][1]["source"]["pointer"]
            == "/data/relationships/roles"
        )

    def test_invitations_partial_update_valid(
        self, authenticated_client, invitations_fixture, roles_fixture
    ):
        invitation, *_ = invitations_fixture
        role1, role2, *_ = roles_fixture
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
                "relationships": {
                    "roles": {
                        "data": [
                            {"type": "roles", "id": str(role1.id)},
                            {"type": "roles", "id": str(role2.id)},
                        ]
                    },
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
        assert invitation.roles.count() == 2

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

    def test_invitations_accept_invitation_new_user(self, client, invitations_fixture):
        invitation, *_ = invitations_fixture

        data = {
            "name": "test",
            "password": "Newpassword123@",
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

    def test_invitations_accept_invitation_invalid_token(self, authenticated_client):
        data = {
            "invitation_token": "invalid_token",
        }

        response = authenticated_client.post(
            reverse("invitation-accept"), data=data, format="json"
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.json()["errors"][0]["code"] == "not_found"

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
            "password": "Newpassword123@",
            "email": new_email,
        }

        response = client.post(
            reverse("user-list") + f"?invitation_token={invitation.token}",
            data=data,
            format="json",
        )

        assert response.status_code == status.HTTP_410_GONE

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
class TestRoleViewSet:
    def test_role_list(self, authenticated_client, roles_fixture):
        response = authenticated_client.get(reverse("role-list"))
        assert response.status_code == status.HTTP_200_OK
        assert (
            len(response.json()["data"]) == len(roles_fixture) + 1
        )  # 1 default admin role

    def test_role_retrieve(self, authenticated_client, roles_fixture):
        role = roles_fixture[0]
        response = authenticated_client.get(
            reverse("role-detail", kwargs={"pk": role.id})
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert data["id"] == str(role.id)
        assert data["attributes"]["name"] == role.name

    @pytest.mark.parametrize(
        ("permission_state", "index"),
        [("limited", 0), ("unlimited", 2), ("none", 3)],
    )
    def test_role_retrieve_permission_state(
        self, authenticated_client, roles_fixture, permission_state, index
    ):
        role = roles_fixture[index]
        response = authenticated_client.get(
            reverse("role-detail", kwargs={"pk": role.id}),
            {"filter[permission_state]": permission_state},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert data["id"] == str(role.id)
        assert data["attributes"]["name"] == role.name
        assert data["attributes"]["permission_state"] == permission_state

    def test_role_create(self, authenticated_client):
        data = {
            "data": {
                "type": "roles",
                "attributes": {
                    "name": "Test Role",
                    "manage_users": "false",
                    "manage_account": "false",
                    "manage_providers": "true",
                    "manage_scans": "true",
                    "unlimited_visibility": "true",
                },
                "relationships": {"provider_groups": {"data": []}},
            }
        }
        response = authenticated_client.post(
            reverse("role-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()["data"]
        assert response_data["attributes"]["name"] == "Test Role"
        assert Role.objects.filter(name="Test Role").exists()

    def test_role_provider_groups_create(
        self, authenticated_client, provider_groups_fixture
    ):
        data = {
            "data": {
                "type": "roles",
                "attributes": {
                    "name": "Test Role",
                    "manage_users": "false",
                    "manage_account": "false",
                    "manage_providers": "true",
                    "manage_scans": "true",
                    "unlimited_visibility": "true",
                },
                "relationships": {
                    "provider_groups": {
                        "data": [
                            {"type": "provider-groups", "id": str(provider_group.id)}
                            for provider_group in provider_groups_fixture[:2]
                        ]
                    }
                },
            }
        }
        response = authenticated_client.post(
            reverse("role-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()["data"]
        assert response_data["attributes"]["name"] == "Test Role"
        assert Role.objects.filter(name="Test Role").exists()
        relationships = (
            Role.objects.filter(name="Test Role").first().provider_groups.all()
        )
        assert relationships.count() == 2
        for relationship in relationships:
            assert relationship.id in [pg.id for pg in provider_groups_fixture[:2]]

    def test_role_create_invalid(self, authenticated_client):
        data = {
            "data": {
                "type": "roles",
                "attributes": {
                    # Name is missing
                },
            }
        }
        response = authenticated_client.post(
            reverse("role-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert errors[0]["source"]["pointer"] == "/data/attributes/name"

    def test_admin_role_partial_update(self, authenticated_client, admin_role_fixture):
        role = admin_role_fixture
        data = {
            "data": {
                "id": str(role.id),
                "type": "roles",
                "attributes": {
                    "name": "Updated Role",
                },
            }
        }
        response = authenticated_client.patch(
            reverse("role-detail", kwargs={"pk": role.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        role.refresh_from_db()
        assert role.name != "Updated Role"

    def test_role_partial_update(self, authenticated_client, roles_fixture):
        role = roles_fixture[1]
        data = {
            "data": {
                "id": str(role.id),
                "type": "roles",
                "attributes": {
                    "name": "Updated Role",
                },
            }
        }
        response = authenticated_client.patch(
            reverse("role-detail", kwargs={"pk": role.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        role.refresh_from_db()
        assert role.name == "Updated Role"

    def test_role_partial_update_invalid(self, authenticated_client, roles_fixture):
        role = roles_fixture[2]
        data = {
            "data": {
                "id": str(role.id),
                "type": "roles",
                "attributes": {
                    "name": "",  # Invalid name
                },
            }
        }
        response = authenticated_client.patch(
            reverse("role-detail", kwargs={"pk": role.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert errors[0]["source"]["pointer"] == "/data/attributes/name"

    def test_role_destroy_admin(self, authenticated_client, admin_role_fixture):
        role = admin_role_fixture
        response = authenticated_client.delete(
            reverse("role-detail", kwargs={"pk": role.id})
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert Role.objects.filter(id=role.id).exists()

    def test_role_destroy(self, authenticated_client, roles_fixture):
        role = roles_fixture[2]
        response = authenticated_client.delete(
            reverse("role-detail", kwargs={"pk": role.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Role.objects.filter(id=role.id).exists()

    def test_role_destroy_invalid(self, authenticated_client):
        response = authenticated_client.delete(
            reverse("role-detail", kwargs={"pk": "non-existent-id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_role_retrieve_not_found(self, authenticated_client):
        response = authenticated_client.get(
            reverse("role-detail", kwargs={"pk": "non-existent-id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_role_list_filters(self, authenticated_client, roles_fixture):
        role = roles_fixture[0]
        response = authenticated_client.get(
            reverse("role-list"), {"filter[name]": role.name}
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["attributes"]["name"] == role.name

    def test_role_list_sorting(self, authenticated_client, roles_fixture):
        response = authenticated_client.get(reverse("role-list"), {"sort": "name"})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        names = [
            item["attributes"]["name"]
            for item in data
            if item["attributes"]["name"] != "admin"
        ]
        assert names == sorted(names, key=lambda v: v.lower())

    def test_role_invalid_method(self, authenticated_client):
        response = authenticated_client.put(reverse("role-list"))
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_role_create_with_users_and_provider_groups(
        self, authenticated_client, users_fixture, provider_groups_fixture
    ):
        user1, user2, *_ = users_fixture
        pg1, pg2, *_ = provider_groups_fixture

        data = {
            "data": {
                "type": "roles",
                "attributes": {
                    "name": "Role with Users and PGs",
                    "manage_users": "true",
                    "manage_account": "false",
                    "manage_providers": "true",
                    "manage_scans": "false",
                    "unlimited_visibility": "false",
                },
                "relationships": {
                    "users": {
                        "data": [
                            {"type": "users", "id": str(user1.id)},
                            {"type": "users", "id": str(user2.id)},
                        ]
                    },
                    "provider_groups": {
                        "data": [
                            {"type": "provider-groups", "id": str(pg1.id)},
                            {"type": "provider-groups", "id": str(pg2.id)},
                        ]
                    },
                },
            }
        }

        response = authenticated_client.post(
            reverse("role-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        created_role = Role.objects.get(name="Role with Users and PGs")

        assert created_role.users.count() == 2
        assert set(created_role.users.all()) == {user1, user2}

        assert created_role.provider_groups.count() == 2
        assert set(created_role.provider_groups.all()) == {pg1, pg2}

    def test_role_update_relationships(
        self,
        authenticated_client,
        roles_fixture,
        users_fixture,
        provider_groups_fixture,
    ):
        role = roles_fixture[0]
        user3 = users_fixture[2]
        pg3 = provider_groups_fixture[2]

        data = {
            "data": {
                "id": str(role.id),
                "type": "roles",
                "relationships": {
                    "users": {
                        "data": [
                            {"type": "users", "id": str(user3.id)},
                        ]
                    },
                    "provider_groups": {
                        "data": [
                            {"type": "provider-groups", "id": str(pg3.id)},
                        ]
                    },
                },
            }
        }

        response = authenticated_client.patch(
            reverse("role-detail", kwargs={"pk": role.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        role.refresh_from_db()

        assert role.users.count() == 1
        assert role.users.first() == user3
        assert role.provider_groups.count() == 1
        assert role.provider_groups.first() == pg3

    def test_role_clear_relationships(self, authenticated_client, roles_fixture):
        role = roles_fixture[0]
        data = {
            "data": {
                "id": str(role.id),
                "type": "roles",
                "relationships": {
                    "users": {"data": []},  # Clearing all users
                    "provider_groups": {"data": []},  # Clearing all provider groups
                },
            }
        }

        response = authenticated_client.patch(
            reverse("role-detail", kwargs={"pk": role.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        role.refresh_from_db()
        assert role.users.count() == 0
        assert role.provider_groups.count() == 0

    def test_cannot_remove_own_assignment_via_role_update(
        self, authenticated_client, roles_fixture
    ):
        role = roles_fixture[0]
        # Ensure the authenticated user is assigned to this role
        user = User.objects.get(email=TEST_USER)
        if not UserRoleRelationship.objects.filter(user=user, role=role).exists():
            UserRoleRelationship.objects.create(
                user=user, role=role, tenant_id=role.tenant_id
            )

        # Attempt to update role users to exclude the current user
        data = {
            "data": {
                "id": str(role.id),
                "type": "roles",
                "relationships": {"users": {"data": []}},
            }
        }
        response = authenticated_client.patch(
            reverse("role-detail", kwargs={"pk": role.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            "cannot remove their own role"
            in response.json()["errors"][0]["detail"].lower()
        )

    def test_role_create_with_invalid_user_relationship(
        self, authenticated_client, provider_groups_fixture
    ):
        invalid_user_id = "non-existent-user-id"
        pg = provider_groups_fixture[0]

        data = {
            "data": {
                "type": "roles",
                "attributes": {
                    "name": "Invalid Users Role",
                    "manage_users": "false",
                    "manage_account": "false",
                    "manage_providers": "true",
                    "manage_scans": "true",
                    "unlimited_visibility": "true",
                },
                "relationships": {
                    "users": {"data": [{"type": "users", "id": invalid_user_id}]},
                    "provider_groups": {
                        "data": [{"type": "provider-groups", "id": str(pg.id)}]
                    },
                },
            }
        }

        response = authenticated_client.post(
            reverse("role-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )

        assert response.status_code in [status.HTTP_400_BAD_REQUEST]


@pytest.mark.django_db
class TestUserRoleRelationshipViewSet:
    def test_create_relationship(
        self, authenticated_client, roles_fixture, create_test_user
    ):
        data = {
            "data": [
                {"type": "roles", "id": str(role.id)} for role in roles_fixture[:2]
            ]
        }
        response = authenticated_client.post(
            reverse("user-roles-relationship", kwargs={"pk": create_test_user.id}),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = UserRoleRelationship.objects.filter(user=create_test_user.id)
        assert relationships.count() == 4
        for relationship in relationships[2:]:  # Skip admin role
            assert relationship.role.id in [r.id for r in roles_fixture[:2]]

    def test_create_relationship_already_exists(
        self, authenticated_client, roles_fixture, create_test_user
    ):
        # Only add Role One (which has manage_account=True) to ensure
        # the second request has permission to add roles
        data = {
            "data": [
                {"type": "roles", "id": str(roles_fixture[0].id)},
            ]
        }
        authenticated_client.post(
            reverse("user-roles-relationship", kwargs={"pk": create_test_user.id}),
            data=data,
            content_type="application/vnd.api+json",
        )

        data = {
            "data": [
                {"type": "roles", "id": str(roles_fixture[0].id)},
            ]
        }
        response = authenticated_client.post(
            reverse("user-roles-relationship", kwargs={"pk": create_test_user.id}),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]["detail"]
        assert "already associated" in errors

    def test_partial_update_relationship(
        self, authenticated_client, roles_fixture, create_test_user
    ):
        data = {
            "data": [
                {"type": "roles", "id": str(roles_fixture[2].id)},
            ]
        }
        response = authenticated_client.patch(
            reverse("user-roles-relationship", kwargs={"pk": create_test_user.id}),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = UserRoleRelationship.objects.filter(user=create_test_user.id)
        assert relationships.count() == 1
        assert {rel.role.id for rel in relationships} == {roles_fixture[2].id}

        data = {
            "data": [
                {"type": "roles", "id": str(roles_fixture[1].id)},
                {"type": "roles", "id": str(roles_fixture[2].id)},
            ]
        }
        response = authenticated_client.patch(
            reverse("user-roles-relationship", kwargs={"pk": create_test_user.id}),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = UserRoleRelationship.objects.filter(user=create_test_user.id)
        assert relationships.count() == 2
        assert {rel.role.id for rel in relationships} == {
            roles_fixture[1].id,
            roles_fixture[2].id,
        }

    def test_destroy_relationship_other_user(
        self, authenticated_client, roles_fixture, create_test_user, tenants_fixture
    ):
        # Create another user in same tenant and assign a role
        tenant = tenants_fixture[0]
        other_user = User.objects.create_user(
            name="other",
            email="other_user@prowler.com",
            password="TmpPass123@",
        )
        Membership.objects.create(user=other_user, tenant=tenant)
        UserRoleRelationship.objects.create(
            user=other_user, role=roles_fixture[0], tenant_id=tenant.id
        )

        # Delete roles for the other user (allowed)
        response = authenticated_client.delete(
            reverse("user-roles-relationship", kwargs={"pk": other_user.id}),
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = UserRoleRelationship.objects.filter(user=other_user.id)
        assert relationships.count() == 0

    def test_cannot_delete_own_roles(self, authenticated_client, create_test_user):
        # Attempt to delete own roles should be forbidden
        response = authenticated_client.delete(
            reverse("user-roles-relationship", kwargs={"pk": create_test_user.id}),
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_prevent_removing_last_manage_account_on_patch(
        self, authenticated_client, roles_fixture, create_test_user, tenants_fixture
    ):
        # roles_fixture[1] has manage_account=False
        limited_role = roles_fixture[1]

        # Ensure there is no other user with MANAGE_ACCOUNT in the tenant
        tenant = tenants_fixture[0]
        # Create a secondary user without MANAGE_ACCOUNT
        user2 = User.objects.create_user(
            name="limited_user",
            email="limited_user@prowler.com",
            password="TmpPass123@",
        )
        Membership.objects.create(user=user2, tenant=tenant)
        UserRoleRelationship.objects.create(
            user=user2, role=limited_role, tenant_id=tenant.id
        )

        # Attempt to switch the only MANAGE_ACCOUNT user to a role without it
        data = {"data": [{"type": "roles", "id": str(limited_role.id)}]}
        response = authenticated_client.patch(
            reverse("user-roles-relationship", kwargs={"pk": create_test_user.id}),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "MANAGE_ACCOUNT" in response.json()["errors"][0]["detail"]

    def test_allow_role_change_when_other_user_has_manage_account_on_patch(
        self, authenticated_client, roles_fixture, create_test_user, tenants_fixture
    ):
        # roles_fixture[1] has manage_account=False, roles_fixture[0] has manage_account=True
        limited_role = roles_fixture[1]
        ma_role = roles_fixture[0]

        tenant = tenants_fixture[0]
        # Create another user with MANAGE_ACCOUNT
        user2 = User.objects.create_user(
            name="ma_user",
            email="ma_user@prowler.com",
            password="TmpPass123@",
        )
        Membership.objects.create(user=user2, tenant=tenant)
        UserRoleRelationship.objects.create(
            user=user2, role=ma_role, tenant_id=tenant.id
        )

        # Now changing the first user's roles to a non-MA role should succeed
        data = {"data": [{"type": "roles", "id": str(limited_role.id)}]}
        response = authenticated_client.patch(
            reverse("user-roles-relationship", kwargs={"pk": create_test_user.id}),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_role_destroy_only_manage_account_blocked(
        self, authenticated_client, tenants_fixture
    ):
        # Use a tenant without default admin role (tenant3)
        tenant = tenants_fixture[2]
        user = User.objects.get(email=TEST_USER)
        # Add membership for this tenant
        Membership.objects.create(user=user, tenant=tenant)

        # Create a single MANAGE_ACCOUNT role in this tenant
        only_role = Role.objects.create(
            name="only_ma",
            tenant=tenant,
            manage_users=True,
            manage_account=True,
            manage_billing=False,
            manage_providers=False,
            manage_integrations=False,
            manage_scans=False,
            unlimited_visibility=False,
        )

        # Switch token to this tenant
        serializer = TokenSerializer(
            data={
                "type": "tokens",
                "email": TEST_USER,
                "password": TEST_PASSWORD,
                "tenant_id": str(tenant.id),
            }
        )
        serializer.is_valid(raise_exception=True)
        access_token = serializer.validated_data["access"]
        authenticated_client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"

        # Attempt to delete the only MANAGE_ACCOUNT role
        response = authenticated_client.delete(
            reverse("role-detail", kwargs={"pk": only_role.id})
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert Role.objects.filter(id=only_role.id).exists()

    def test_invalid_provider_group_id(self, authenticated_client, create_test_user):
        invalid_id = "non-existent-id"
        data = {"data": [{"type": "provider-groups", "id": invalid_id}]}
        response = authenticated_client.post(
            reverse("user-roles-relationship", kwargs={"pk": create_test_user.id}),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"][0]["detail"]
        assert "valid UUID" in errors


@pytest.mark.django_db
class TestRoleProviderGroupRelationshipViewSet:
    def test_create_relationship(
        self, authenticated_client, roles_fixture, provider_groups_fixture
    ):
        data = {
            "data": [
                {"type": "provider-groups", "id": str(provider_group.id)}
                for provider_group in provider_groups_fixture[:2]
            ]
        }
        response = authenticated_client.post(
            reverse(
                "role-provider-groups-relationship", kwargs={"pk": roles_fixture[0].id}
            ),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = RoleProviderGroupRelationship.objects.filter(
            role=roles_fixture[0].id
        )
        assert relationships.count() == 2
        for relationship in relationships:
            assert relationship.provider_group.id in [
                pg.id for pg in provider_groups_fixture[:2]
            ]

    def test_create_relationship_already_exists(
        self, authenticated_client, roles_fixture, provider_groups_fixture
    ):
        data = {
            "data": [
                {"type": "provider-groups", "id": str(provider_group.id)}
                for provider_group in provider_groups_fixture[:2]
            ]
        }
        authenticated_client.post(
            reverse(
                "role-provider-groups-relationship", kwargs={"pk": roles_fixture[0].id}
            ),
            data=data,
            content_type="application/vnd.api+json",
        )

        data = {
            "data": [
                {"type": "provider-groups", "id": str(provider_groups_fixture[0].id)},
            ]
        }
        response = authenticated_client.post(
            reverse(
                "role-provider-groups-relationship", kwargs={"pk": roles_fixture[0].id}
            ),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]["detail"]
        assert "already associated" in errors

    def test_partial_update_relationship(
        self, authenticated_client, roles_fixture, provider_groups_fixture
    ):
        data = {
            "data": [
                {"type": "provider-groups", "id": str(provider_groups_fixture[1].id)},
            ]
        }
        response = authenticated_client.patch(
            reverse(
                "role-provider-groups-relationship", kwargs={"pk": roles_fixture[2].id}
            ),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = RoleProviderGroupRelationship.objects.filter(
            role=roles_fixture[2].id
        )
        assert relationships.count() == 1
        assert {rel.provider_group.id for rel in relationships} == {
            provider_groups_fixture[1].id
        }

        data = {
            "data": [
                {"type": "provider-groups", "id": str(provider_groups_fixture[1].id)},
                {"type": "provider-groups", "id": str(provider_groups_fixture[2].id)},
            ]
        }
        response = authenticated_client.patch(
            reverse(
                "role-provider-groups-relationship", kwargs={"pk": roles_fixture[2].id}
            ),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = RoleProviderGroupRelationship.objects.filter(
            role=roles_fixture[2].id
        )
        assert relationships.count() == 2
        assert {rel.provider_group.id for rel in relationships} == {
            provider_groups_fixture[1].id,
            provider_groups_fixture[2].id,
        }

    def test_destroy_relationship(
        self, authenticated_client, roles_fixture, provider_groups_fixture
    ):
        response = authenticated_client.delete(
            reverse(
                "role-provider-groups-relationship", kwargs={"pk": roles_fixture[0].id}
            ),
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = RoleProviderGroupRelationship.objects.filter(
            role=roles_fixture[0].id
        )
        assert relationships.count() == 0

    def test_invalid_provider_group_id(self, authenticated_client, roles_fixture):
        invalid_id = "non-existent-id"
        data = {"data": [{"type": "provider-groups", "id": invalid_id}]}
        response = authenticated_client.post(
            reverse(
                "role-provider-groups-relationship", kwargs={"pk": roles_fixture[1].id}
            ),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"][0]["detail"]
        assert "valid UUID" in errors


@pytest.mark.django_db
class TestProviderGroupMembershipViewSet:
    def test_create_relationship(
        self, authenticated_client, providers_fixture, provider_groups_fixture
    ):
        provider_group, *_ = provider_groups_fixture
        data = {
            "data": [
                {"type": "provider", "id": str(provider.id)}
                for provider in providers_fixture[:2]
            ]
        }
        response = authenticated_client.post(
            reverse(
                "provider_group-providers-relationship",
                kwargs={"pk": provider_group.id},
            ),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = ProviderGroupMembership.objects.filter(
            provider_group=provider_group.id
        )
        assert relationships.count() == 2
        for relationship in relationships:
            assert relationship.provider.id in [p.id for p in providers_fixture[:2]]

    def test_create_relationship_already_exists(
        self, authenticated_client, providers_fixture, provider_groups_fixture
    ):
        provider_group, *_ = provider_groups_fixture
        data = {
            "data": [
                {"type": "provider", "id": str(provider.id)}
                for provider in providers_fixture[:2]
            ]
        }
        authenticated_client.post(
            reverse(
                "provider_group-providers-relationship",
                kwargs={"pk": provider_group.id},
            ),
            data=data,
            content_type="application/vnd.api+json",
        )

        data = {
            "data": [
                {"type": "provider", "id": str(providers_fixture[0].id)},
            ]
        }
        response = authenticated_client.post(
            reverse(
                "provider_group-providers-relationship",
                kwargs={"pk": provider_group.id},
            ),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]["detail"]
        assert "already associated" in errors

    def test_partial_update_relationship(
        self, authenticated_client, providers_fixture, provider_groups_fixture
    ):
        provider_group, *_ = provider_groups_fixture
        data = {
            "data": [
                {"type": "provider", "id": str(providers_fixture[1].id)},
            ]
        }
        response = authenticated_client.patch(
            reverse(
                "provider_group-providers-relationship",
                kwargs={"pk": provider_group.id},
            ),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = ProviderGroupMembership.objects.filter(
            provider_group=provider_group.id
        )
        assert relationships.count() == 1
        assert {rel.provider.id for rel in relationships} == {providers_fixture[1].id}

        data = {
            "data": [
                {"type": "provider", "id": str(providers_fixture[1].id)},
                {"type": "provider", "id": str(providers_fixture[2].id)},
            ]
        }
        response = authenticated_client.patch(
            reverse(
                "provider_group-providers-relationship",
                kwargs={"pk": provider_group.id},
            ),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = ProviderGroupMembership.objects.filter(
            provider_group=provider_group.id
        )
        assert relationships.count() == 2
        assert {rel.provider.id for rel in relationships} == {
            providers_fixture[1].id,
            providers_fixture[2].id,
        }

    def test_destroy_relationship(
        self, authenticated_client, providers_fixture, provider_groups_fixture
    ):
        provider_group, *_ = provider_groups_fixture
        data = {
            "data": [
                {"type": "provider", "id": str(provider.id)}
                for provider in providers_fixture[:2]
            ]
        }
        response = authenticated_client.post(
            reverse(
                "provider_group-providers-relationship",
                kwargs={"pk": provider_group.id},
            ),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        response = authenticated_client.delete(
            reverse(
                "provider_group-providers-relationship",
                kwargs={"pk": provider_group.id},
            ),
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        relationships = ProviderGroupMembership.objects.filter(
            provider_group=providers_fixture[0].id
        )
        assert relationships.count() == 0

    def test_invalid_provider_group_id(
        self, authenticated_client, provider_groups_fixture
    ):
        provider_group, *_ = provider_groups_fixture
        invalid_id = "non-existent-id"
        data = {"data": [{"type": "provider-groups", "id": invalid_id}]}
        response = authenticated_client.post(
            reverse(
                "provider_group-providers-relationship",
                kwargs={"pk": provider_group.id},
            ),
            data=data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"][0]["detail"]
        assert "valid UUID" in errors


@pytest.mark.django_db
class TestComplianceOverviewViewSet:
    @pytest.fixture(autouse=True)
    def mock_backfill_task(self):
        with patch("api.v1.views.backfill_compliance_summaries_task.delay") as mock:
            yield mock

    def test_compliance_overview_list_none(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        mock_backfill_task,
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        scan = Scan.objects.create(
            name="empty-compliance-scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {"filter[scan_id]": str(scan.id)},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0
        mock_backfill_task.assert_called_once()
        _, kwargs = mock_backfill_task.call_args
        assert kwargs["scan_id"] == str(scan.id)
        assert str(kwargs["tenant_id"]) == str(tenant.id)

    def test_compliance_overview_list(
        self,
        authenticated_client,
        compliance_requirements_overviews_fixture,
        mock_backfill_task,
    ):
        # List compliance overviews with existing data
        requirement_overview1 = compliance_requirements_overviews_fixture[0]
        scan_id = str(requirement_overview1.scan.id)

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {"filter[scan_id]": scan_id},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 3  # Three compliance frameworks

        # Check that we get aggregated data for each compliance framework
        framework_ids = [item["id"] for item in data]
        assert "aws_account_security_onboarding_aws" in framework_ids
        assert "cis_1.4_aws" in framework_ids
        assert "mitre_attack_aws" in framework_ids
        # Check structure of response
        for item in data:
            assert "id" in item
            assert "attributes" in item
            attributes = item["attributes"]
            assert "framework" in attributes
            assert "version" in attributes
            assert "requirements_passed" in attributes
            assert "requirements_failed" in attributes
            assert "requirements_manual" in attributes
            assert "total_requirements" in attributes
        mock_backfill_task.assert_called_once()
        _, kwargs = mock_backfill_task.call_args
        assert kwargs["scan_id"] == scan_id

    def test_compliance_overview_list_uses_preaggregated_summaries(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        mock_backfill_task,
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        scan = Scan.objects.create(
            name="preaggregated-scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        ComplianceRequirementOverview.objects.create(
            tenant=tenant,
            scan=scan,
            compliance_id="cis_1.4_aws",
            framework="CIS-1.4-AWS",
            version="1.4",
            description="CIS AWS Foundations Benchmark v1.4.0",
            region="eu-west-1",
            requirement_id="framework-metadata",
            requirement_status=StatusChoices.PASS,
            passed_checks=1,
            failed_checks=0,
            total_checks=1,
        )

        ComplianceOverviewSummary.objects.create(
            tenant=tenant,
            scan=scan,
            compliance_id="cis_1.4_aws",
            requirements_passed=5,
            requirements_failed=1,
            requirements_manual=2,
            total_requirements=8,
        )

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {"filter[scan_id]": str(scan.id)},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        overview = data[0]
        assert overview["id"] == "cis_1.4_aws"
        assert overview["attributes"]["requirements_passed"] == 5
        assert overview["attributes"]["requirements_failed"] == 1
        assert overview["attributes"]["requirements_manual"] == 2
        assert overview["attributes"]["total_requirements"] == 8
        assert "framework" in overview["attributes"]
        assert "version" in overview["attributes"]
        mock_backfill_task.assert_not_called()

    def test_compliance_overview_region_filter_skips_backfill(
        self,
        authenticated_client,
        compliance_requirements_overviews_fixture,
        mock_backfill_task,
    ):
        requirement_overview = compliance_requirements_overviews_fixture[0]
        scan_id = str(requirement_overview.scan.id)

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            {
                "filter[scan_id]": scan_id,
                "filter[region]": requirement_overview.region,
            },
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) >= 1
        mock_backfill_task.assert_not_called()

    def test_compliance_overview_metadata(
        self, authenticated_client, compliance_requirements_overviews_fixture
    ):
        requirement_overview1 = compliance_requirements_overviews_fixture[0]
        scan_id = str(requirement_overview1.scan.id)

        response = authenticated_client.get(
            reverse("complianceoverview-metadata"),
            {"filter[scan_id]": scan_id},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert "attributes" in data
        assert "regions" in data["attributes"]
        assert isinstance(data["attributes"]["regions"], list)

    def test_compliance_overview_requirements(
        self, authenticated_client, compliance_requirements_overviews_fixture
    ):
        requirement_overview1 = compliance_requirements_overviews_fixture[0]
        scan_id = str(requirement_overview1.scan.id)
        compliance_id = requirement_overview1.compliance_id

        response = authenticated_client.get(
            reverse("complianceoverview-requirements"),
            {
                "filter[scan_id]": scan_id,
                "filter[compliance_id]": compliance_id,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) > 0

        # Check structure of requirements response
        for item in data:
            assert "id" in item
            assert "attributes" in item
            attributes = item["attributes"]
            assert "framework" in attributes
            assert "version" in attributes
            assert "description" in attributes
            assert "status" in attributes

    # TODO: This test may fail randomly because requirements are not ordered
    @pytest.mark.xfail
    def test_compliance_overview_requirements_manual(
        self, authenticated_client, compliance_requirements_overviews_fixture
    ):
        scan_id = str(compliance_requirements_overviews_fixture[0].scan.id)
        # Compliance with a manual requirement
        compliance_id = "aws_account_security_onboarding_aws"

        response = authenticated_client.get(
            reverse("complianceoverview-requirements"),
            {
                "filter[scan_id]": scan_id,
                "filter[compliance_id]": compliance_id,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert data[-1]["attributes"]["status"] == "MANUAL"

    def test_compliance_overview_requirements_missing_scan_id(
        self, authenticated_client
    ):
        response = authenticated_client.get(
            reverse("complianceoverview-requirements"),
            {"filter[compliance_id]": "aws_account_security_onboarding_aws"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_compliance_overview_requirements_missing_compliance_id(
        self, authenticated_client, compliance_requirements_overviews_fixture
    ):
        requirement_overview1 = compliance_requirements_overviews_fixture[0]
        scan_id = str(requirement_overview1.scan.id)

        response = authenticated_client.get(
            reverse("complianceoverview-requirements"),
            {"filter[scan_id]": scan_id},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_compliance_overview_attributes(self, authenticated_client):
        response = authenticated_client.get(
            reverse("complianceoverview-attributes"),
            {"filter[compliance_id]": "aws_account_security_onboarding_aws"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) > 0

        # Check structure of attributes response
        for item in data:
            assert "id" in item
            assert "attributes" in item
            attributes = item["attributes"]
            assert "framework" in attributes
            assert "version" in attributes
            assert "description" in attributes
            assert "attributes" in attributes
            assert "metadata" in attributes["attributes"]
            assert "check_ids" in attributes["attributes"]
            assert "technique_details" not in attributes["attributes"]

    def test_compliance_overview_attributes_technique_details(
        self, authenticated_client
    ):
        response = authenticated_client.get(
            reverse("complianceoverview-attributes"),
            {"filter[compliance_id]": "mitre_attack_aws"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) > 0

        # Check structure of attributes response
        for item in data:
            assert "id" in item
            assert "attributes" in item
            attributes = item["attributes"]
            assert "framework" in attributes
            assert "version" in attributes
            assert "description" in attributes
            assert "attributes" in attributes
            assert "metadata" in attributes["attributes"]
            assert "check_ids" in attributes["attributes"]
            assert "technique_details" in attributes["attributes"]
            assert "tactics" in attributes["attributes"]["technique_details"]
            assert "subtechniques" in attributes["attributes"]["technique_details"]
            assert "platforms" in attributes["attributes"]["technique_details"]
            assert "technique_url" in attributes["attributes"]["technique_details"]

    def test_compliance_overview_attributes_missing_compliance_id(
        self, authenticated_client
    ):
        response = authenticated_client.get(
            reverse("complianceoverview-attributes"),
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_compliance_overview_task_management_integration(
        self, authenticated_client, compliance_requirements_overviews_fixture
    ):
        """Test that task management mixin is properly integrated"""
        from unittest.mock import patch

        requirement_overview1 = compliance_requirements_overviews_fixture[0]
        scan_id = str(requirement_overview1.scan.id)

        # Remove existing compliance data so the view falls back to task checks
        scan = requirement_overview1.scan
        ComplianceOverviewSummary.objects.filter(scan=scan).delete()
        ComplianceRequirementOverview.objects.filter(scan=scan).delete()

        # Mock a running task
        with patch.object(
            ComplianceOverviewViewSet, "get_task_response_if_running"
        ) as mock_task_response:
            mock_response = Response(
                {"detail": "Task is running"}, status=status.HTTP_202_ACCEPTED
            )
            mock_task_response.return_value = mock_response

            response = authenticated_client.get(
                reverse("complianceoverview-list"),
                {"filter[scan_id]": scan_id},
            )
            assert response.status_code == status.HTTP_202_ACCEPTED
            mock_task_response.assert_called_once()

    def test_compliance_overview_task_failed_exception(
        self, authenticated_client, compliance_requirements_overviews_fixture
    ):
        """Test handling of TaskFailedException"""
        from unittest.mock import patch

        from api.exceptions import TaskFailedException

        requirement_overview1 = compliance_requirements_overviews_fixture[0]
        scan_id = str(requirement_overview1.scan.id)

        # Remove existing compliance data so the view falls back to task checks
        scan = requirement_overview1.scan
        ComplianceOverviewSummary.objects.filter(scan=scan).delete()
        ComplianceRequirementOverview.objects.filter(scan=scan).delete()

        # Mock a failed task
        with patch.object(
            ComplianceOverviewViewSet, "get_task_response_if_running"
        ) as mock_task_response:
            mock_task_response.side_effect = TaskFailedException("Task failed")

            response = authenticated_client.get(
                reverse("complianceoverview-list"),
                {"filter[scan_id]": scan_id},
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Task failed to generate compliance overview data" in str(
                response.data
            )

    @pytest.mark.parametrize(
        "filter_name, filter_value_attr, expected_count_min",
        [
            ("scan_id", "scan.id", 1),
            ("compliance_id", "compliance_id", 1),
            ("framework", "framework", 1),
            ("version", "version", 1),
            ("region", "region", 1),
            ("region__in", "region", 1),
            ("region.in", "region", 1),
        ],
    )
    def test_compliance_overview_filters(
        self,
        authenticated_client,
        compliance_requirements_overviews_fixture,
        filter_name,
        filter_value_attr,
        expected_count_min,
    ):
        requirement_overview = compliance_requirements_overviews_fixture[0]
        scan_id = str(requirement_overview.scan.id)

        filter_value = requirement_overview
        for attr in filter_value_attr.split("."):
            filter_value = getattr(filter_value, attr)

        filter_value = str(filter_value)

        query_params = {
            "filter[scan_id]": scan_id,
            f"filter[{filter_name}]": filter_value,
        }

        if filter_name == "scan_id":
            query_params = {"filter[scan_id]": filter_value}

        response = authenticated_client.get(
            reverse("complianceoverview-list"),
            query_params,
        )

        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()

        assert len(response_data["data"]) >= expected_count_min

        if response_data["data"]:
            first_item = response_data["data"][0]
            assert "id" in first_item
            assert "type" in first_item
            assert first_item["type"] == "compliance-overviews"
            assert "attributes" in first_item

            attributes = first_item["attributes"]
            assert "framework" in attributes
            assert "version" in attributes
            assert "requirements_passed" in attributes
            assert "requirements_failed" in attributes
            assert "requirements_manual" in attributes
            assert "total_requirements" in attributes

            if filter_name == "compliance_id":
                assert first_item["id"] == filter_value
            elif filter_name == "framework":
                assert attributes["framework"] == filter_value
            elif filter_name == "version":
                assert attributes["version"] == filter_value


@pytest.mark.django_db
class TestOverviewViewSet:
    def test_overview_list_invalid_method(self, authenticated_client):
        response = authenticated_client.put(reverse("overview-list"))
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_overview_providers_list(
        self, authenticated_client, scan_summaries_fixture, resources_fixture
    ):
        response = authenticated_client.get(reverse("overview-providers"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["findings"]["total"] == 9
        assert response.json()["data"][0]["attributes"]["findings"]["pass"] == 2
        assert response.json()["data"][0]["attributes"]["findings"]["fail"] == 1
        assert response.json()["data"][0]["attributes"]["findings"]["muted"] == 6
        # Aggregated resources include all AWS providers present in the tenant
        assert response.json()["data"][0]["attributes"]["resources"]["total"] == 3

    def test_overview_providers_aggregates_same_provider_type(
        self,
        authenticated_client,
        scan_summaries_fixture,
        resources_fixture,
        providers_fixture,
        tenants_fixture,
    ):
        tenant = tenants_fixture[0]
        _provider1, provider2, *_ = providers_fixture

        scan = Scan.objects.create(
            name="overview scan aws account 2",
            provider=provider2,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        ScanSummary.objects.create(
            tenant=tenant,
            scan=scan,
            check_id="check-aws-two",
            service="service-extra",
            severity="medium",
            region="region-extra",
            _pass=3,
            fail=2,
            muted=1,
            total=6,
        )

        Resource.objects.create(
            tenant_id=tenant.id,
            provider=provider2,
            uid="arn:aws:ec2:us-west-2:123456789013:instance/i-aggregation",
            name="Aggregated Instance",
            region="us-west-2",
            service="ec2",
            type="prowler-test",
        )

        response = authenticated_client.get(reverse("overview-providers"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        attributes = data[0]["attributes"]

        assert attributes["findings"]["total"] == 15
        assert attributes["findings"]["pass"] == 5
        assert attributes["findings"]["fail"] == 3
        assert attributes["findings"]["muted"] == 7
        assert attributes["resources"]["total"] == 4

    def test_overview_providers_count(
        self,
        authenticated_client,
        scan_summaries_fixture,
        resources_fixture,
        providers_fixture,
        tenants_fixture,
    ):
        tenant = tenants_fixture[0]

        default_response = authenticated_client.get(reverse("overview-providers"))
        assert default_response.status_code == status.HTTP_200_OK
        default_data = default_response.json()["data"]
        assert len(default_data) == 1
        assert all("count" not in item["attributes"] for item in default_data)
        grouped_response = authenticated_client.get(reverse("overview-providers-count"))
        assert grouped_response.status_code == status.HTTP_200_OK
        grouped_data = grouped_response.json()["data"]
        assert len(grouped_data) >= 1

        aggregated = {
            entry["id"]: entry["attributes"]["count"] for entry in grouped_data
        }
        db_counts = (
            Provider.objects.filter(tenant_id=tenant.id, is_deleted=False)
            .values("provider")
            .annotate(count=Count("id"))
        )
        expected = {row["provider"]: row["count"] for row in db_counts}

        assert aggregated == expected
        for entry in grouped_data:
            assert "findings" not in entry["attributes"]

    def _create_scan(self, tenant, provider, name, started_at=None):
        scan_started = started_at or datetime.now(timezone.utc) - timedelta(hours=1)
        return Scan.objects.create(
            tenant=tenant,
            provider=provider,
            name=name,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            started_at=scan_started,
            completed_at=scan_started + timedelta(minutes=30),
        )

    def _create_threatscore_snapshot(
        self,
        tenant,
        scan,
        provider,
        *,
        compliance_id,
        overall_score,
        score_delta,
        section_scores,
        critical_requirements,
        total_requirements,
        passed_requirements,
        failed_requirements,
        manual_requirements,
        total_findings,
        passed_findings,
        failed_findings,
    ):
        return ThreatScoreSnapshot.objects.create(
            tenant=tenant,
            scan=scan,
            provider=provider,
            compliance_id=compliance_id,
            overall_score=Decimal(overall_score),
            score_delta=Decimal(score_delta) if score_delta is not None else None,
            section_scores=section_scores,
            critical_requirements=critical_requirements,
            total_requirements=total_requirements,
            passed_requirements=passed_requirements,
            failed_requirements=failed_requirements,
            manual_requirements=manual_requirements,
            total_findings=total_findings,
            passed_findings=passed_findings,
            failed_findings=failed_findings,
        )

    def test_overview_threatscore_returns_weighted_aggregate_snapshot(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider1, provider2, *_ = providers_fixture

        scan1 = self._create_scan(tenant, provider1, "agg-scan-one")
        scan2 = self._create_scan(tenant, provider2, "agg-scan-two")

        snapshot1 = self._create_threatscore_snapshot(
            tenant,
            scan1,
            provider1,
            compliance_id="prowler_threatscore_aws",
            overall_score="80.00",
            score_delta="5.00",
            section_scores={"1. IAM": "70.00", "2. Attack Surface": "60.00"},
            critical_requirements=[
                {
                    "requirement_id": "req_shared",
                    "title": "Shared requirement (preferred)",
                    "section": "1. IAM",
                    "subsection": "Sub IAM",
                    "risk_level": 5,
                    "weight": 150,
                    "passed_findings": 14,
                    "total_findings": 20,
                    "description": "Higher risk duplicate",
                },
                {
                    "requirement_id": "req_unique_one",
                    "title": "Unique provider one",
                    "section": "2. Attack Surface",
                    "subsection": "Sub Attack",
                    "risk_level": 4,
                    "weight": 90,
                    "passed_findings": 20,
                    "total_findings": 30,
                    "description": "Lower risk",
                },
            ],
            total_requirements=120,
            passed_requirements=90,
            failed_requirements=30,
            manual_requirements=0,
            total_findings=100,
            passed_findings=70,
            failed_findings=30,
        )

        snapshot2 = self._create_threatscore_snapshot(
            tenant,
            scan2,
            provider2,
            compliance_id="prowler_threatscore_aws",
            overall_score="20.00",
            score_delta="-2.00",
            section_scores={
                "1. IAM": "10.00",
                "2. Attack Surface": "40.00",
                "3. Logging": "30.00",
            },
            critical_requirements=[
                {
                    "requirement_id": "req_shared",
                    "title": "Shared requirement (secondary)",
                    "section": "1. IAM",
                    "subsection": "Sub IAM",
                    "risk_level": 4,
                    "weight": 120,
                    "passed_findings": 8,
                    "total_findings": 12,
                    "description": "Lower risk duplicate",
                },
                {
                    "requirement_id": "req_unique_two",
                    "title": "Unique provider two",
                    "section": "3. Logging",
                    "subsection": "Sub Logging",
                    "risk_level": 5,
                    "weight": 110,
                    "passed_findings": 6,
                    "total_findings": 10,
                    "description": "Another critical requirement",
                },
            ],
            total_requirements=80,
            passed_requirements=30,
            failed_requirements=50,
            manual_requirements=0,
            total_findings=50,
            passed_findings=15,
            failed_findings=35,
        )

        older_inserted = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
        newer_inserted = datetime(2025, 1, 2, 12, 0, tzinfo=timezone.utc)
        ThreatScoreSnapshot.objects.filter(id=snapshot1.id).update(
            inserted_at=older_inserted
        )
        ThreatScoreSnapshot.objects.filter(id=snapshot2.id).update(
            inserted_at=newer_inserted
        )
        snapshot2.refresh_from_db()

        response = authenticated_client.get(reverse("overview-threatscore"))

        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert len(body["data"]) == 1
        aggregated = body["data"][0]

        assert aggregated["id"] == "n/a"
        assert aggregated["relationships"]["scan"]["data"] is None
        assert aggregated["relationships"]["provider"]["data"] is None

        attrs = aggregated["attributes"]
        assert Decimal(attrs["overall_score"]) == Decimal("60.00")
        assert Decimal(attrs["score_delta"]) == Decimal("2.67")
        assert attrs["inserted_at"] == snapshot2.inserted_at.isoformat().replace(
            "+00:00", "Z"
        )
        assert attrs["total_findings"] == 150
        assert attrs["passed_findings"] == 85
        assert attrs["failed_findings"] == 65
        assert attrs["total_requirements"] == 200
        assert attrs["passed_requirements"] == 120
        assert attrs["failed_requirements"] == 80
        assert attrs["manual_requirements"] == 0

        assert attrs["section_scores"] == {
            "1. IAM": "50.00",
            "2. Attack Surface": "53.33",
            "3. Logging": "30.00",
        }

        expected_critical = [
            {
                "requirement_id": "req_shared",
                "title": "Shared requirement (preferred)",
                "section": "1. IAM",
                "subsection": "Sub IAM",
                "risk_level": 5,
                "weight": 150,
                "passed_findings": 14,
                "total_findings": 20,
                "description": "Higher risk duplicate",
            },
            {
                "requirement_id": "req_unique_two",
                "title": "Unique provider two",
                "section": "3. Logging",
                "subsection": "Sub Logging",
                "risk_level": 5,
                "weight": 110,
                "passed_findings": 6,
                "total_findings": 10,
                "description": "Another critical requirement",
            },
            {
                "requirement_id": "req_unique_one",
                "title": "Unique provider one",
                "section": "2. Attack Surface",
                "subsection": "Sub Attack",
                "risk_level": 4,
                "weight": 90,
                "passed_findings": 20,
                "total_findings": 30,
                "description": "Lower risk",
            },
        ]
        assert attrs["critical_requirements"] == expected_critical

    def test_overview_threatscore_weight_fallback_to_requirements(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider1, provider2, *_ = providers_fixture

        scan1 = self._create_scan(tenant, provider1, "fallback-scan-1")
        scan2 = self._create_scan(tenant, provider2, "fallback-scan-2")

        self._create_threatscore_snapshot(
            tenant,
            scan1,
            provider1,
            compliance_id="prowler_threatscore_aws",
            overall_score="90.00",
            score_delta="4.00",
            section_scores={"1. IAM": "90.00"},
            critical_requirements=[],
            total_requirements=10,
            passed_requirements=8,
            failed_requirements=0,
            manual_requirements=2,
            total_findings=0,
            passed_findings=0,
            failed_findings=0,
        )
        self._create_threatscore_snapshot(
            tenant,
            scan2,
            provider2,
            compliance_id="prowler_threatscore_aws",
            overall_score="50.00",
            score_delta="1.00",
            section_scores={"1. IAM": "40.00"},
            critical_requirements=[],
            total_requirements=12,
            passed_requirements=5,
            failed_requirements=7,
            manual_requirements=0,
            total_findings=10,
            passed_findings=4,
            failed_findings=6,
        )

        response = authenticated_client.get(reverse("overview-threatscore"))
        assert response.status_code == status.HTTP_200_OK
        aggregate = response.json()["data"][0]["attributes"]

        assert Decimal(aggregate["overall_score"]) == Decimal("67.78")
        assert Decimal(aggregate["score_delta"]) == Decimal("2.33")
        assert aggregate["total_findings"] == 10
        assert aggregate["total_requirements"] == 22
        assert aggregate["manual_requirements"] == 2
        assert aggregate["section_scores"] == {"1. IAM": "62.22"}

    def test_overview_threatscore_filter_by_scan_id_returns_snapshot(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider1, *_ = providers_fixture
        scan = self._create_scan(tenant, provider1, "filter-scan")

        snapshot = self._create_threatscore_snapshot(
            tenant,
            scan,
            provider1,
            compliance_id="prowler_threatscore_aws",
            overall_score="75.00",
            score_delta="3.00",
            section_scores={"1. IAM": "70.00"},
            critical_requirements=[],
            total_requirements=50,
            passed_requirements=30,
            failed_requirements=20,
            manual_requirements=0,
            total_findings=25,
            passed_findings=15,
            failed_findings=10,
        )

        response = authenticated_client.get(
            reverse("overview-threatscore"), {"filter[scan_id]": str(scan.id)}
        )

        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert len(body["data"]) == 1
        assert body["data"][0]["id"] == str(snapshot.id)
        assert body["data"][0]["attributes"]["overall_score"] == "75.00"

    def test_overview_threatscore_snapshot_id_returns_specific_snapshot(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider1, *_ = providers_fixture
        scan = self._create_scan(tenant, provider1, "snapshot-id-scan")

        snapshot = self._create_threatscore_snapshot(
            tenant,
            scan,
            provider1,
            compliance_id="prowler_threatscore_aws",
            overall_score="88.50",
            score_delta=None,
            section_scores={"1. IAM": "80.00"},
            critical_requirements=[],
            total_requirements=60,
            passed_requirements=45,
            failed_requirements=15,
            manual_requirements=0,
            total_findings=30,
            passed_findings=25,
            failed_findings=5,
        )

        response = authenticated_client.get(
            reverse("overview-threatscore"), {"snapshot_id": str(snapshot.id)}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["id"] == str(snapshot.id)
        assert data["data"]["attributes"]["score_delta"] is None

    def test_overview_threatscore_provider_filter_returns_unaggregated_snapshot(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider1, provider2, *_ = providers_fixture

        scan1 = self._create_scan(tenant, provider1, "provider-filter-scan-1")
        scan2 = self._create_scan(tenant, provider2, "provider-filter-scan-2")

        snapshot1 = self._create_threatscore_snapshot(
            tenant,
            scan1,
            provider1,
            compliance_id="prowler_threatscore_aws",
            overall_score="55.55",
            score_delta="1.10",
            section_scores={"1. IAM": "50.00"},
            critical_requirements=[],
            total_requirements=40,
            passed_requirements=25,
            failed_requirements=15,
            manual_requirements=0,
            total_findings=12,
            passed_findings=7,
            failed_findings=5,
        )
        self._create_threatscore_snapshot(
            tenant,
            scan2,
            provider2,
            compliance_id="prowler_threatscore_aws",
            overall_score="44.44",
            score_delta="0.80",
            section_scores={"1. IAM": "40.00"},
            critical_requirements=[],
            total_requirements=30,
            passed_requirements=18,
            failed_requirements=12,
            manual_requirements=0,
            total_findings=10,
            passed_findings=6,
            failed_findings=4,
        )

        response = authenticated_client.get(
            reverse("overview-threatscore"),
            {"filter[provider_id__in]": str(provider1.id)},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["id"] == str(snapshot1.id)
        assert data[0]["attributes"]["overall_score"] == "55.55"

    def test_overview_services_list_no_required_filters(
        self, authenticated_client, scan_summaries_fixture
    ):
        response = authenticated_client.get(reverse("overview-services"))
        assert response.status_code == status.HTTP_200_OK
        # Should return services from latest scans
        assert len(response.json()["data"]) == 2

    def test_overview_regions_list(self, authenticated_client, scan_summaries_fixture):
        response = authenticated_client.get(
            reverse("overview-regions"), {"filter[inserted_at]": TODAY}
        )
        assert response.status_code == status.HTTP_200_OK
        # Only two different regions in the fixture (region1, region2)
        assert len(response.json()["data"]) == 2

        data = response.json()["data"]
        regions = {item["id"]: item["attributes"] for item in data}

        assert "aws:region1" in regions
        assert "aws:region2" in regions

        # region1 has 5 findings (2 pass, 0 fail, 3 muted)
        assert regions["aws:region1"]["total"] == 5
        assert regions["aws:region1"]["pass"] == 2
        assert regions["aws:region1"]["fail"] == 0
        assert regions["aws:region1"]["muted"] == 3

        # region2 has 4 findings (0 pass, 1 fail, 3 muted)
        assert regions["aws:region2"]["total"] == 4
        assert regions["aws:region2"]["pass"] == 0
        assert regions["aws:region2"]["fail"] == 1
        assert regions["aws:region2"]["muted"] == 3

    def test_overview_services_list(self, authenticated_client, scan_summaries_fixture):
        response = authenticated_client.get(
            reverse("overview-services"), {"filter[inserted_at]": TODAY}
        )
        assert response.status_code == status.HTTP_200_OK
        # Only two different services
        assert len(response.json()["data"]) == 2
        # Fixed data from the fixture
        service1_data = response.json()["data"][0]
        service2_data = response.json()["data"][1]
        assert service1_data["id"] == "service1"
        assert service2_data["id"] == "service2"

        assert service1_data["attributes"]["total"] == 7
        assert service2_data["attributes"]["total"] == 2

        assert service1_data["attributes"]["pass"] == 1
        assert service2_data["attributes"]["pass"] == 1

        assert service1_data["attributes"]["fail"] == 1
        assert service2_data["attributes"]["fail"] == 0

        assert service1_data["attributes"]["muted"] == 5
        assert service2_data["attributes"]["muted"] == 1

    def test_overview_findings_provider_id_in_filter(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider1, provider2, *_ = providers_fixture

        scan1 = Scan.objects.create(
            name="scan-one",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )
        scan2 = Scan.objects.create(
            name="scan-two",
            provider=provider2,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        ScanSummary.objects.create(
            tenant=tenant,
            scan=scan1,
            check_id="check-provider-one",
            service="service-a",
            severity="high",
            region="region-a",
            _pass=5,
            fail=1,
            muted=2,
            total=8,
            new=5,
            changed=2,
            unchanged=1,
            fail_new=1,
            fail_changed=0,
            pass_new=3,
            pass_changed=2,
            muted_new=1,
            muted_changed=1,
        )

        ScanSummary.objects.create(
            tenant=tenant,
            scan=scan2,
            check_id="check-provider-two",
            service="service-b",
            severity="medium",
            region="region-b",
            _pass=2,
            fail=3,
            muted=1,
            total=6,
            new=3,
            changed=2,
            unchanged=1,
            fail_new=2,
            fail_changed=1,
            pass_new=1,
            pass_changed=1,
            muted_new=1,
            muted_changed=0,
        )

        single_response = authenticated_client.get(
            reverse("overview-findings"),
            {"filter[provider_id__in]": str(provider1.id)},
        )
        assert single_response.status_code == status.HTTP_200_OK
        single_attributes = single_response.json()["data"]["attributes"]
        assert single_attributes["pass"] == 5
        assert single_attributes["fail"] == 1
        assert single_attributes["muted"] == 2
        assert single_attributes["total"] == 8

        combined_response = authenticated_client.get(
            reverse("overview-findings"),
            {"filter[provider_id__in]": f"{provider1.id},{provider2.id}"},
        )
        assert combined_response.status_code == status.HTTP_200_OK
        combined_attributes = combined_response.json()["data"]["attributes"]
        assert combined_attributes["pass"] == 7
        assert combined_attributes["fail"] == 4
        assert combined_attributes["muted"] == 3
        assert combined_attributes["total"] == 14

    def test_overview_findings_severity_provider_id_in_filter(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider1, provider2, *_ = providers_fixture

        scan1 = Scan.objects.create(
            name="severity-scan-one",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )
        scan2 = Scan.objects.create(
            name="severity-scan-two",
            provider=provider2,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        # Muted findings should be excluded from severity counts
        ScanSummary.objects.create(
            tenant=tenant,
            scan=scan1,
            check_id="severity-check-one",
            service="service-a",
            severity="high",
            region="region-a",
            _pass=4,
            fail=4,
            muted=3,
            total=11,
        )
        ScanSummary.objects.create(
            tenant=tenant,
            scan=scan1,
            check_id="severity-check-two",
            service="service-a",
            severity="medium",
            region="region-b",
            _pass=2,
            fail=2,
            muted=2,
            total=6,
        )
        ScanSummary.objects.create(
            tenant=tenant,
            scan=scan2,
            check_id="severity-check-three",
            service="service-b",
            severity="critical",
            region="region-c",
            _pass=1,
            fail=2,
            muted=5,
            total=8,
        )

        single_response = authenticated_client.get(
            reverse("overview-findings_severity"),
            {"filter[provider_id__in]": str(provider1.id)},
        )
        assert single_response.status_code == status.HTTP_200_OK
        single_attributes = single_response.json()["data"]["attributes"]
        # Should only count pass + fail, excluding muted (3 muted in high, 2 in medium)
        assert single_attributes["high"] == 8
        assert single_attributes["medium"] == 4
        assert single_attributes["critical"] == 0

        combined_response = authenticated_client.get(
            reverse("overview-findings_severity"),
            {"filter[provider_id__in]": f"{provider1.id},{provider2.id}"},
        )
        assert combined_response.status_code == status.HTTP_200_OK
        combined_attributes = combined_response.json()["data"]["attributes"]
        # Should only count pass + fail, excluding muted (5 muted in critical)
        assert combined_attributes["high"] == 8
        assert combined_attributes["medium"] == 4
        assert combined_attributes["critical"] == 3

    def test_overview_findings_severity_timeseries_requires_date_from(
        self, authenticated_client
    ):
        response = authenticated_client.get(
            reverse("overview-findings_severity_timeseries")
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "date_from" in response.json()["errors"][0]["source"]["pointer"]

    def test_overview_findings_severity_timeseries_invalid_date_format(
        self, authenticated_client
    ):
        response = authenticated_client.get(
            reverse("overview-findings_severity_timeseries"),
            {"filter[date_from]": "invalid-date"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Enter a valid date." in response.json()["errors"][0]["detail"]

    def test_overview_findings_severity_timeseries_empty_data(
        self, authenticated_client
    ):
        response = authenticated_client.get(
            reverse("overview-findings_severity_timeseries"),
            {
                "filter[date_from]": "2024-01-01",
                "filter[date_to]": "2024-01-03",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        # Should return 3 days with fill-forward (all zeros since no data)
        assert len(data) == 3
        for item in data:
            assert item["attributes"]["critical"] == 0
            assert item["attributes"]["high"] == 0
            assert item["attributes"]["medium"] == 0
            assert item["attributes"]["low"] == 0
            assert item["attributes"]["informational"] == 0
            assert item["attributes"]["muted"] == 0
            assert item["attributes"]["scan_ids"] == []

    def test_overview_findings_severity_timeseries_with_data(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider1, provider2, *_ = providers_fixture

        # Create scan for day 1
        scan1 = Scan.objects.create(
            name="severity-over-time-scan-1",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
            completed_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        )

        # Create scan for day 3
        scan3 = Scan.objects.create(
            name="severity-over-time-scan-3",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
            completed_at=datetime(2024, 1, 3, 12, 0, 0, tzinfo=timezone.utc),
        )

        # Create DailySeveritySummary for day 1
        DailySeveritySummary.objects.create(
            tenant=tenant,
            provider=provider1,
            scan=scan1,
            date=date(2024, 1, 1),
            critical=10,
            high=20,
            medium=30,
            low=40,
            informational=50,
            muted=5,
        )

        # Create DailySeveritySummary for day 3
        DailySeveritySummary.objects.create(
            tenant=tenant,
            provider=provider1,
            scan=scan3,
            date=date(2024, 1, 3),
            critical=15,
            high=25,
            medium=35,
            low=45,
            informational=55,
            muted=10,
        )

        response = authenticated_client.get(
            reverse("overview-findings_severity_timeseries"),
            {
                "filter[date_from]": "2024-01-01",
                "filter[date_to]": "2024-01-03",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 3

        # Day 1 - actual data (id is the date)
        assert data[0]["id"] == "2024-01-01"
        assert data[0]["attributes"]["critical"] == 10
        assert data[0]["attributes"]["high"] == 20
        assert data[0]["attributes"]["scan_ids"] == [str(scan1.id)]

        # Day 2 - fill forward from day 1 (no data for this day)
        assert data[1]["id"] == "2024-01-02"
        assert data[1]["attributes"]["critical"] == 10
        assert data[1]["attributes"]["high"] == 20
        assert data[1]["attributes"]["scan_ids"] == [str(scan1.id)]

        # Day 3 - actual data
        assert data[2]["id"] == "2024-01-03"
        assert data[2]["attributes"]["critical"] == 15
        assert data[2]["attributes"]["high"] == 25
        assert data[2]["attributes"]["scan_ids"] == [str(scan3.id)]

    def test_overview_findings_severity_timeseries_aggregates_providers(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider1, provider2, *_ = providers_fixture

        # Same day, different providers
        scan1 = Scan.objects.create(
            name="severity-over-time-scan-p1",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
            completed_at=datetime(2024, 2, 1, 12, 0, 0, tzinfo=timezone.utc),
        )
        scan2 = Scan.objects.create(
            name="severity-over-time-scan-p2",
            provider=provider2,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
            completed_at=datetime(2024, 2, 1, 14, 0, 0, tzinfo=timezone.utc),
        )

        # Create DailySeveritySummary for provider1
        DailySeveritySummary.objects.create(
            tenant=tenant,
            provider=provider1,
            scan=scan1,
            date=date(2024, 2, 1),
            critical=10,
            high=20,
            medium=30,
            low=40,
            informational=50,
            muted=5,
        )

        # Create DailySeveritySummary for provider2
        DailySeveritySummary.objects.create(
            tenant=tenant,
            provider=provider2,
            scan=scan2,
            date=date(2024, 2, 1),
            critical=5,
            high=10,
            medium=15,
            low=20,
            informational=25,
            muted=3,
        )

        response = authenticated_client.get(
            reverse("overview-findings_severity_timeseries"),
            {
                "filter[date_from]": "2024-02-01",
                "filter[date_to]": "2024-02-01",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1

        # Should aggregate both providers
        assert data[0]["attributes"]["critical"] == 15  # 10 + 5
        assert data[0]["attributes"]["high"] == 30  # 20 + 10
        assert data[0]["attributes"]["medium"] == 45  # 30 + 15
        assert data[0]["attributes"]["low"] == 60  # 40 + 20
        assert data[0]["attributes"]["informational"] == 75  # 50 + 25
        assert data[0]["attributes"]["muted"] == 8  # 5 + 3
        # scan_ids should contain both scans (order may vary)
        assert set(data[0]["attributes"]["scan_ids"]) == {str(scan1.id), str(scan2.id)}

    def test_overview_findings_severity_timeseries_provider_filter(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider1, provider2, *_ = providers_fixture

        scan1 = Scan.objects.create(
            name="severity-over-time-filter-scan-p1",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
            completed_at=datetime(2024, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
        )
        scan2 = Scan.objects.create(
            name="severity-over-time-filter-scan-p2",
            provider=provider2,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
            completed_at=datetime(2024, 3, 1, 14, 0, 0, tzinfo=timezone.utc),
        )

        # Provider 1 - critical=100
        DailySeveritySummary.objects.create(
            tenant=tenant,
            provider=provider1,
            scan=scan1,
            date=date(2024, 3, 1),
            critical=100,
            high=0,
            medium=0,
            low=0,
            informational=0,
            muted=0,
        )

        # Provider 2 - critical=50
        DailySeveritySummary.objects.create(
            tenant=tenant,
            provider=provider2,
            scan=scan2,
            date=date(2024, 3, 1),
            critical=50,
            high=0,
            medium=0,
            low=0,
            informational=0,
            muted=0,
        )

        # Filter by provider1 only
        response = authenticated_client.get(
            reverse("overview-findings_severity_timeseries"),
            {
                "filter[date_from]": "2024-03-01",
                "filter[date_to]": "2024-03-01",
                "filter[provider_id]": str(provider1.id),
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["attributes"]["critical"] == 100  # Only provider1
        assert data[0]["attributes"]["scan_ids"] == [str(scan1.id)]

    def test_overview_attack_surface_no_data(self, authenticated_client):
        response = authenticated_client.get(reverse("overview-attack-surface"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 4
        for item in data:
            assert item["attributes"]["total_findings"] == 0
            assert item["attributes"]["failed_findings"] == 0
            assert item["attributes"]["muted_failed_findings"] == 0

    def test_overview_attack_surface_with_data(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        create_attack_surface_overview,
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        scan = Scan.objects.create(
            name="attack-surface-scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        create_attack_surface_overview(
            tenant,
            scan,
            AttackSurfaceOverview.AttackSurfaceTypeChoices.INTERNET_EXPOSED,
            total=20,
            failed=10,
            muted_failed=3,
        )
        create_attack_surface_overview(
            tenant,
            scan,
            AttackSurfaceOverview.AttackSurfaceTypeChoices.SECRETS,
            total=15,
            failed=8,
            muted_failed=2,
        )

        response = authenticated_client.get(reverse("overview-attack-surface"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 4

        results_by_type = {item["id"]: item["attributes"] for item in data}
        assert results_by_type["internet-exposed"]["total_findings"] == 20
        assert results_by_type["internet-exposed"]["failed_findings"] == 10
        assert results_by_type["secrets"]["total_findings"] == 15
        assert results_by_type["secrets"]["failed_findings"] == 8
        assert results_by_type["privilege-escalation"]["total_findings"] == 0
        assert results_by_type["ec2-imdsv1"]["total_findings"] == 0

    def test_overview_attack_surface_provider_filter(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        create_attack_surface_overview,
    ):
        tenant = tenants_fixture[0]
        provider1, provider2, *_ = providers_fixture

        scan1 = Scan.objects.create(
            name="attack-surface-scan-1",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )
        scan2 = Scan.objects.create(
            name="attack-surface-scan-2",
            provider=provider2,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        create_attack_surface_overview(
            tenant,
            scan1,
            AttackSurfaceOverview.AttackSurfaceTypeChoices.INTERNET_EXPOSED,
            total=10,
            failed=5,
            muted_failed=1,
        )
        create_attack_surface_overview(
            tenant,
            scan2,
            AttackSurfaceOverview.AttackSurfaceTypeChoices.INTERNET_EXPOSED,
            total=20,
            failed=15,
            muted_failed=3,
        )

        response = authenticated_client.get(
            reverse("overview-attack-surface"),
            {"filter[provider_id]": str(provider1.id)},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        results_by_type = {item["id"]: item["attributes"] for item in data}
        assert results_by_type["internet-exposed"]["total_findings"] == 10
        assert results_by_type["internet-exposed"]["failed_findings"] == 5

    def test_overview_services_region_filter(
        self, authenticated_client, scan_summaries_fixture
    ):
        response = authenticated_client.get(
            reverse("overview-services"),
            {"filter[region]": "region1"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 2
        service_ids = {item["id"] for item in data}
        assert service_ids == {"service1", "service2"}

    def test_overview_services_provider_type_filter(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        aws_provider, _, gcp_provider, *_ = providers_fixture

        aws_scan = Scan.objects.create(
            name="aws-scan",
            provider=aws_provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )
        gcp_scan = Scan.objects.create(
            name="gcp-scan",
            provider=gcp_provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        ScanSummary.objects.create(
            tenant=tenant,
            scan=aws_scan,
            check_id="aws-check",
            service="aws-service",
            severity="high",
            region="us-east-1",
            _pass=5,
            fail=2,
            muted=1,
            total=8,
        )
        ScanSummary.objects.create(
            tenant=tenant,
            scan=gcp_scan,
            check_id="gcp-check",
            service="gcp-service",
            severity="medium",
            region="us-central1",
            _pass=3,
            fail=1,
            muted=0,
            total=4,
        )

        response = authenticated_client.get(
            reverse("overview-services"),
            {"filter[provider_type]": "aws"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        service_ids = [item["id"] for item in data]
        assert "aws-service" in service_ids
        assert "gcp-service" not in service_ids

    @pytest.mark.parametrize(
        "status_filter,field_to_check",
        [
            ("FAIL", "fail"),
            ("PASS", "_pass"),
        ],
    )
    def test_overview_findings_severity_status_filter(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        status_filter,
        field_to_check,
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        scan = Scan.objects.create(
            name="status-filter-scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        ScanSummary.objects.create(
            tenant=tenant,
            scan=scan,
            check_id="status-check-high",
            service="service-a",
            severity="high",
            region="us-east-1",
            _pass=10,
            fail=5,
            muted=3,
            total=18,
        )
        ScanSummary.objects.create(
            tenant=tenant,
            scan=scan,
            check_id="status-check-medium",
            service="service-a",
            severity="medium",
            region="us-east-1",
            _pass=8,
            fail=2,
            muted=1,
            total=11,
        )

        response = authenticated_client.get(
            reverse("overview-findings_severity"),
            {
                "filter[provider_id]": str(provider.id),
                "filter[status]": status_filter,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        attrs = response.json()["data"]["attributes"]
        if status_filter == "FAIL":
            assert attrs["high"] == 5
            assert attrs["medium"] == 2
        else:
            assert attrs["high"] == 10
            assert attrs["medium"] == 8

    def test_overview_threatscore_compliance_id_filter(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        scan = self._create_scan(tenant, provider, "compliance-filter-scan")

        self._create_threatscore_snapshot(
            tenant,
            scan,
            provider,
            compliance_id="prowler_threatscore_aws",
            overall_score="75.00",
            score_delta="2.00",
            section_scores={"1. IAM": "70.00"},
            critical_requirements=[],
            total_requirements=50,
            passed_requirements=35,
            failed_requirements=15,
            manual_requirements=0,
            total_findings=30,
            passed_findings=20,
            failed_findings=10,
        )
        self._create_threatscore_snapshot(
            tenant,
            scan,
            provider,
            compliance_id="cis_1.4_aws",
            overall_score="65.00",
            score_delta="1.00",
            section_scores={"1. IAM": "60.00"},
            critical_requirements=[],
            total_requirements=40,
            passed_requirements=25,
            failed_requirements=15,
            manual_requirements=0,
            total_findings=25,
            passed_findings=15,
            failed_findings=10,
        )

        response = authenticated_client.get(
            reverse("overview-threatscore"),
            {"filter[compliance_id]": "prowler_threatscore_aws"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["attributes"]["overall_score"] == "75.00"
        assert data[0]["attributes"]["compliance_id"] == "prowler_threatscore_aws"

    def test_overview_threatscore_provider_type_filter(
        self, authenticated_client, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        aws_provider, _, gcp_provider, *_ = providers_fixture

        aws_scan = self._create_scan(tenant, aws_provider, "aws-threatscore-scan")
        gcp_scan = self._create_scan(tenant, gcp_provider, "gcp-threatscore-scan")

        self._create_threatscore_snapshot(
            tenant,
            aws_scan,
            aws_provider,
            compliance_id="prowler_threatscore_aws",
            overall_score="80.00",
            score_delta="3.00",
            section_scores={"1. IAM": "75.00"},
            critical_requirements=[],
            total_requirements=60,
            passed_requirements=45,
            failed_requirements=15,
            manual_requirements=0,
            total_findings=40,
            passed_findings=30,
            failed_findings=10,
        )
        self._create_threatscore_snapshot(
            tenant,
            gcp_scan,
            gcp_provider,
            compliance_id="prowler_threatscore_gcp",
            overall_score="70.00",
            score_delta="2.00",
            section_scores={"1. IAM": "65.00"},
            critical_requirements=[],
            total_requirements=50,
            passed_requirements=35,
            failed_requirements=15,
            manual_requirements=0,
            total_findings=35,
            passed_findings=25,
            failed_findings=10,
        )

        response = authenticated_client.get(
            reverse("overview-threatscore"),
            {"filter[provider_type]": "aws"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["attributes"]["overall_score"] == "80.00"

    def test_overview_categories_no_data(self, authenticated_client):
        response = authenticated_client.get(reverse("overview-categories"))
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"] == []

    def test_overview_categories_aggregates_by_category_with_severity(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        create_scan_category_summary,
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        scan = Scan.objects.create(
            name="categories-scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        create_scan_category_summary(
            tenant,
            scan,
            "iam",
            "high",
            total_findings=20,
            failed_findings=10,
            new_failed_findings=5,
        )
        create_scan_category_summary(
            tenant,
            scan,
            "iam",
            "medium",
            total_findings=15,
            failed_findings=8,
            new_failed_findings=3,
        )
        create_scan_category_summary(
            tenant,
            scan,
            "encryption",
            "critical",
            total_findings=5,
            failed_findings=2,
            new_failed_findings=1,
        )

        response = authenticated_client.get(reverse("overview-categories"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 2

        results_by_category = {item["id"]: item["attributes"] for item in data}

        assert results_by_category["iam"]["total_findings"] == 35
        assert results_by_category["iam"]["failed_findings"] == 18
        assert results_by_category["iam"]["new_failed_findings"] == 8
        assert results_by_category["iam"]["severity"]["high"] == 10
        assert results_by_category["iam"]["severity"]["medium"] == 8
        assert results_by_category["iam"]["severity"]["critical"] == 0

        assert results_by_category["encryption"]["total_findings"] == 5
        assert results_by_category["encryption"]["failed_findings"] == 2
        assert results_by_category["encryption"]["severity"]["critical"] == 2

    @pytest.mark.parametrize(
        "filter_key,filter_value_fn,expected_total,expected_failed",
        [
            ("filter[provider_id]", lambda p1, _: str(p1.id), 10, 5),
            ("filter[provider_type]", lambda *_: "aws", 10, 5),
            ("filter[provider_type__in]", lambda *_: "aws,gcp", 30, 20),
        ],
    )
    def test_overview_categories_filters(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        create_scan_category_summary,
        filter_key,
        filter_value_fn,
        expected_total,
        expected_failed,
    ):
        tenant = tenants_fixture[0]
        provider1, _, gcp_provider, *_ = providers_fixture

        scan1 = Scan.objects.create(
            name="categories-scan-1",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )
        scan2 = Scan.objects.create(
            name="categories-scan-2",
            provider=gcp_provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        create_scan_category_summary(
            tenant, scan1, "iam", "high", total_findings=10, failed_findings=5
        )
        create_scan_category_summary(
            tenant, scan2, "iam", "high", total_findings=20, failed_findings=15
        )

        response = authenticated_client.get(
            reverse("overview-categories"),
            {filter_key: filter_value_fn(provider1, gcp_provider)},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["attributes"]["total_findings"] == expected_total
        assert data[0]["attributes"]["failed_findings"] == expected_failed

    def test_overview_categories_category_filter(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        create_scan_category_summary,
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        scan = Scan.objects.create(
            name="category-filter-scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        create_scan_category_summary(
            tenant, scan, "iam", "high", total_findings=10, failed_findings=5
        )
        create_scan_category_summary(
            tenant, scan, "encryption", "medium", total_findings=20, failed_findings=8
        )
        create_scan_category_summary(
            tenant, scan, "logging", "low", total_findings=15, failed_findings=3
        )

        response = authenticated_client.get(
            reverse("overview-categories"),
            {"filter[category__in]": "iam,encryption"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        category_ids = {item["id"] for item in data}
        assert category_ids == {"iam", "encryption"}

    def test_overview_categories_aggregates_multiple_providers(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        create_scan_category_summary,
    ):
        tenant = tenants_fixture[0]
        provider1, provider2, *_ = providers_fixture

        scan1 = Scan.objects.create(
            name="multi-provider-scan-1",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )
        scan2 = Scan.objects.create(
            name="multi-provider-scan-2",
            provider=provider2,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        create_scan_category_summary(
            tenant,
            scan1,
            "iam",
            "high",
            total_findings=10,
            failed_findings=5,
            new_failed_findings=2,
        )
        create_scan_category_summary(
            tenant,
            scan2,
            "iam",
            "high",
            total_findings=15,
            failed_findings=8,
            new_failed_findings=3,
        )

        response = authenticated_client.get(reverse("overview-categories"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["id"] == "iam"
        assert data[0]["attributes"]["total_findings"] == 25
        assert data[0]["attributes"]["failed_findings"] == 13
        assert data[0]["attributes"]["new_failed_findings"] == 5

    def test_overview_groups_no_data(self, authenticated_client):
        response = authenticated_client.get(reverse("overview-resource-groups"))
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"] == []

    def test_overview_groups_aggregates_by_group_with_severity(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        create_scan_resource_group_summary,
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        scan = Scan.objects.create(
            name="resource-groups-scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        # resources_count is group-level (same for all severities within a group)
        create_scan_resource_group_summary(
            tenant,
            scan,
            "storage",
            "high",
            total_findings=20,
            failed_findings=10,
            new_failed_findings=5,
            resources_count=8,
        )
        create_scan_resource_group_summary(
            tenant,
            scan,
            "storage",
            "medium",
            total_findings=15,
            failed_findings=7,
            new_failed_findings=3,
            resources_count=8,  # Same as high - group-level count
        )
        create_scan_resource_group_summary(
            tenant,
            scan,
            "security",
            "critical",
            total_findings=10,
            failed_findings=8,
            new_failed_findings=2,
            resources_count=4,
        )

        response = authenticated_client.get(reverse("overview-resource-groups"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 2

        storage_data = next(d for d in data if d["id"] == "storage")
        security_data = next(d for d in data if d["id"] == "security")

        assert storage_data["attributes"]["total_findings"] == 35
        assert storage_data["attributes"]["failed_findings"] == 17
        assert storage_data["attributes"]["new_failed_findings"] == 8
        assert (
            storage_data["attributes"]["resources_count"] == 8
        )  # Group-level, not sum
        assert security_data["attributes"]["total_findings"] == 10
        assert security_data["attributes"]["failed_findings"] == 8
        assert security_data["attributes"]["resources_count"] == 4

    @pytest.mark.parametrize(
        "filter_key,filter_value_fn,expected_total,expected_failed",
        [
            ("filter[provider_id]", lambda p1, p2: str(p1.id), 10, 5),
            ("filter[provider_id__in]", lambda p1, p2: f"{p1.id},{p2.id}", 25, 12),
            ("filter[provider_type]", lambda p1, p2: "aws", 10, 5),
            ("filter[provider_type__in]", lambda p1, p2: "aws,gcp", 25, 12),
        ],
    )
    def test_overview_groups_provider_filters(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        create_scan_resource_group_summary,
        filter_key,
        filter_value_fn,
        expected_total,
        expected_failed,
    ):
        tenant = tenants_fixture[0]
        provider1 = providers_fixture[0]  # AWS
        gcp_provider = providers_fixture[2]  # GCP

        scan1 = Scan.objects.create(
            name="aws-rg-scan",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )
        scan2 = Scan.objects.create(
            name="gcp-rg-scan",
            provider=gcp_provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        create_scan_resource_group_summary(
            tenant, scan1, "storage", "high", total_findings=10, failed_findings=5
        )
        create_scan_resource_group_summary(
            tenant, scan2, "storage", "high", total_findings=15, failed_findings=7
        )

        response = authenticated_client.get(
            reverse("overview-resource-groups"),
            {filter_key: filter_value_fn(provider1, gcp_provider)},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["attributes"]["total_findings"] == expected_total
        assert data[0]["attributes"]["failed_findings"] == expected_failed

    def test_overview_groups_group_filter(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        create_scan_resource_group_summary,
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        scan = Scan.objects.create(
            name="rg-filter-scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        create_scan_resource_group_summary(
            tenant, scan, "storage", "high", total_findings=10, failed_findings=5
        )
        create_scan_resource_group_summary(
            tenant, scan, "compute", "medium", total_findings=20, failed_findings=8
        )
        create_scan_resource_group_summary(
            tenant, scan, "security", "low", total_findings=15, failed_findings=3
        )

        response = authenticated_client.get(
            reverse("overview-resource-groups"),
            {"filter[resource_group__in]": "storage,compute"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        group_ids = {item["id"] for item in data}
        assert group_ids == {"storage", "compute"}

    def test_overview_groups_aggregates_multiple_providers(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        create_scan_resource_group_summary,
    ):
        tenant = tenants_fixture[0]
        provider1, provider2, *_ = providers_fixture

        scan1 = Scan.objects.create(
            name="multi-provider-rg-scan-1",
            provider=provider1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )
        scan2 = Scan.objects.create(
            name="multi-provider-rg-scan-2",
            provider=provider2,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant=tenant,
        )

        create_scan_resource_group_summary(
            tenant,
            scan1,
            "storage",
            "high",
            total_findings=10,
            failed_findings=5,
            new_failed_findings=2,
            resources_count=4,
        )
        create_scan_resource_group_summary(
            tenant,
            scan2,
            "storage",
            "high",
            total_findings=15,
            failed_findings=8,
            new_failed_findings=3,
            resources_count=6,
        )

        response = authenticated_client.get(reverse("overview-resource-groups"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["id"] == "storage"
        assert data[0]["attributes"]["total_findings"] == 25
        assert data[0]["attributes"]["failed_findings"] == 13
        assert data[0]["attributes"]["new_failed_findings"] == 5
        assert data[0]["attributes"]["resources_count"] == 10

    def test_compliance_watchlist_no_filters_uses_tenant_summary(
        self, authenticated_client, tenant_compliance_summary_fixture
    ):
        response = authenticated_client.get(reverse("overview-compliance-watchlist"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]

        assert len(data) == 2

        by_id = {item["id"]: item["attributes"] for item in data}
        assert "aws_cis_2.0" in by_id
        assert by_id["aws_cis_2.0"]["requirements_passed"] == 1
        assert by_id["aws_cis_2.0"]["requirements_failed"] == 2
        assert by_id["aws_cis_2.0"]["requirements_manual"] == 1
        assert by_id["aws_cis_2.0"]["total_requirements"] == 4

        assert "gdpr_aws" in by_id
        assert by_id["gdpr_aws"]["requirements_passed"] == 5
        assert by_id["gdpr_aws"]["requirements_failed"] == 0
        assert by_id["gdpr_aws"]["total_requirements"] == 7

    def test_compliance_watchlist_with_provider_filter_uses_provider_scores(
        self,
        authenticated_client,
        provider_compliance_scores_fixture,
        providers_fixture,
    ):
        provider1 = providers_fixture[0]
        url = f"{reverse('overview-compliance-watchlist')}?filter[provider_id]={provider1.id}"
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]

        assert len(data) == 2
        by_id = {item["id"]: item["attributes"] for item in data}

        assert by_id["aws_cis_2.0"]["requirements_passed"] == 1
        assert by_id["aws_cis_2.0"]["requirements_failed"] == 1
        assert by_id["aws_cis_2.0"]["requirements_manual"] == 1
        assert by_id["aws_cis_2.0"]["total_requirements"] == 3

    def test_compliance_watchlist_fail_dominant_logic(
        self, authenticated_client, provider_compliance_scores_fixture
    ):
        response = authenticated_client.get(
            f"{reverse('overview-compliance-watchlist')}?filter[provider_type]=aws"
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]

        by_id = {item["id"]: item["attributes"] for item in data}
        aws_cis = by_id["aws_cis_2.0"]

        assert aws_cis["requirements_failed"] == 2
        assert aws_cis["requirements_passed"] == 0
        assert aws_cis["requirements_manual"] == 1
        assert aws_cis["total_requirements"] == 3

    def test_compliance_watchlist_provider_id_in_filter(
        self,
        authenticated_client,
        provider_compliance_scores_fixture,
        providers_fixture,
    ):
        provider1, provider2, *_ = providers_fixture
        url = (
            f"{reverse('overview-compliance-watchlist')}"
            f"?filter[provider_id__in]={provider1.id},{provider2.id}"
        )
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) >= 1

    def test_compliance_watchlist_empty_result(self, authenticated_client):
        response = authenticated_client.get(reverse("overview-compliance-watchlist"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert data == []

    @pytest.mark.parametrize(
        "invalid_provider_type",
        ["invalid", "not_a_provider", "AWS", "awss"],
    )
    def test_compliance_watchlist_invalid_provider_type_filter(
        self, authenticated_client, invalid_provider_type
    ):
        url = f"{reverse('overview-compliance-watchlist')}?filter[provider_type]={invalid_provider_type}"
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_400_BAD_REQUEST


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

    @patch("tasks.beat.perform_scheduled_scan_task.apply_async")
    @patch("api.v1.views.Task.objects.get")
    def test_schedule_daily_already_scheduled(
        self,
        mock_task_get,
        mock_apply_async,
        authenticated_client,
        providers_fixture,
        tasks_fixture,
    ):
        provider, *_ = providers_fixture
        prowler_task = tasks_fixture[0]
        mock_task_get.return_value = prowler_task
        mock_apply_async.return_value.id = prowler_task.id
        json_payload = {
            "provider_id": str(provider.id),
        }
        response = authenticated_client.post(
            reverse("schedule-daily"), data=json_payload, format="json"
        )
        assert response.status_code == status.HTTP_202_ACCEPTED

        response = authenticated_client.post(
            reverse("schedule-daily"), data=json_payload, format="json"
        )
        assert response.status_code == status.HTTP_409_CONFLICT


@pytest.mark.django_db
class TestIntegrationViewSet:
    def test_integrations_list(self, authenticated_client, integrations_fixture):
        response = authenticated_client.get(reverse("integration-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(integrations_fixture)

    def test_integrations_retrieve(self, authenticated_client, integrations_fixture):
        integration1, *_ = integrations_fixture
        response = authenticated_client.get(
            reverse("integration-detail", kwargs={"pk": integration1.id}),
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["id"] == str(integration1.id)
        assert (
            response.json()["data"]["attributes"]["configuration"]
            == integration1.configuration
        )

    def test_integrations_invalid_retrieve(self, authenticated_client):
        response = authenticated_client.get(
            reverse(
                "integration-detail",
                kwargs={"pk": "f498b103-c760-4785-9a3e-e23fafbb7b02"},
            )
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "include_values, expected_resources",
        [
            ("providers", ["providers"]),
        ],
    )
    def test_integrations_list_include(
        self,
        include_values,
        expected_resources,
        authenticated_client,
        integrations_fixture,
    ):
        response = authenticated_client.get(
            reverse("integration-list"), {"include": include_values}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(integrations_fixture)
        assert "included" in response.json()

        included_data = response.json()["included"]
        for expected_type in expected_resources:
            assert any(
                d.get("type") == expected_type for d in included_data
            ), f"Expected type '{expected_type}' not found in included data"

    @pytest.mark.parametrize(
        "integration_type, configuration, credentials",
        [
            # Amazon S3 - AWS credentials
            (
                Integration.IntegrationChoices.AMAZON_S3,
                {
                    "bucket_name": "bucket-name",
                    "output_directory": "output-directory",
                },
                {
                    "role_arn": "arn:aws",
                    "external_id": "external-id",
                },
            ),
            # Amazon S3 - No credentials (AWS self-hosted)
            (
                Integration.IntegrationChoices.AMAZON_S3,
                {
                    "bucket_name": "bucket-name",
                    "output_directory": "output-directory",
                },
                {},
            ),
        ],
    )
    def test_integrations_create_valid(
        self,
        authenticated_client,
        providers_fixture,
        integration_type,
        configuration,
        credentials,
    ):
        provider = Provider.objects.first()

        data = {
            "data": {
                "type": "integrations",
                "attributes": {
                    "integration_type": integration_type,
                    "configuration": configuration,
                    "credentials": credentials,
                    "enabled": True,
                },
                "relationships": {
                    "providers": {
                        "data": [{"type": "providers", "id": str(provider.id)}]
                    }
                },
            }
        }
        response = authenticated_client.post(
            reverse("integration-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Integration.objects.count() == 1
        integration = Integration.objects.first()
        assert integration.configuration == data["data"]["attributes"]["configuration"]
        assert integration.enabled == data["data"]["attributes"]["enabled"]
        assert (
            integration.integration_type
            == data["data"]["attributes"]["integration_type"]
        )
        assert "credentials" not in response.json()["data"]["attributes"]
        assert (
            str(provider.id)
            == data["data"]["relationships"]["providers"]["data"][0]["id"]
        )

    def test_integrations_create_valid_jira(
        self,
        authenticated_client,
    ):
        """Jira integrations are special"""
        data = {
            "data": {
                "type": "integrations",
                "attributes": {
                    "integration_type": Integration.IntegrationChoices.JIRA,
                    "configuration": {},
                    "credentials": {
                        "domain": "prowlerdomain",
                        "api_token": "this-is-an-api-token-for-jira-that-works-for-sure",
                        "user_mail": "testing@prowler.com",
                    },
                    "enabled": True,
                },
            }
        }
        response = authenticated_client.post(
            reverse("integration-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Integration.objects.count() == 1
        integration = Integration.objects.first()
        integration_configuration = response.json()["data"]["attributes"][
            "configuration"
        ]
        assert "projects" in integration_configuration
        assert "issue_types" in integration_configuration
        assert "domain" in integration_configuration
        assert integration.enabled == data["data"]["attributes"]["enabled"]
        assert (
            integration.integration_type
            == data["data"]["attributes"]["integration_type"]
        )
        assert "credentials" not in response.json()["data"]["attributes"]

    def test_integrations_create_valid_relationships(
        self,
        authenticated_client,
        providers_fixture,
    ):
        provider1, provider2, *_ = providers_fixture

        data = {
            "data": {
                "type": "integrations",
                "attributes": {
                    "integration_type": Integration.IntegrationChoices.AMAZON_S3,
                    "configuration": {
                        "bucket_name": "bucket-name",
                        "output_directory": "output-directory",
                    },
                    "credentials": {
                        "role_arn": "arn:aws",
                        "external_id": "external-id",
                    },
                },
                "relationships": {
                    "providers": {
                        "data": [
                            {"type": "providers", "id": str(provider1.id)},
                            {"type": "providers", "id": str(provider2.id)},
                        ]
                    }
                },
            }
        }
        response = authenticated_client.post(
            reverse("integration-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Integration.objects.first().providers.count() == 2

    @pytest.mark.parametrize(
        "attributes, error_code, error_pointer",
        (
            [
                (
                    {
                        "integration_type": "whatever",
                        "configuration": {
                            "bucket_name": "bucket-name",
                            "output_directory": "output-directory",
                        },
                        "credentials": {
                            "role_arn": "arn:aws",
                            "external_id": "external-id",
                        },
                    },
                    "invalid_choice",
                    "integration_type",
                ),
                (
                    {
                        "integration_type": "amazon_s3",
                        "configuration": {},
                        "credentials": {
                            "role_arn": "arn:aws",
                            "external_id": "external-id",
                        },
                    },
                    "required",
                    "bucket_name",
                ),
                (
                    {
                        "integration_type": "amazon_s3",
                        "configuration": {
                            "bucket_name": "bucket_name",
                            "output_directory": "output_directory",
                            "invalid_key": "invalid_value",
                        },
                        "credentials": {
                            "role_arn": "arn:aws",
                            "external_id": "external-id",
                        },
                    },
                    "invalid",
                    None,
                ),
                (
                    {
                        "integration_type": "amazon_s3",
                        "configuration": {
                            "bucket_name": "bucket_name",
                            "output_directory": "output_directory",
                        },
                        "credentials": {"invalid_key": "invalid_key"},
                    },
                    "invalid",
                    None,
                ),
                (
                    {
                        "integration_type": "jira",
                        "configuration": {
                            "projects": ["JIRA"],
                        },
                        "credentials": {"domain": "prowlerdomain"},
                    },
                    "invalid",
                    "configuration",
                ),
                (
                    {
                        "integration_type": "jira",
                        "credentialss": {
                            "domain": "prowlerdomain",
                            "api_token": "api-token",
                            "user_mail": "test@prowler.com",
                        },
                    },
                    "required",
                    "configuration",
                ),
                (
                    {
                        "integration_type": "jira",
                        "configuration": {},
                    },
                    "required",
                    "credentials",
                ),
                (
                    {
                        "integration_type": "jira",
                        "configuration": {},
                        "credentials": {"api_token": "api-token"},
                    },
                    "invalid",
                    "credentials",
                ),
            ]
        ),
    )
    def test_integrations_invalid_create(
        self,
        authenticated_client,
        attributes,
        error_code,
        error_pointer,
    ):
        data = {
            "data": {
                "type": "integrations",
                "attributes": attributes,
            }
        }
        response = authenticated_client.post(
            reverse("integration-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == error_code
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == f"/data/attributes/{error_pointer}"
            if error_pointer
            else "/data"
        )

    def test_integrations_partial_update(
        self, authenticated_client, integrations_fixture
    ):
        integration, *_ = integrations_fixture
        data = {
            "data": {
                "type": "integrations",
                "id": str(integration.id),
                "attributes": {
                    "credentials": {
                        "aws_access_key_id": "new_value",
                    },
                    # integration_type is `amazon_s3`
                    "configuration": {
                        "bucket_name": "new_bucket_name",
                        "output_directory": "new_output_directory",
                    },
                },
            }
        }
        response = authenticated_client.patch(
            reverse("integration-detail", kwargs={"pk": integration.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        integration.refresh_from_db()
        assert integration.credentials["aws_access_key_id"] == "new_value"
        assert integration.configuration["bucket_name"] == "new_bucket_name"
        assert integration.configuration["output_directory"] == "new_output_directory"

    def test_integrations_partial_update_relationships(
        self, authenticated_client, integrations_fixture
    ):
        integration, *_ = integrations_fixture
        data = {
            "data": {
                "type": "integrations",
                "id": str(integration.id),
                "attributes": {
                    "credentials": {
                        "aws_access_key_id": "new_value",
                    },
                    # integration_type is `amazon_s3`
                    "configuration": {
                        "bucket_name": "new_bucket_name",
                        "output_directory": "new_output_directory",
                    },
                },
                "relationships": {"providers": {"data": []}},
            }
        }

        assert integration.providers.count() > 0
        response = authenticated_client.patch(
            reverse("integration-detail", kwargs={"pk": integration.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        integration.refresh_from_db()
        assert integration.providers.count() == 0

    def test_integrations_partial_update_invalid_content_type(
        self, authenticated_client, integrations_fixture
    ):
        integration, *_ = integrations_fixture
        response = authenticated_client.patch(
            reverse("integration-detail", kwargs={"pk": integration.id}),
            data={},
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_integrations_partial_update_invalid_content(
        self, authenticated_client, integrations_fixture
    ):
        integration, *_ = integrations_fixture
        data = {
            "data": {
                "type": "integrations",
                "id": str(integration.id),
                "attributes": {"invalid_config": "value"},
            }
        }
        response = authenticated_client.patch(
            reverse("integration-detail", kwargs={"pk": integration.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_integrations_delete(
        self,
        authenticated_client,
        integrations_fixture,
    ):
        integration, *_ = integrations_fixture
        response = authenticated_client.delete(
            reverse("integration-detail", kwargs={"pk": integration.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_integrations_delete_invalid(self, authenticated_client):
        response = authenticated_client.delete(
            reverse(
                "integration-detail",
                kwargs={"pk": "e67d0283-440f-48d1-b5f8-38d0763474f4"},
            )
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        (
            [
                ("inserted_at", TODAY, 2),
                ("inserted_at.gte", "2024-01-01", 2),
                ("inserted_at.lte", "2024-01-01", 0),
                ("integration_type", Integration.IntegrationChoices.AMAZON_S3, 2),
                ("integration_type", Integration.IntegrationChoices.SLACK, 0),
                (
                    "integration_type__in",
                    f"{Integration.IntegrationChoices.AMAZON_S3},{Integration.IntegrationChoices.SLACK}",
                    2,
                ),
            ]
        ),
    )
    def test_integrations_filters(
        self,
        authenticated_client,
        integrations_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        response = authenticated_client.get(
            reverse("integration-list"),
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
    def test_integrations_filters_invalid(self, authenticated_client, filter_name):
        response = authenticated_client.get(
            reverse("integration-list"),
            {f"filter[{filter_name}]": "whatever"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_integrations_create_duplicate_amazon_s3(
        self, authenticated_client, providers_fixture
    ):
        provider = providers_fixture[0]

        # Create first S3 integration
        data = {
            "data": {
                "type": "integrations",
                "attributes": {
                    "integration_type": Integration.IntegrationChoices.AMAZON_S3,
                    "configuration": {
                        "bucket_name": "test-bucket",
                        "output_directory": "test-output",
                    },
                    "credentials": {
                        "role_arn": "arn:aws:iam::123456789012:role/test-role",
                        "external_id": "test-external-id",
                    },
                    "enabled": True,
                },
                "relationships": {
                    "providers": {
                        "data": [{"type": "providers", "id": str(provider.id)}]
                    }
                },
            }
        }

        # First creation should succeed
        response = authenticated_client.post(
            reverse("integration-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

        # Attempt to create duplicate should return 409
        response = authenticated_client.post(
            reverse("integration-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_409_CONFLICT
        assert (
            "This integration already exists" in response.json()["errors"][0]["detail"]
        )
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/configuration"
        )

    def test_integrations_create_duplicate_jira(self, authenticated_client):
        # Create first JIRA integration
        data = {
            "data": {
                "type": "integrations",
                "attributes": {
                    "integration_type": Integration.IntegrationChoices.JIRA,
                    "configuration": {},
                    "credentials": {
                        "user_mail": "test@example.com",
                        "api_token": "test-api-token",
                        "domain": "prowlerdomain",
                    },
                    "enabled": True,
                },
            }
        }

        # First creation should succeed
        response = authenticated_client.post(
            reverse("integration-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

        # Attempt to create duplicate should return 409
        response = authenticated_client.post(
            reverse("integration-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_409_CONFLICT
        assert (
            "This integration already exists" in response.json()["errors"][0]["detail"]
        )
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/configuration"
        )

    def test_integrations_update_jira_configuration_readonly(
        self, authenticated_client
    ):
        # Create JIRA integration first
        create_data = {
            "data": {
                "type": "integrations",
                "attributes": {
                    "integration_type": Integration.IntegrationChoices.JIRA,
                    "configuration": {},
                    "credentials": {
                        "user_mail": "test@example.com",
                        "api_token": "test-api-token",
                        "domain": "initial-domain",
                    },
                    "enabled": True,
                },
            }
        }

        # Create the integration
        response = authenticated_client.post(
            reverse("integration-list"),
            data=json.dumps(create_data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        integration_id = response.json()["data"]["id"]

        # Attempt to update configuration - should be ignored/not allowed
        update_data = {
            "data": {
                "type": "integrations",
                "id": integration_id,
                "attributes": {
                    "configuration": {
                        "projects": {"NEW_PROJECT": "New Project"},
                        "issue_types": ["Epic", "Story"],
                        "domain": "malicious-domain",
                    }
                },
            }
        }

        response = authenticated_client.patch(
            reverse("integration-detail", kwargs={"pk": integration_id}),
            data=json.dumps(update_data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_integrations_update_jira_credentials_domain_reflects_in_configuration(
        self, authenticated_client
    ):
        # Create JIRA integration first
        create_data = {
            "data": {
                "type": "integrations",
                "attributes": {
                    "integration_type": Integration.IntegrationChoices.JIRA,
                    "configuration": {},
                    "credentials": {
                        "user_mail": "test@example.com",
                        "api_token": "test-api-token",
                        "domain": "original-domain",
                    },
                    "enabled": True,
                },
            }
        }

        # Create the integration
        response = authenticated_client.post(
            reverse("integration-list"),
            data=json.dumps(create_data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        integration_id = response.json()["data"]["id"]

        # Verify initial domain in configuration
        initial_integration = response.json()["data"]
        assert (
            initial_integration["attributes"]["configuration"]["domain"]
            == "original-domain"
        )

        # Update credentials with new domain
        update_data = {
            "data": {
                "type": "integrations",
                "id": integration_id,
                "attributes": {
                    "credentials": {
                        "user_mail": "updated@example.com",
                        "api_token": "updated-api-token",
                        "domain": "updated-domain",
                    }
                },
            }
        }

        response = authenticated_client.patch(
            reverse("integration-detail", kwargs={"pk": integration_id}),
            data=json.dumps(update_data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK

        # Verify the new domain is reflected in configuration
        updated_integration = response.json()["data"]
        configuration = updated_integration["attributes"]["configuration"]
        assert configuration["domain"] == "updated-domain"

        # Verify other configuration fields are preserved
        assert "projects" in configuration
        assert "issue_types" in configuration


@pytest.mark.django_db
class TestSAMLTokenValidation:
    def test_valid_token_returns_tokens(self, authenticated_client, create_test_user):
        user = create_test_user
        valid_token_data = {
            "access": "mock_access_token",
            "refresh": "mock_refresh_token",
        }
        saml_token = SAMLToken.objects.create(
            token=valid_token_data,
            user=user,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=10),
        )

        url = reverse("token-saml")
        response = authenticated_client.post(f"{url}?id={saml_token.id}")

        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"data": valid_token_data}
        assert not SAMLToken.objects.filter(id=saml_token.id).exists()

    def test_invalid_token_id_returns_404(self, authenticated_client):
        url = reverse("token-saml")
        response = authenticated_client.post(f"{url}?id={str(uuid4())}")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.json()["errors"]["detail"] == "Invalid token ID."

    def test_expired_token_returns_400(self, authenticated_client, create_test_user):
        user = create_test_user
        expired_token_data = {
            "access": "expired_access_token",
            "refresh": "expired_refresh_token",
        }
        saml_token = SAMLToken.objects.create(
            token=expired_token_data,
            user=user,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )

        url = reverse("token-saml")
        response = authenticated_client.post(f"{url}?id={saml_token.id}")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"]["detail"] == "Token expired."
        assert SAMLToken.objects.filter(id=saml_token.id).exists()

    def test_token_can_be_used_only_once(self, authenticated_client, create_test_user):
        user = create_test_user
        token_data = {
            "access": "single_use_token",
            "refresh": "single_use_refresh",
        }
        saml_token = SAMLToken.objects.create(
            token=token_data,
            user=user,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=10),
        )

        url = reverse("token-saml")

        # First use: should succeed
        response1 = authenticated_client.post(f"{url}?id={saml_token.id}")
        assert response1.status_code == status.HTTP_200_OK

        # Second use: should fail (already deleted)
        response2 = authenticated_client.post(f"{url}?id={saml_token.id}")
        assert response2.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestSAMLInitiateAPIView:
    def test_valid_email_domain_and_certificates(
        self, authenticated_client, saml_setup, monkeypatch
    ):
        monkeypatch.setenv("SAML_PUBLIC_CERT", "fake_cert")
        monkeypatch.setenv("SAML_PRIVATE_KEY", "fake_key")

        url = reverse("api_saml_initiate")
        payload = {"email_domain": saml_setup["email"]}

        response = authenticated_client.post(url, data=payload, format="json")

        assert response.status_code == status.HTTP_302_FOUND
        assert (
            reverse("saml_login", kwargs={"organization_slug": saml_setup["domain"]})
            in response.url
        )
        assert "SAMLRequest" not in response.url

    def test_invalid_email_domain(self, authenticated_client):
        url = reverse("api_saml_initiate")
        payload = {"email_domain": "user@unauthorized.com"}

        response = authenticated_client.post(url, data=payload, format="json")

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["errors"]["detail"] == "Unauthorized domain."


@pytest.mark.django_db
class TestSAMLConfigurationViewSet:
    def test_list_saml_configurations(self, authenticated_client, saml_setup):
        config = SAMLConfiguration.objects.get(
            email_domain=saml_setup["email"].split("@")[-1]
        )
        response = authenticated_client.get(reverse("saml-config-list"))
        assert response.status_code == status.HTTP_200_OK
        assert (
            response.json()["data"][0]["attributes"]["email_domain"]
            == config.email_domain
        )

    def test_retrieve_saml_configuration(self, authenticated_client, saml_setup):
        config = SAMLConfiguration.objects.get(
            email_domain=saml_setup["email"].split("@")[-1]
        )
        response = authenticated_client.get(
            reverse("saml-config-detail", kwargs={"pk": config.id})
        )
        assert response.status_code == status.HTTP_200_OK
        assert (
            response.json()["data"]["attributes"]["metadata_xml"] == config.metadata_xml
        )

    def test_create_saml_configuration(self, authenticated_client, tenants_fixture):
        payload = {
            "email_domain": "newdomain.com",
            "metadata_xml": """<?xml version='1.0' encoding='UTF-8'?>
                <md:EntityDescriptor entityID='TEST' xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata'>
                <md:IDPSSODescriptor WantAuthnRequestsSigned='false' protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>
                    <md:KeyDescriptor use='signing'>
                    <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
                        <ds:X509Data>
                        <ds:X509Certificate>TEST</ds:X509Certificate>
                        </ds:X509Data>
                    </ds:KeyInfo>
                    </md:KeyDescriptor>
                    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
                    <md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='https://TEST/sso/saml'/>
                    <md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' Location='https://TEST/sso/saml'/>
                </md:IDPSSODescriptor>
                </md:EntityDescriptor>
            """,
        }
        response = authenticated_client.post(
            reverse("saml-config-list"), data=payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert SAMLConfiguration.objects.filter(email_domain="newdomain.com").exists()

    def test_update_saml_configuration(self, authenticated_client, saml_setup):
        config = SAMLConfiguration.objects.get(
            email_domain=saml_setup["email"].split("@")[-1]
        )
        payload = {
            "data": {
                "type": "saml-configurations",
                "id": str(config.id),
                "attributes": {
                    "metadata_xml": """<?xml version='1.0' encoding='UTF-8'?>
        <md:EntityDescriptor entityID='TEST' xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata'>
        <md:IDPSSODescriptor WantAuthnRequestsSigned='false' protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>
            <md:KeyDescriptor use='signing'>
            <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
                <ds:X509Data>
                <ds:X509Certificate>TEST2</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
            </md:KeyDescriptor>
            <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
            <md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='https://TEST/sso/saml'/>
            <md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' Location='https://TEST/sso/saml'/>
        </md:IDPSSODescriptor>
        </md:EntityDescriptor>
        """
                },
            }
        }
        response = authenticated_client.patch(
            reverse("saml-config-detail", kwargs={"pk": config.id}),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        config.refresh_from_db()
        assert (
            config.metadata_xml.strip()
            == payload["data"]["attributes"]["metadata_xml"].strip()
        )

    def test_delete_saml_configuration(self, authenticated_client, saml_setup):
        config = SAMLConfiguration.objects.get(
            email_domain=saml_setup["email"].split("@")[-1]
        )
        response = authenticated_client.delete(
            reverse("saml-config-detail", kwargs={"pk": config.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not SAMLConfiguration.objects.filter(id=config.id).exists()


@pytest.mark.django_db
class TestTenantFinishACSView:
    def test_dispatch_skips_if_user_not_authenticated(self, monkeypatch):
        monkeypatch.setenv("AUTH_URL", "http://localhost")
        request = RequestFactory().get(
            reverse("saml_finish_acs", kwargs={"organization_slug": "testtenant"})
        )
        request.user = type("Anonymous", (), {"is_authenticated": False})()
        request.session = {}

        with patch(
            "allauth.socialaccount.providers.saml.views.get_app_or_404"
        ) as mock_get_app:
            mock_get_app.return_value = SocialApp(
                provider="saml",
                client_id="testtenant",
                name="Test App",
                settings={},
            )

            view = TenantFinishACSView.as_view()
            response = view(request, organization_slug="testtenant")

        assert response.status_code in [200, 302]

    def test_dispatch_skips_if_social_app_not_found(self, users_fixture, monkeypatch):
        monkeypatch.setenv("AUTH_URL", "http://localhost")
        request = RequestFactory().get(
            reverse("saml_finish_acs", kwargs={"organization_slug": "testtenant"})
        )
        request.user = users_fixture[0]
        request.session = {}

        with patch(
            "allauth.socialaccount.providers.saml.views.get_app_or_404"
        ) as mock_get_app:
            mock_get_app.return_value = SocialApp(
                provider="saml",
                client_id="testtenant",
                name="Test App",
                settings={},
            )

            view = TenantFinishACSView.as_view()
            response = view(request, organization_slug="testtenant")

        assert isinstance(response, JsonResponse) or response.status_code in [200, 302]

    def test_dispatch_sets_user_profile_and_assigns_role_and_creates_token(
        self, create_test_user, tenants_fixture, saml_setup, settings, monkeypatch
    ):
        monkeypatch.setenv("SAML_SSO_CALLBACK_URL", "http://localhost/sso-complete")
        user = create_test_user
        original_name = user.name
        original_company = user.company_name
        user.company_name = "testing_company"
        user.is_authenticate = True

        social_account = SocialAccount(
            user=user,
            provider="saml",
            extra_data={
                "firstName": ["John"],
                "lastName": ["Doe"],
                "organization": ["testing_company"],
                "userType": ["no_permissions"],
            },
        )

        request = RequestFactory().get(
            reverse("saml_finish_acs", kwargs={"organization_slug": "testtenant"})
        )
        request.user = user
        request.session = {}

        with (
            patch(
                "allauth.socialaccount.providers.saml.views.get_app_or_404"
            ) as mock_get_app_or_404,
            patch(
                "allauth.socialaccount.models.SocialApp.objects.get"
            ) as mock_socialapp_get,
            patch(
                "allauth.socialaccount.models.SocialAccount.objects.get"
            ) as mock_sa_get,
            patch("api.models.SAMLDomainIndex.objects.get") as mock_saml_domain_get,
            patch("api.models.SAMLConfiguration.objects.get") as mock_saml_config_get,
            patch("api.models.User.objects.get") as mock_user_get,
        ):
            mock_get_app_or_404.return_value = MagicMock(
                provider="saml", client_id="testtenant", name="Test App", settings={}
            )
            mock_sa_get.return_value = social_account
            mock_socialapp_get.return_value = MagicMock(provider_id="saml")
            mock_saml_domain_get.return_value = SimpleNamespace(
                tenant_id=tenants_fixture[0].id
            )
            mock_saml_config_get.return_value = MagicMock()
            mock_user_get.return_value = user

            view = TenantFinishACSView.as_view()
            response = view(request, organization_slug="testtenant")

        assert response.status_code == 302

        expected_callback_host = "localhost"
        parsed_url = urlparse(response.url)
        assert parsed_url.netloc == expected_callback_host
        query_params = parse_qs(parsed_url.query)
        assert "id" in query_params

        token_id = query_params["id"][0]
        token_obj = SAMLToken.objects.get(id=token_id)
        assert token_obj.user == user
        assert not token_obj.is_expired()

        user.refresh_from_db()
        assert user.name == "John Doe"
        assert user.company_name == "testing_company"

        role = Role.objects.using(MainRouter.admin_db).get(name="no_permissions")
        assert role.tenant == tenants_fixture[0]

        assert (
            UserRoleRelationship.objects.using(MainRouter.admin_db)
            .filter(user=user, tenant_id=tenants_fixture[0].id)
            .exists()
        )

        membership = Membership.objects.using(MainRouter.admin_db).get(
            user=user, tenant=tenants_fixture[0]
        )
        assert membership.role == Membership.RoleChoices.MEMBER
        assert membership.user == user
        assert membership.tenant == tenants_fixture[0]

        user.name = original_name
        user.company_name = original_company
        user.save()

    def test_rollback_saml_user_when_error_occurs(self, users_fixture, monkeypatch):
        """Test that a user is properly deleted when created during SAML flow and an error occurs"""
        monkeypatch.setenv("AUTH_URL", "http://localhost")

        # Create a test user to simulate one created during SAML flow
        test_user = User.objects.using(MainRouter.admin_db).create(
            email="testuser@example.com", name="Test User"
        )

        request = RequestFactory().get(
            reverse("saml_finish_acs", kwargs={"organization_slug": "testtenant"})
        )
        request.user = users_fixture[0]
        request.session = {"saml_user_created": test_user.id}

        # Force an exception to trigger rollback
        with patch(
            "allauth.socialaccount.providers.saml.views.get_app_or_404"
        ) as mock_get_app:
            mock_get_app.side_effect = Exception("Test error")

            view = TenantFinishACSView.as_view()
            response = view(request, organization_slug="testtenant")

            # Verify the user was deleted
            assert (
                not User.objects.using(MainRouter.admin_db)
                .filter(id=test_user.id)
                .exists()
            )

            # Verify session was cleaned up
            assert "saml_user_created" not in request.session

            # Verify proper redirect
            assert response.status_code == 302
            assert "sso_saml_failed=true" in response.url

    def test_dispatch_skips_role_mapping_when_single_manage_account_user(
        self,
        create_test_user,
        tenants_fixture,
        admin_role_fixture,
        saml_setup,
        settings,
        monkeypatch,
    ):
        """Test that role mapping is skipped when tenant has only one user with MANAGE_ACCOUNT role"""
        monkeypatch.setenv("SAML_SSO_CALLBACK_URL", "http://localhost/sso-complete")
        user = create_test_user
        tenant = tenants_fixture[0]

        admin_role = admin_role_fixture
        UserRoleRelationship.objects.using(MainRouter.admin_db).create(
            user=user, role=admin_role, tenant_id=tenant.id
        )

        social_account = SocialAccount(
            user=user,
            provider="saml",
            extra_data={
                "firstName": ["John"],
                "lastName": ["Doe"],
                "organization": ["testing_company"],
                "userType": ["no_permissions"],  # This should be ignored
            },
        )

        request = RequestFactory().get(
            reverse("saml_finish_acs", kwargs={"organization_slug": "testtenant"})
        )
        request.user = user
        request.session = {}

        with (
            patch(
                "allauth.socialaccount.providers.saml.views.get_app_or_404"
            ) as mock_get_app_or_404,
            patch(
                "allauth.socialaccount.models.SocialApp.objects.get"
            ) as mock_socialapp_get,
            patch(
                "allauth.socialaccount.models.SocialAccount.objects.get"
            ) as mock_sa_get,
            patch("api.models.SAMLDomainIndex.objects.get") as mock_saml_domain_get,
            patch("api.models.SAMLConfiguration.objects.get") as mock_saml_config_get,
            patch("api.models.User.objects.get") as mock_user_get,
        ):
            mock_get_app_or_404.return_value = MagicMock(
                provider="saml", client_id="testtenant", name="Test App", settings={}
            )
            mock_sa_get.return_value = social_account
            mock_socialapp_get.return_value = MagicMock(provider_id="saml")
            mock_saml_domain_get.return_value = SimpleNamespace(tenant_id=tenant.id)
            mock_saml_config_get.return_value = MagicMock()
            mock_user_get.return_value = user

            view = TenantFinishACSView.as_view()
            response = view(request, organization_slug="testtenant")

        assert response.status_code == 302

        # Verify the admin role is still assigned (not changed to no_permissions)
        assert (
            UserRoleRelationship.objects.using(MainRouter.admin_db)
            .filter(user=user, role=admin_role, tenant_id=tenant.id)
            .exists()
        )

        # Verify no_permissions role was NOT created in the database
        assert (
            not Role.objects.using(MainRouter.admin_db)
            .filter(name="no_permissions", tenant=tenant)
            .exists()
        )

        # Verify no_permissions role was NOT assigned to the user
        assert not (
            UserRoleRelationship.objects.using(MainRouter.admin_db)
            .filter(user=user, role__name="no_permissions", tenant_id=tenant.id)
            .exists()
        )

    def test_dispatch_skips_role_mapping_when_last_manage_account_user_maps_to_existing_role(
        self,
        create_test_user,
        tenants_fixture,
        admin_role_fixture,
        roles_fixture,
        saml_setup,
        settings,
        monkeypatch,
    ):
        """Test that role mapping is skipped when it would remove the last MANAGE_ACCOUNT user"""
        monkeypatch.setenv("SAML_SSO_CALLBACK_URL", "http://localhost/sso-complete")
        user = create_test_user
        tenant = tenants_fixture[0]

        admin_role = admin_role_fixture
        viewer_role = roles_fixture[3]
        UserRoleRelationship.objects.using(MainRouter.admin_db).create(
            user=user, role=admin_role, tenant_id=tenant.id
        )

        social_account = SocialAccount(
            user=user,
            provider="saml",
            extra_data={
                "firstName": ["John"],
                "lastName": ["Doe"],
                "organization": ["testing_company"],
                "userType": [viewer_role.name],
            },
        )

        request = RequestFactory().get(
            reverse("saml_finish_acs", kwargs={"organization_slug": "testtenant"})
        )
        request.user = user
        request.session = {}

        with (
            patch(
                "allauth.socialaccount.providers.saml.views.get_app_or_404"
            ) as mock_get_app_or_404,
            patch(
                "allauth.socialaccount.models.SocialApp.objects.get"
            ) as mock_socialapp_get,
            patch(
                "allauth.socialaccount.models.SocialAccount.objects.get"
            ) as mock_sa_get,
            patch("api.models.SAMLDomainIndex.objects.get") as mock_saml_domain_get,
            patch("api.models.SAMLConfiguration.objects.get") as mock_saml_config_get,
            patch("api.models.User.objects.get") as mock_user_get,
        ):
            mock_get_app_or_404.return_value = MagicMock(
                provider="saml", client_id="testtenant", name="Test App", settings={}
            )
            mock_sa_get.return_value = social_account
            mock_socialapp_get.return_value = MagicMock(provider_id="saml")
            mock_saml_domain_get.return_value = SimpleNamespace(tenant_id=tenant.id)
            mock_saml_config_get.return_value = MagicMock()
            mock_user_get.return_value = user

            view = TenantFinishACSView.as_view()
            response = view(request, organization_slug="testtenant")

        assert response.status_code == 302

        assert (
            UserRoleRelationship.objects.using(MainRouter.admin_db)
            .filter(user=user, role=admin_role, tenant_id=tenant.id)
            .exists()
        )
        assert not (
            UserRoleRelationship.objects.using(MainRouter.admin_db)
            .filter(user=user, role=viewer_role, tenant_id=tenant.id)
            .exists()
        )

    def test_dispatch_applies_role_mapping_when_multiple_manage_account_users(
        self,
        create_test_user,
        tenants_fixture,
        admin_role_fixture,
        roles_fixture,
        saml_setup,
        settings,
        monkeypatch,
    ):
        """Test that role mapping is applied when tenant has multiple users with MANAGE_ACCOUNT role"""
        monkeypatch.setenv("SAML_SSO_CALLBACK_URL", "http://localhost/sso-complete")
        user = create_test_user
        tenant = tenants_fixture[0]

        # Create a second user with manage_account=True
        second_admin = User.objects.using(MainRouter.admin_db).create(
            email="admin2@prowler.com", name="Second Admin"
        )
        admin_role = admin_role_fixture
        viewer_role = roles_fixture[3]
        UserRoleRelationship.objects.using(MainRouter.admin_db).create(
            user=user, role=admin_role, tenant_id=tenant.id
        )
        UserRoleRelationship.objects.using(MainRouter.admin_db).create(
            user=second_admin, role=admin_role, tenant_id=tenant.id
        )

        social_account = SocialAccount(
            user=user,
            provider="saml",
            extra_data={
                "firstName": ["John"],
                "lastName": ["Doe"],
                "organization": ["testing_company"],
                "userType": [viewer_role.name],  # This SHOULD be applied
            },
        )

        request = RequestFactory().get(
            reverse("saml_finish_acs", kwargs={"organization_slug": "testtenant"})
        )
        request.user = user
        request.session = {}

        with (
            patch(
                "allauth.socialaccount.providers.saml.views.get_app_or_404"
            ) as mock_get_app_or_404,
            patch(
                "allauth.socialaccount.models.SocialApp.objects.get"
            ) as mock_socialapp_get,
            patch(
                "allauth.socialaccount.models.SocialAccount.objects.get"
            ) as mock_sa_get,
            patch("api.models.SAMLDomainIndex.objects.get") as mock_saml_domain_get,
            patch("api.models.SAMLConfiguration.objects.get") as mock_saml_config_get,
            patch("api.models.User.objects.get") as mock_user_get,
        ):
            mock_get_app_or_404.return_value = MagicMock(
                provider="saml", client_id="testtenant", name="Test App", settings={}
            )
            mock_sa_get.return_value = social_account
            mock_socialapp_get.return_value = MagicMock(provider_id="saml")
            mock_saml_domain_get.return_value = SimpleNamespace(tenant_id=tenant.id)
            mock_saml_config_get.return_value = MagicMock()
            mock_user_get.return_value = user

            view = TenantFinishACSView.as_view()
            response = view(request, organization_slug="testtenant")

        assert response.status_code == 302

        # Verify the viewer role was assigned (role mapping was applied)
        assert (
            UserRoleRelationship.objects.using(MainRouter.admin_db)
            .filter(user=user, role=viewer_role, tenant_id=tenant.id)
            .exists()
        )

        # Verify the admin role was removed (replaced by viewer)
        assert not (
            UserRoleRelationship.objects.using(MainRouter.admin_db)
            .filter(user=user, role=admin_role, tenant_id=tenant.id)
            .exists()
        )

    def test_dispatch_applies_role_mapping_for_non_admin_user_with_single_admin(
        self,
        create_test_user,
        tenants_fixture,
        admin_role_fixture,
        roles_fixture,
        saml_setup,
        settings,
        monkeypatch,
    ):
        """Test that role mapping is applied for a non-admin user when a single admin exists"""
        monkeypatch.setenv("SAML_SSO_CALLBACK_URL", "http://localhost/sso-complete")
        admin_user = create_test_user
        tenant = tenants_fixture[0]
        non_admin_user = User.objects.using(MainRouter.admin_db).create(
            email="viewer@prowler.com", name="Viewer"
        )

        admin_role = admin_role_fixture
        viewer_role = roles_fixture[3]
        UserRoleRelationship.objects.using(MainRouter.admin_db).create(
            user=admin_user, role=admin_role, tenant_id=tenant.id
        )

        social_account = SocialAccount(
            user=non_admin_user,
            provider="saml",
            extra_data={
                "firstName": ["Jane"],
                "lastName": ["Doe"],
                "organization": ["testing_company"],
                "userType": [viewer_role.name],
            },
        )

        request = RequestFactory().get(
            reverse("saml_finish_acs", kwargs={"organization_slug": "testtenant"})
        )
        request.user = non_admin_user
        request.session = {}

        with (
            patch(
                "allauth.socialaccount.providers.saml.views.get_app_or_404"
            ) as mock_get_app_or_404,
            patch(
                "allauth.socialaccount.models.SocialApp.objects.get"
            ) as mock_socialapp_get,
            patch(
                "allauth.socialaccount.models.SocialAccount.objects.get"
            ) as mock_sa_get,
            patch("api.models.SAMLDomainIndex.objects.get") as mock_saml_domain_get,
            patch("api.models.SAMLConfiguration.objects.get") as mock_saml_config_get,
            patch("api.models.User.objects.get") as mock_user_get,
        ):
            mock_get_app_or_404.return_value = MagicMock(
                provider="saml", client_id="testtenant", name="Test App", settings={}
            )
            mock_sa_get.return_value = social_account
            mock_socialapp_get.return_value = MagicMock(provider_id="saml")
            mock_saml_domain_get.return_value = SimpleNamespace(tenant_id=tenant.id)
            mock_saml_config_get.return_value = MagicMock()
            mock_user_get.return_value = non_admin_user

            view = TenantFinishACSView.as_view()
            response = view(request, organization_slug="testtenant")

        assert response.status_code == 302

        assert (
            UserRoleRelationship.objects.using(MainRouter.admin_db)
            .filter(user=non_admin_user, role=viewer_role, tenant_id=tenant.id)
            .exists()
        )
        assert (
            UserRoleRelationship.objects.using(MainRouter.admin_db)
            .filter(user=admin_user, role=admin_role, tenant_id=tenant.id)
            .exists()
        )


@pytest.mark.django_db
class TestLighthouseConfigViewSet:
    @pytest.fixture
    def valid_config_payload(self):
        return {
            "data": {
                "type": "lighthouse-configurations",
                "attributes": {
                    "name": "OpenAI",
                    "api_key": "sk-fake-test-key-for-unit-testing-only",
                    "model": "gpt-4o",
                    "temperature": 0.7,
                    "max_tokens": 4000,
                    "business_context": "Test business context",
                    "is_active": True,
                },
            }
        }

    @pytest.fixture
    def invalid_config_payload(self):
        return {
            "data": {
                "type": "lighthouse-configurations",
                "attributes": {
                    "name": "T",  # Too short
                    "api_key": "invalid-key",  # Invalid format
                    "model": "invalid-model",
                    "temperature": 2.0,  # Invalid range
                    "max_tokens": -1,  # Invalid value
                },
            }
        }

    def test_lighthouse_config_list(self, authenticated_client):
        response = authenticated_client.get(reverse("lighthouseconfiguration-list"))
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"] == []

    def test_lighthouse_config_create(self, authenticated_client, valid_config_payload):
        response = authenticated_client.post(
            reverse("lighthouseconfiguration-list"),
            data=valid_config_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()["data"]
        assert (
            data["attributes"]["name"]
            == valid_config_payload["data"]["attributes"]["name"]
        )
        assert (
            data["attributes"]["model"]
            == valid_config_payload["data"]["attributes"]["model"]
        )
        assert (
            data["attributes"]["temperature"]
            == valid_config_payload["data"]["attributes"]["temperature"]
        )
        assert (
            data["attributes"]["max_tokens"]
            == valid_config_payload["data"]["attributes"]["max_tokens"]
        )
        assert (
            data["attributes"]["business_context"]
            == valid_config_payload["data"]["attributes"]["business_context"]
        )
        assert (
            data["attributes"]["is_active"]
            == valid_config_payload["data"]["attributes"]["is_active"]
        )
        # Check that API key is masked with asterisks only
        masked_api_key = data["attributes"]["api_key"]
        assert all(
            c == "*" for c in masked_api_key
        ), "API key should contain only asterisks"

    @pytest.mark.parametrize(
        "field_name, invalid_value",
        [
            ("name", "T"),  # Too short
            ("api_key", "invalid-key"),  # Invalid format
            ("model", "invalid-model"),  # Invalid model
            ("temperature", 2.0),  # Out of range
            ("max_tokens", -1),  # Invalid value
        ],
    )
    def test_lighthouse_config_create_invalid_fields(
        self, authenticated_client, valid_config_payload, field_name, invalid_value
    ):
        """Test that validation fails for various invalid field values"""
        payload = valid_config_payload.copy()
        payload["data"]["attributes"][field_name] = invalid_value

        response = authenticated_client.post(
            reverse("lighthouseconfiguration-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]

        # All field validation errors now follow the same pattern
        assert any(field_name in error["source"]["pointer"] for error in errors)

    def test_lighthouse_config_create_missing_required_fields(
        self, authenticated_client
    ):
        """Test that validation fails when required fields are missing"""
        payload = {"data": {"type": "lighthouse-configurations", "attributes": {}}}

        response = authenticated_client.post(
            reverse("lighthouseconfiguration-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        # Check for required fields
        required_fields = ["name", "api_key"]
        for field in required_fields:
            assert any(field in error["source"]["pointer"] for error in errors)

    def test_lighthouse_config_create_duplicate(
        self, authenticated_client, valid_config_payload
    ):
        # Create first config
        response = authenticated_client.post(
            reverse("lighthouseconfiguration-list"),
            data=valid_config_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_201_CREATED

        # Try to create second config for same tenant
        response = authenticated_client.post(
            reverse("lighthouseconfiguration-list"),
            data=valid_config_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            "Lighthouse configuration already exists for this tenant"
            in response.json()["errors"][0]["detail"]
        )

    def test_lighthouse_config_update(
        self, authenticated_client, lighthouse_config_fixture
    ):
        update_payload = {
            "data": {
                "type": "lighthouse-configurations",
                "id": str(lighthouse_config_fixture.id),
                "attributes": {
                    "name": "Updated Config",
                    "model": "gpt-4o-mini",
                    "temperature": 0.5,
                },
            }
        }
        response = authenticated_client.patch(
            reverse(
                "lighthouseconfiguration-detail",
                kwargs={"pk": lighthouse_config_fixture.id},
            ),
            data=update_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert data["attributes"]["name"] == "Updated Config"
        assert data["attributes"]["model"] == "gpt-4o-mini"
        assert data["attributes"]["temperature"] == 0.5

    @pytest.mark.parametrize(
        "field_name, invalid_value",
        [
            ("model", "invalid-model"),  # Invalid model name
            ("temperature", 2.5),  # Temperature too high
            ("temperature", -0.5),  # Temperature too low
            ("max_tokens", -1),  # Negative max tokens
            ("max_tokens", 100000),  # Max tokens too high
            ("name", "T"),  # Name too short
            ("api_key", "invalid-key"),  # Invalid API key format
        ],
    )
    def test_lighthouse_config_update_invalid(
        self, authenticated_client, lighthouse_config_fixture, field_name, invalid_value
    ):
        update_payload = {
            "data": {
                "type": "lighthouse-configurations",
                "id": str(lighthouse_config_fixture.id),
                "attributes": {
                    field_name: invalid_value,
                },
            }
        }
        response = authenticated_client.patch(
            reverse(
                "lighthouseconfiguration-detail",
                kwargs={"pk": lighthouse_config_fixture.id},
            ),
            data=update_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any(field_name in error["source"]["pointer"] for error in errors)

    def test_lighthouse_config_delete(
        self, authenticated_client, lighthouse_config_fixture
    ):
        config_id = lighthouse_config_fixture.id
        response = authenticated_client.delete(
            reverse("lighthouseconfiguration-detail", kwargs={"pk": config_id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify deletion by checking list endpoint returns no items
        response = authenticated_client.get(reverse("lighthouseconfiguration-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    def test_lighthouse_config_list_masked_api_key_default(
        self, authenticated_client, lighthouse_config_fixture
    ):
        """Test that list view returns all fields with masked API key by default"""
        response = authenticated_client.get(reverse("lighthouseconfiguration-list"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        config = data[0]["attributes"]

        # All fields should be present
        assert "name" in config
        assert "model" in config
        assert "temperature" in config
        assert "max_tokens" in config
        assert "business_context" in config
        assert "api_key" in config

        # API key should be masked (asterisks)
        api_key = config["api_key"]
        assert api_key.startswith("*")
        assert all(c == "*" for c in api_key)

    def test_lighthouse_config_unmasked_api_key_single_field(
        self, authenticated_client, lighthouse_config_fixture, valid_config_payload
    ):
        """Test that specifying api_key in fields param returns all fields with unmasked API key"""
        expected_api_key = valid_config_payload["data"]["attributes"]["api_key"]
        response = authenticated_client.get(
            reverse("lighthouseconfiguration-list")
            + "?fields[lighthouse-config]=api_key"
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        config = data[0]["attributes"]

        # All fields should still be present
        assert "name" in config
        assert "model" in config
        assert "temperature" in config
        assert "max_tokens" in config
        assert "business_context" in config
        assert "api_key" in config

        # API key should be unmasked
        assert config["api_key"] == expected_api_key

    @pytest.mark.parametrize(
        "sort_field, expected_count",
        [
            ("name", 1),  # Test sorting by name
            ("-inserted_at", 1),  # Test sorting by inserted_at
        ],
    )
    def test_lighthouse_config_sorting(
        self,
        authenticated_client,
        lighthouse_config_fixture,
        sort_field,
        expected_count,
    ):
        """Test sorting lighthouse configurations by various fields"""
        response = authenticated_client.get(
            reverse("lighthouseconfiguration-list") + f"?sort={sort_field}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.check_lighthouse_connection_task.delay")
    def test_lighthouse_config_connection(
        self,
        mock_lighthouse_connection,
        mock_task_get,
        authenticated_client,
        lighthouse_config_fixture,
        tasks_fixture,
    ):
        prowler_task = tasks_fixture[0]
        task_mock = Mock()
        task_mock.id = prowler_task.id
        task_mock.status = "PENDING"
        mock_lighthouse_connection.return_value = task_mock
        mock_task_get.return_value = prowler_task

        config_id = lighthouse_config_fixture.id
        assert lighthouse_config_fixture.is_active is True

        response = authenticated_client.post(
            reverse("lighthouseconfiguration-connection", kwargs={"pk": config_id})
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        mock_lighthouse_connection.assert_called_once_with(
            lighthouse_config_id=str(config_id), tenant_id=ANY
        )
        assert "Content-Location" in response.headers
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task_mock.id}"

    def test_lighthouse_config_connection_invalid_config(
        self, authenticated_client, lighthouse_config_fixture
    ):
        response = authenticated_client.post(
            reverse("lighthouseconfiguration-connection", kwargs={"pk": "random_id"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestProcessorViewSet:
    valid_mutelist_configuration = """Mutelist:
    Accounts:
      '*':
        Checks:
            iam_user_hardware_mfa_enabled:
                Regions:
                    - '*'
                Resources:
                    - '*'
    """

    def test_list_processors(self, authenticated_client, processor_fixture):
        response = authenticated_client.get(reverse("processor-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1

    def test_retrieve_processor(self, authenticated_client, processor_fixture):
        processor = processor_fixture
        response = authenticated_client.get(
            reverse("processor-detail", kwargs={"pk": processor.id})
        )
        assert response.status_code == status.HTTP_200_OK

    def test_create_processor_valid(self, authenticated_client):
        payload = {
            "data": {
                "type": "processors",
                "attributes": {
                    "processor_type": "mutelist",
                    "configuration": self.valid_mutelist_configuration,
                },
            },
        }
        response = authenticated_client.post(
            reverse("processor-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

    @pytest.mark.parametrize(
        "invalid_configuration",
        [
            None,
            "",
            "invalid configuration",
            {"invalid": "configuration"},
        ],
    )
    def test_create_processor_invalid(
        self, authenticated_client, invalid_configuration
    ):
        payload = {
            "data": {
                "type": "processors",
                "attributes": {
                    "processor_type": "mutelist",
                    "configuration": invalid_configuration,
                },
            },
        }
        response = authenticated_client.post(
            reverse("processor-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_update_processor_valid(self, authenticated_client, processor_fixture):
        processor = processor_fixture
        payload = {
            "data": {
                "type": "processors",
                "id": str(processor.id),
                "attributes": {
                    "configuration": {
                        "Mutelist": {
                            "Accounts": {
                                "1234567890": {
                                    "Checks": {
                                        "iam_user_hardware_mfa_enabled": {
                                            "Regions": ["*"],
                                            "Resources": ["*"],
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            },
        }
        response = authenticated_client.patch(
            reverse("processor-detail", kwargs={"pk": processor.id}),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        processor.refresh_from_db()
        assert (
            processor.configuration["Mutelist"]["Accounts"]["1234567890"]
            == payload["data"]["attributes"]["configuration"]["Mutelist"]["Accounts"][
                "1234567890"
            ]
        )

    @pytest.mark.parametrize(
        "invalid_configuration",
        [
            None,
            "",
            "invalid configuration",
            {"invalid": "configuration"},
        ],
    )
    def test_update_processor_invalid(
        self, authenticated_client, processor_fixture, invalid_configuration
    ):
        processor = processor_fixture
        payload = {
            "data": {
                "type": "processors",
                "id": str(processor.id),
                "attributes": {
                    "configuration": invalid_configuration,
                },
            },
        }
        response = authenticated_client.patch(
            reverse("processor-detail", kwargs={"pk": processor.id}),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_delete_processor(self, authenticated_client, processor_fixture):
        processor = processor_fixture
        response = authenticated_client.delete(
            reverse("processor-detail", kwargs={"pk": processor.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Processor.objects.filter(id=processor.id).exists()

    def test_processors_filters(self, authenticated_client, processor_fixture):
        response = authenticated_client.get(
            reverse("processor-list"),
            {"filter[processor_type]": "mutelist"},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["processor_type"] == "mutelist"

    def test_processors_filters_invalid(self, authenticated_client):
        response = authenticated_client.get(
            reverse("processor-list"),
            {"filter[processor_type]": "invalid"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_processors_create_another_with_same_type(
        self, authenticated_client, processor_fixture
    ):
        pass

        payload = {
            "data": {
                "type": "processors",
                "attributes": {
                    "processor_type": "mutelist",
                    "configuration": self.valid_mutelist_configuration,
                },
            },
        }
        response = authenticated_client.post(
            reverse("processor-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestTenantApiKeyViewSet:
    """Tests for TenantAPIKey endpoints."""

    def test_api_keys_list(self, authenticated_client, api_keys_fixture):
        """Test listing all API keys for the tenant."""
        response = authenticated_client.get(reverse("api-key-list"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == len(api_keys_fixture)

    def test_api_keys_list_empty(self, authenticated_client, tenants_fixture):
        """Test listing API keys when none exist returns empty list."""
        response = authenticated_client.get(reverse("api-key-list"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 0
        assert isinstance(data, list)

    def test_api_keys_list_default_ordering(
        self, authenticated_client, api_keys_fixture
    ):
        """Test that API keys are ordered by -created (newest first) by default."""
        response = authenticated_client.get(reverse("api-key-list"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]

        # Verify ordering by comparing inserted_at timestamps
        # (newest should be first since ordering = ["-created"])
        if len(data) >= 2:
            first_date = data[0]["attributes"]["inserted_at"]
            second_date = data[1]["attributes"]["inserted_at"]
            assert first_date >= second_date

    def test_api_keys_list_pagination_page_size(
        self, authenticated_client, api_keys_fixture
    ):
        """Test pagination with custom page size."""
        page_size = 1
        response = authenticated_client.get(
            reverse("api-key-list"), {"page[size]": page_size}
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == page_size
        assert response.json()["meta"]["pagination"]["page"] == 1
        assert response.json()["meta"]["pagination"]["pages"] == 3

    def test_api_keys_list_pagination_page_number(
        self, authenticated_client, api_keys_fixture
    ):
        """Test pagination with specific page number."""
        page_size = 1
        page_number = 2
        response = authenticated_client.get(
            reverse("api-key-list"),
            {"page[size]": page_size, "page[number]": page_number},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == page_size
        assert response.json()["meta"]["pagination"]["page"] == page_number

    def test_api_keys_list_pagination_invalid_page(self, authenticated_client):
        """Test pagination with invalid page number returns 404."""
        response = authenticated_client.get(
            reverse("api-key-list"), {"page[number]": 999}
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_api_keys_retrieve(self, authenticated_client, api_keys_fixture):
        """Test retrieving a single API key by ID."""
        api_key = api_keys_fixture[0]
        response = authenticated_client.get(
            reverse("api-key-detail", kwargs={"pk": api_key.id})
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert data["id"] == str(api_key.id)
        assert data["attributes"]["name"] == api_key.name
        assert data["attributes"]["prefix"] == api_key.prefix
        assert data["attributes"]["revoked"] == api_key.revoked
        assert "expires_at" in data["attributes"]
        assert "inserted_at" in data["attributes"]
        assert "last_used_at" in data["attributes"]
        # Verify api_key field is NOT in response (only on creation)
        assert "api_key" not in data["attributes"]

    def test_api_keys_retrieve_invalid(self, authenticated_client):
        """Test retrieving non-existent API key returns 404."""
        response = authenticated_client.get(
            reverse(
                "api-key-detail",
                kwargs={"pk": "f498b103-c760-4785-9a3e-e23fafbb7b02"},
            )
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_api_keys_retrieve_field_mapping(
        self, authenticated_client, api_keys_fixture
    ):
        """Test that field names are correctly mapped (expires_at, inserted_at)."""
        api_key = api_keys_fixture[0]
        response = authenticated_client.get(
            reverse("api-key-detail", kwargs={"pk": api_key.id})
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]["attributes"]

        # Verify field mapping: expires_at -> expiry_date
        assert "expires_at" in data
        assert "expiry_date" not in data

        # Verify field mapping: inserted_at -> created
        assert "inserted_at" in data
        assert "created" not in data

    @pytest.mark.parametrize(
        "api_key_payload",
        (
            [
                {"name": "New API Key"},
            ]
        ),
    )
    def test_api_keys_create_valid(
        self, authenticated_client, create_test_user, api_key_payload
    ):
        data = {
            "data": {
                "type": "api-keys",
                "attributes": api_key_payload,
            }
        }
        response = authenticated_client.post(
            reverse("api-key-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()["data"]
        assert "prefix" in response_data["attributes"]
        assert "api_key" in response_data["attributes"]
        assert response_data["attributes"]["api_key"] is not None
        # Verify the raw API key is returned (only on creation)
        assert (
            response_data["attributes"]["prefix"]
            in response_data["attributes"]["api_key"]
        )
        # Verify entity is set to current user
        assert response_data["relationships"]["entity"]["data"]["id"] == str(
            create_test_user.id
        )

    @pytest.mark.parametrize(
        "api_key_payload, error_pointer",
        (
            [
                (
                    {"name": "Invalid Expiry", "expires_at": "not-a-date"},
                    "expires_at",
                ),
                (
                    {"name": ""},
                    "name",
                ),
                (
                    {},
                    "name",
                ),
                (
                    {"name": "AB"},  # Too short (min length is 3)
                    "name",
                ),
            ]
        ),
    )
    def test_api_keys_create_invalid(
        self,
        authenticated_client,
        create_test_user,
        api_key_payload,
        error_pointer,
    ):
        data = {
            "data": {
                "type": "api-keys",
                "attributes": api_key_payload,
            }
        }
        response = authenticated_client.post(
            reverse("api-key-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "errors" in response.json()
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == f"/data/attributes/{error_pointer}"
        )

    def test_api_keys_create_duplicate_name(
        self, authenticated_client, api_keys_fixture
    ):
        """Test creating an API key with a duplicate name fails."""
        # Use the name of an existing API key
        existing_name = api_keys_fixture[0].name
        data = {
            "data": {
                "type": "api-keys",
                "attributes": {
                    "name": existing_name,
                },
            }
        }
        response = authenticated_client.post(
            reverse("api-key-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "errors" in response.json()
        error_detail = response.json()["errors"][0]["detail"]
        assert "already exists" in error_detail.lower()

    def test_api_keys_update_duplicate_name(
        self, authenticated_client, api_keys_fixture
    ):
        """Test updating an API key with a duplicate name fails."""
        # Get two different API keys
        first_api_key = api_keys_fixture[0]
        second_api_key = api_keys_fixture[1]

        # Try to update the second API key to have the same name as the first one
        data = {
            "data": {
                "type": "api-keys",
                "id": str(second_api_key.id),
                "attributes": {
                    "name": first_api_key.name,
                },
            }
        }
        response = authenticated_client.patch(
            reverse("api-key-detail", kwargs={"pk": second_api_key.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "errors" in response.json()
        error_detail = response.json()["errors"][0]["detail"]
        assert "already exists" in error_detail.lower()

    def test_api_keys_create_multiple_unique_prefixes(
        self, authenticated_client, api_keys_fixture
    ):
        """Test creating multiple API keys generates unique prefixes."""
        prefixes = set()
        for i in range(3):
            data = {
                "data": {
                    "type": "api-keys",
                    "attributes": {
                        "name": f"Unique Key {i}",
                    },
                }
            }
            response = authenticated_client.post(
                reverse("api-key-list"),
                data=json.dumps(data),
                content_type="application/vnd.api+json",
            )
            assert response.status_code == status.HTTP_201_CREATED
            prefix = response.json()["data"]["attributes"]["prefix"]
            prefixes.add(prefix)
        # Verify all prefixes are unique
        assert len(prefixes) == 3

    def test_api_keys_create_invalid_content_type(
        self, authenticated_client, create_test_user
    ):
        """Test creating an API key with wrong content type returns 415."""
        data = {"name": "Test Key"}
        response = authenticated_client.post(
            reverse("api-key-list"),
            data=data,
            content_type="application/json",
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_api_keys_create_malformed_json(
        self, authenticated_client, create_test_user
    ):
        """Test creating an API key with malformed JSON returns 400."""
        response = authenticated_client.post(
            reverse("api-key-list"),
            data="not valid json",
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_api_keys_create_invalid_structure(
        self, authenticated_client, create_test_user
    ):
        """Test creating an API key with invalid JSON:API structure."""
        data = {"invalid": "structure"}
        response = authenticated_client.post(
            reverse("api-key-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "errors" in response.json()

    def test_api_keys_revoke(self, authenticated_client, api_keys_fixture):
        """Test revoking an API key."""
        api_key = api_keys_fixture[0]  # Not revoked
        assert api_key.revoked is False

        response = authenticated_client.delete(
            reverse("api-key-revoke", kwargs={"pk": api_key.id})
        )
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()["data"]
        assert response_data["attributes"]["revoked"] is True

        # Verify in database
        api_key.refresh_from_db()
        assert api_key.revoked is True

    def test_api_keys_revoke_preserves_created_field(
        self, authenticated_client, api_keys_fixture
    ):
        """Test that revoking an API key preserves the created timestamp."""
        api_key = api_keys_fixture[0]  # Not revoked
        assert api_key.revoked is False

        # Record the original created timestamp
        original_created = api_key.created

        response = authenticated_client.delete(
            reverse("api-key-revoke", kwargs={"pk": api_key.id})
        )
        assert response.status_code == status.HTTP_200_OK

        # Verify in database
        api_key.refresh_from_db()
        assert api_key.revoked is True
        # Verify created field has not changed
        assert api_key.created == original_created

    def test_api_keys_revoke_already_revoked(
        self, authenticated_client, api_keys_fixture
    ):
        """Test revoking an already revoked API key returns validation error."""
        api_key = api_keys_fixture[2]  # Already revoked
        api_key.refresh_from_db()
        assert api_key.revoked is True

        response = authenticated_client.delete(
            reverse("api-key-revoke", kwargs={"pk": api_key.id})
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already revoked" in response.json()["errors"][0]["detail"]

    def test_api_keys_revoke_nonexistent(self, authenticated_client):
        """Test revoking non-existent API key returns 404."""
        response = authenticated_client.delete(
            reverse(
                "api-key-revoke",
                kwargs={"pk": "f498b103-c760-4785-9a3e-e23fafbb7b02"},
            )
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_api_keys_destroy_not_allowed(self, authenticated_client, api_keys_fixture):
        """Test that DELETE (destroy) endpoint is disabled."""
        api_key = api_keys_fixture[0]
        response = authenticated_client.delete(
            reverse("api-key-detail", kwargs={"pk": api_key.id})
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_api_keys_put_not_allowed(self, authenticated_client, api_keys_fixture):
        """Test that PUT is not allowed."""
        api_key = api_keys_fixture[0]
        data = {
            "data": {
                "type": "api-keys",
                "id": str(api_key.id),
                "attributes": {
                    "name": "Updated Name",
                },
            }
        }
        response = authenticated_client.put(
            reverse("api-key-detail", kwargs={"pk": api_key.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_min_count",
        (
            [
                ("name", "Test API Key 1", 1),
                ("name__icontains", "test", 2),
                ("revoked", "true", 1),
                ("revoked", "false", 2),
                ("inserted_at", TODAY, 1),
                ("inserted_at__gte", "2024-01-01", 3),
                ("inserted_at__lte", "2099-12-31", 3),
                ("expires_at__gte", today_after_n_days(50), 1),
            ]
        ),
    )
    def test_api_keys_filters(
        self,
        authenticated_client,
        api_keys_fixture,
        filter_name,
        filter_value,
        expected_min_count,
    ):
        response = authenticated_client.get(
            reverse("api-key-list"),
            {f"filter[{filter_name}]": filter_value},
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) >= expected_min_count

    def test_api_keys_filter_combined(self, authenticated_client, api_keys_fixture):
        """Test combining multiple filters."""
        response = authenticated_client.get(
            reverse("api-key-list"),
            {
                "filter[revoked]": "false",
                "filter[name__icontains]": "test",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert all(item["attributes"]["revoked"] is False for item in data)
        assert all("test" in item["attributes"]["name"].lower() for item in data)

    @pytest.mark.parametrize(
        "filter_name",
        (
            [
                "invalid_field",
                "nonexistent",
            ]
        ),
    )
    def test_api_keys_filters_invalid(self, authenticated_client, filter_name):
        response = authenticated_client.get(
            reverse("api-key-list"),
            {f"filter[{filter_name}]": "whatever"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_api_keys_filter_invalid_date_format(self, authenticated_client):
        """Test filtering with invalid date format returns 400."""
        response = authenticated_client.get(
            reverse("api-key-list"),
            {"filter[inserted_at]": "not-a-date"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_api_keys_filter_empty_result(self, authenticated_client, api_keys_fixture):
        """Test filter that returns no results."""
        response = authenticated_client.get(
            reverse("api-key-list"),
            {"filter[name]": "NonExistent Key Name"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 0
        assert isinstance(data, list)

    @pytest.mark.parametrize(
        "sort_field",
        (
            [
                "name",
                "prefix",
                "revoked",
                "inserted_at",
                "expires_at",
                "-name",
                "-inserted_at",
            ]
        ),
    )
    def test_api_keys_sort(self, authenticated_client, api_keys_fixture, sort_field):
        response = authenticated_client.get(
            reverse("api-key-list"), {"sort": sort_field}
        )
        assert response.status_code == status.HTTP_200_OK

    def test_api_keys_sort_invalid(self, authenticated_client):
        """Test invalid sort parameter returns 400."""
        response = authenticated_client.get(
            reverse("api-key-list"),
            {"sort": "invalid_field"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_api_keys_rbac_manage_account_required(
        self, authenticated_client_rbac_manage_users_only, api_keys_fixture
    ):
        """Test that users without MANAGE_ACCOUNT permission are denied."""
        response = authenticated_client_rbac_manage_users_only.get(
            reverse("api-key-list")
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_api_keys_rbac_manage_account_allowed(
        self, authenticated_client_rbac_manage_account, tenants_fixture
    ):
        """Test that users with MANAGE_ACCOUNT permission can access API keys."""
        response = authenticated_client_rbac_manage_account.get(reverse("api-key-list"))
        assert response.status_code == status.HTTP_200_OK

    def test_api_keys_rbac_create_requires_permission(
        self, authenticated_client_rbac_manage_users_only
    ):
        """Test that creating API keys requires MANAGE_ACCOUNT permission."""
        data = {
            "data": {
                "type": "api-keys",
                "attributes": {
                    "name": "Test Key",
                },
            }
        }
        response = authenticated_client_rbac_manage_users_only.post(
            reverse("api-key-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_api_keys_rbac_revoke_requires_permission(
        self, authenticated_client_rbac_manage_users_only, api_keys_fixture
    ):
        """Test that revoking API keys requires MANAGE_ACCOUNT permission."""
        api_key = api_keys_fixture[0]
        response = authenticated_client_rbac_manage_users_only.delete(
            reverse("api-key-revoke", kwargs={"pk": api_key.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_api_keys_tenant_isolation(
        self, authenticated_client, api_keys_fixture, tenants_fixture
    ):
        """Test that API keys are isolated by tenant (RLS enforcement)."""
        # Create a second tenant with different user

        tenant2 = Tenant.objects.create(name="Another Tenant")
        user2 = User.objects.create_user(
            name="Another User",
            email="another@example.com",
            password=TEST_PASSWORD,
        )
        Membership.objects.create(
            user=user2,
            tenant=tenant2,
            role=Membership.RoleChoices.OWNER,
        )

        # Create API key for tenant2
        TenantAPIKey.objects.create_api_key(
            name="Tenant 2 Key",
            tenant_id=tenant2.id,
            entity=user2,
        )

        # Authenticate as user from tenant 1
        response = authenticated_client.get(reverse("api-key-list"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]

        # Should only see keys from tenant 1
        assert len(data) == len(api_keys_fixture)
        assert all(item["attributes"]["name"] != "Tenant 2 Key" for item in data)

    def test_api_keys_tenant_isolation_retrieve(
        self, authenticated_client, tenants_fixture
    ):
        """Test that retrieving API key from another tenant returns 404."""
        # Create a second tenant with API key
        tenant2 = Tenant.objects.create(name="Another Tenant")
        user2 = User.objects.create_user(
            name="Another User",
            email="another2@example.com",
            password=TEST_PASSWORD,
        )
        Membership.objects.create(
            user=user2,
            tenant=tenant2,
            role=Membership.RoleChoices.OWNER,
        )

        api_key2, _ = TenantAPIKey.objects.create_api_key(
            name="Tenant 2 Key",
            tenant_id=tenant2.id,
            entity=user2,
        )

        # Try to retrieve tenant2's API key as tenant1 user
        response = authenticated_client.get(
            reverse("api-key-detail", kwargs={"pk": api_key2.id})
        )
        # Should return 404 due to RLS filtering
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_api_keys_tenant_isolation_revoke(
        self, authenticated_client, tenants_fixture
    ):
        """Test that revoking API key from another tenant returns 404."""
        # Create a second tenant with API key
        tenant2 = Tenant.objects.create(name="Another Tenant")
        user2 = User.objects.create_user(
            name="Another User",
            email="another3@example.com",
            password=TEST_PASSWORD,
        )
        Membership.objects.create(
            user=user2,
            tenant=tenant2,
            role=Membership.RoleChoices.OWNER,
        )

        api_key2, _ = TenantAPIKey.objects.create_api_key(
            name="Tenant 2 Key",
            tenant_id=tenant2.id,
            entity=user2,
        )

        # Try to revoke tenant2's API key as tenant1 user
        response = authenticated_client.delete(
            reverse("api-key-revoke", kwargs={"pk": api_key2.id})
        )
        # Should return 404 due to RLS filtering
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_api_keys_read_only_fields_on_create(
        self, authenticated_client, create_test_user
    ):
        """Test that read-only fields are ignored during creation."""
        # Note: Fields not in serializer (like 'prefix', 'revoked') will cause 400
        # So we only test that the response has correct read-only values
        data = {
            "data": {
                "type": "api-keys",
                "attributes": {
                    "name": "Test Read-Only",
                },
            }
        }
        response = authenticated_client.post(
            reverse("api-key-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()["data"]

        # Verify read-only fields have correct default/auto-generated values
        # Prefix should be auto-generated (not empty, not None)
        assert response_data["attributes"]["prefix"] is not None
        assert len(response_data["attributes"]["prefix"]) > 0

        # Revoked should be False (default)
        assert response_data["attributes"]["revoked"] is False

        # Entity should be set to current user (auto-assigned)
        assert response_data["relationships"]["entity"]["data"]["id"] == str(
            create_test_user.id
        )

    def test_api_keys_entity_relationship_included(
        self, authenticated_client, api_keys_fixture
    ):
        """Test that entity (user) relationship is included correctly."""
        api_key = api_keys_fixture[0]
        response = authenticated_client.get(
            reverse("api-key-detail", kwargs={"pk": api_key.id})
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert "entity" in data["relationships"]
        assert data["relationships"]["entity"]["data"]["type"] == "users"
        assert data["relationships"]["entity"]["data"]["id"] == str(api_key.entity.id)

    def test_api_keys_retrieve_with_entity_include(
        self, authenticated_client, api_keys_fixture
    ):
        """Test retrieving API key with ?include=entity returns user data without memberships."""
        api_key = api_keys_fixture[0]
        response = authenticated_client.get(
            reverse("api-key-detail", kwargs={"pk": api_key.id}),
            {"include": "entity"},
        )
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()

        # Verify the main data contains the entity relationship
        data = response_data["data"]
        assert "entity" in data["relationships"]
        assert data["relationships"]["entity"]["data"]["type"] == "users"
        assert data["relationships"]["entity"]["data"]["id"] == str(api_key.entity.id)

        # Verify included section exists
        assert "included" in response_data
        assert len(response_data["included"]) == 1

        # Verify included user data
        included_user = response_data["included"][0]
        assert included_user["type"] == "users"
        assert included_user["id"] == str(api_key.entity.id)

        # Refresh entity from database to get current state
        # (in case other tests modified the shared session-scoped user fixture)
        api_key.entity.refresh_from_db()

        # Verify UserIncludeSerializer fields are present
        user_attrs = included_user["attributes"]
        assert "name" in user_attrs
        assert "email" in user_attrs
        assert "company_name" in user_attrs
        assert "date_joined" in user_attrs
        assert user_attrs["name"] == api_key.entity.name
        assert user_attrs["email"] == api_key.entity.email

        # Verify memberships field is NOT included (excluded by UserIncludeSerializer)
        assert "memberships" not in user_attrs

        # Verify roles relationship is present
        assert "relationships" in included_user
        assert "roles" in included_user["relationships"]

    def test_api_keys_entity_auto_assigned_on_create(
        self, authenticated_client, create_test_user
    ):
        """Test that entity is automatically assigned to current user on creation."""
        data = {
            "data": {
                "type": "api-keys",
                "attributes": {
                    "name": "Auto Entity Key",
                },
            }
        }
        response = authenticated_client.post(
            reverse("api-key-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()["data"]

        # Entity should be set to authenticated user
        assert response_data["relationships"]["entity"]["data"]["id"] == str(
            create_test_user.id
        )

        # Verify in database
        api_key_id = response_data["id"]
        api_key = TenantAPIKey.objects.get(id=api_key_id)
        assert api_key.entity.id == create_test_user.id

    def test_api_keys_list_response_structure(
        self, authenticated_client, api_keys_fixture
    ):
        """Test that list response follows JSON:API structure."""
        response = authenticated_client.get(reverse("api-key-list"))
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()

        # Verify top-level structure
        assert "data" in response_data
        assert "meta" in response_data
        assert isinstance(response_data["data"], list)

        # Verify pagination meta
        assert "pagination" in response_data["meta"]
        assert "count" in response_data["meta"]["pagination"]
        assert "page" in response_data["meta"]["pagination"]
        assert "pages" in response_data["meta"]["pagination"]

    def test_api_keys_retrieve_response_structure(
        self, authenticated_client, api_keys_fixture
    ):
        """Test that retrieve response follows JSON:API structure."""
        api_key = api_keys_fixture[0]
        response = authenticated_client.get(
            reverse("api-key-detail", kwargs={"pk": api_key.id})
        )
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()

        # Verify top-level structure
        assert "data" in response_data
        data = response_data["data"]

        # Verify resource object structure
        assert "type" in data
        assert data["type"] == "api-keys"
        assert "id" in data
        assert "attributes" in data
        assert "relationships" in data

    def test_api_keys_create_response_structure(
        self, authenticated_client, create_test_user
    ):
        """Test that create response follows JSON:API structure."""
        data = {
            "data": {
                "type": "api-keys",
                "attributes": {
                    "name": "Structure Test Key",
                },
            }
        }
        response = authenticated_client.post(
            reverse("api-key-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify top-level structure
        assert "data" in response_data
        data = response_data["data"]

        # Verify resource object structure
        assert "type" in data
        assert data["type"] == "api-keys"
        assert "id" in data
        assert "attributes" in data
        assert "relationships" in data

        # Verify api_key is included in creation response only
        assert "api_key" in data["attributes"]
        assert data["attributes"]["api_key"] is not None

    def test_api_keys_error_response_structure(self, authenticated_client):
        """Test that error responses follow JSON:API structure."""
        response = authenticated_client.get(
            reverse(
                "api-key-detail",
                kwargs={"pk": "f498b103-c760-4785-9a3e-e23fafbb7b02"},
            )
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        response_data = response.json()

        # Verify error structure
        assert "errors" in response_data
        assert isinstance(response_data["errors"], list)
        assert len(response_data["errors"]) > 0

        # Verify error object structure
        error = response_data["errors"][0]
        assert "detail" in error or "title" in error


@pytest.mark.django_db
class TestLighthouseTenantConfigViewSet:
    """Test Lighthouse tenant configuration endpoint (singleton pattern)"""

    def test_lighthouse_tenant_config_create_via_patch(self, authenticated_client):
        """Test creating a tenant config successfully via PATCH (upsert)"""
        payload = {
            "data": {
                "type": "lighthouse-configurations",
                "attributes": {
                    "business_context": "Test business context for security analysis",
                    "default_provider": "",
                    "default_models": {},
                },
            }
        }
        response = authenticated_client.patch(
            reverse("lighthouse-configurations"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert (
            data["attributes"]["business_context"]
            == "Test business context for security analysis"
        )
        assert data["attributes"]["default_provider"] == ""
        assert data["attributes"]["default_models"] == {}

    def test_lighthouse_tenant_config_upsert_behavior(self, authenticated_client):
        """Test that PATCH creates config if not exists and updates if exists (upsert)"""
        payload = {
            "data": {
                "type": "lighthouse-configurations",
                "attributes": {
                    "business_context": "First config",
                },
            }
        }

        # First PATCH creates the config
        response = authenticated_client.patch(
            reverse("lighthouse-configurations"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_200_OK
        first_data = response.json()["data"]
        assert first_data["attributes"]["business_context"] == "First config"

        # Second PATCH updates the same config (not creating a duplicate)
        payload["data"]["attributes"]["business_context"] = "Updated config"
        response = authenticated_client.patch(
            reverse("lighthouse-configurations"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_200_OK
        second_data = response.json()["data"]
        assert second_data["attributes"]["business_context"] == "Updated config"
        # Verify it's the same config (same ID)
        assert first_data["id"] == second_data["id"]

    @patch("openai.OpenAI")
    def test_lighthouse_tenant_config_retrieve(
        self, mock_openai_client, authenticated_client, tenants_fixture
    ):
        """Test retrieving the singleton tenant config with proper provider and model validation"""

        # Mock OpenAI client and models response
        mock_models_response = Mock()
        mock_models_response.data = [
            Mock(id="gpt-4o"),
            Mock(id="gpt-4o-mini"),
            Mock(id="gpt-5"),
        ]
        mock_openai_client.return_value.models.list.return_value = mock_models_response

        # Create OpenAI provider configuration
        provider_config = LighthouseProviderConfiguration.objects.create(
            tenant_id=tenants_fixture[0].id,
            provider_type="openai",
            credentials=b'{"api_key": "sk-fake-test-key-for-unit-testing-only"}',
            is_active=True,
        )

        # Create provider models (simulating refresh)
        LighthouseProviderModels.objects.create(
            tenant_id=tenants_fixture[0].id,
            provider_configuration=provider_config,
            model_id="gpt-4o",
            default_parameters={},
        )
        LighthouseProviderModels.objects.create(
            tenant_id=tenants_fixture[0].id,
            provider_configuration=provider_config,
            model_id="gpt-4o-mini",
            default_parameters={},
        )

        # Create tenant configuration with valid provider and model
        config = LighthouseTenantConfiguration.objects.create(
            tenant_id=tenants_fixture[0].id,
            business_context="Test context",
            default_provider="openai",
            default_models={"openai": "gpt-4o"},
        )

        # Retrieve and verify the configuration
        response = authenticated_client.get(reverse("lighthouse-configurations"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert data["id"] == str(config.id)
        assert data["attributes"]["business_context"] == "Test context"
        assert data["attributes"]["default_provider"] == "openai"
        assert data["attributes"]["default_models"] == {"openai": "gpt-4o"}

    def test_lighthouse_tenant_config_retrieve_not_found(self, authenticated_client):
        """Test GET when config doesn't exist returns 404"""
        response = authenticated_client.get(reverse("lighthouse-configurations"))
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["errors"][0]["detail"].lower()

    def test_lighthouse_tenant_config_partial_update(
        self, authenticated_client, tenants_fixture
    ):
        """Test updating tenant config fields"""
        from api.models import LighthouseTenantConfiguration

        # Create config first
        config = LighthouseTenantConfiguration.objects.create(
            tenant_id=tenants_fixture[0].id,
            business_context="Original context",
            default_provider="",
            default_models={},
        )

        # Update it
        payload = {
            "data": {
                "type": "lighthouse-configurations",
                "attributes": {
                    "business_context": "Updated context for cloud security",
                },
            }
        }
        response = authenticated_client.patch(
            reverse("lighthouse-configurations"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_200_OK

        # Verify update
        config.refresh_from_db()
        assert config.business_context == "Updated context for cloud security"

    def test_lighthouse_tenant_config_update_invalid_provider(
        self, authenticated_client, tenants_fixture
    ):
        """Test validation fails when default_provider is not configured and active"""
        from api.models import LighthouseTenantConfiguration

        # Create config first
        LighthouseTenantConfiguration.objects.create(
            tenant_id=tenants_fixture[0].id,
            business_context="Test",
        )

        # Try to set invalid provider
        payload = {
            "data": {
                "type": "lighthouse-configurations",
                "attributes": {
                    "default_provider": "nonexistent-provider",
                },
            }
        }
        response = authenticated_client.patch(
            reverse("lighthouse-configurations"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "provider" in response.json()["errors"][0]["detail"].lower()

    def test_lighthouse_tenant_config_update_invalid_json_format(
        self, authenticated_client, tenants_fixture
    ):
        """Test that invalid JSON payload is rejected"""
        from api.models import LighthouseTenantConfiguration

        # Create config first
        LighthouseTenantConfiguration.objects.create(
            tenant_id=tenants_fixture[0].id,
            business_context="Test",
        )

        # Send invalid JSON
        response = authenticated_client.patch(
            reverse("lighthouse-configurations"),
            data="invalid json",
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestLighthouseProviderConfigViewSet:
    """Tests for LighthouseProviderConfiguration create validations"""

    def test_invalid_provider_type(self, authenticated_client):
        """Add invalid provider (testprovider) should error"""
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "testprovider",
                    "credentials": {"api_key": "sk-fake-test-key-1234"},
                },
            }
        }
        resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_openai_missing_credentials(self, authenticated_client):
        """OpenAI provider without credentials should error"""
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "openai",
                },
            }
        }
        resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "credentials",
        [
            {},  # empty credentials
            {"token": "sk-fake-test-key-1234"},  # wrong key name
            {"api_key": "ks-invalid-format"},  # wrong format
        ],
    )
    def test_openai_invalid_credentials(self, authenticated_client, credentials):
        """OpenAI provider with invalid credentials should error"""
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "openai",
                    "credentials": credentials,
                },
            }
        }
        resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_openai_valid_credentials_success(self, authenticated_client):
        """OpenAI provider with valid sk-xxx format should succeed"""
        valid_key = "sk-fake-abc-test-key-xyz"
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "openai",
                    "credentials": {"api_key": valid_key},
                },
            }
        }
        resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp.status_code == status.HTTP_201_CREATED
        data = resp.json()["data"]

        masked_creds = data["attributes"].get("credentials")
        assert masked_creds is not None
        assert "api_key" in masked_creds
        assert masked_creds["api_key"] == ("*" * len(valid_key))

    def test_openai_provider_duplicate_per_tenant(self, authenticated_client):
        """If an OpenAI provider exists for tenant, creating again should error"""
        valid_key = "sk-fake-dup-test-key-456"
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "openai",
                    "credentials": {"api_key": valid_key},
                },
            }
        }
        # First creation succeeds
        resp1 = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp1.status_code == status.HTTP_201_CREATED

        # Second creation should fail with validation error
        resp2 = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp2.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in str(resp2.json()).lower()

    def test_openai_patch_base_url_and_is_active(self, authenticated_client):
        """After creating, should be able to patch base_url and is_active"""
        valid_key = "sk-fake-patch-test-key-456"
        create_payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "openai",
                    "credentials": {"api_key": valid_key},
                },
            }
        }
        create_resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=create_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert create_resp.status_code == status.HTTP_201_CREATED
        provider_id = create_resp.json()["data"]["id"]

        patch_payload = {
            "data": {
                "type": "lighthouse-providers",
                "id": provider_id,
                "attributes": {
                    "base_url": "https://api.example.com/v1",
                    "is_active": False,
                },
            }
        }
        patch_resp = authenticated_client.patch(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id}),
            data=patch_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert patch_resp.status_code == status.HTTP_200_OK
        updated = patch_resp.json()["data"]["attributes"]
        assert updated["base_url"] == "https://api.example.com/v1"
        assert updated["is_active"] is False

    def test_openai_patch_invalid_credentials(self, authenticated_client):
        """PATCH with invalid credentials.api_key should error (400)"""
        valid_key = "sk-fake-ok-test-key-456"
        create_payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "openai",
                    "credentials": {"api_key": valid_key},
                },
            }
        }
        create_resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=create_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert create_resp.status_code == status.HTTP_201_CREATED
        provider_id = create_resp.json()["data"]["id"]

        # Try patch with invalid api_key format
        patch_payload = {
            "data": {
                "type": "lighthouse-providers",
                "id": provider_id,
                "attributes": {
                    "credentials": {"api_key": "ks-invalid-format"},
                },
            }
        }
        patch_resp = authenticated_client.patch(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id}),
            data=patch_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert patch_resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_openai_get_masking_and_fields_filter(self, authenticated_client):
        valid_key = "sk-fake-get-test-key-456"
        create_payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "openai",
                    "credentials": {"api_key": valid_key},
                },
            }
        }
        create_resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=create_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert create_resp.status_code == status.HTTP_201_CREATED
        provider_id = create_resp.json()["data"]["id"]

        # Default GET should return masked credentials
        get_resp = authenticated_client.get(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id})
        )
        assert get_resp.status_code == status.HTTP_200_OK
        masked = get_resp.json()["data"]["attributes"]["credentials"]["api_key"]
        assert masked == ("*" * len(valid_key))

        # Fields filter should return decrypted credentials structure
        get_full = authenticated_client.get(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id})
            + "?fields[lighthouse-providers]=credentials"
        )
        assert get_full.status_code == status.HTTP_200_OK
        creds = get_full.json()["data"]["attributes"]["credentials"]
        assert creds["api_key"] == valid_key

    def test_delete_provider_updates_tenant_defaults(
        self, authenticated_client, tenants_fixture
    ):
        """Deleting a provider config should clear tenant default_provider and its default_model entry."""

        tenant = tenants_fixture[0]

        # Create provider configuration to delete
        provider = LighthouseProviderConfiguration.objects.create(
            tenant_id=tenant.id,
            provider_type="openai",
            credentials=b'{"api_key":"sk-fake-test-key-123"}',
            is_active=True,
        )

        # Seed tenant defaults referencing the provider we will delete
        cfg = LighthouseTenantConfiguration.objects.create(
            tenant_id=tenant.id,
            business_context="Test",
            default_provider="openai",
            default_models={"openai": "gpt-4o", "other": "model-x"},
        )

        # Delete via API and validate response
        url = reverse("lighthouse-providers-detail", kwargs={"pk": str(provider.id)})
        resp = authenticated_client.delete(url)
        assert resp.status_code in (
            status.HTTP_204_NO_CONTENT,
            status.HTTP_200_OK,
        )

        # Tenant defaults should be updated
        cfg.refresh_from_db()
        assert cfg.default_provider == ""
        assert "openai" not in cfg.default_models

        # Unrelated entries should remain untouched
        assert cfg.default_models.get("other") == "model-x"

    @pytest.mark.parametrize(
        "credentials",
        [
            {},  # empty credentials
            {
                "access_key_id": "AKIAIOSFODNN7EXAMPLE"
            },  # missing secret_access_key and region
            {
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            },  # missing access_key_id and region
            {
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            },  # missing region
            {  # invalid access_key_id format (not starting with AKIA)
                "access_key_id": "ABCD0123456789ABCDEF",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
            },
            {  # invalid access_key_id format (wrong length)
                "access_key_id": "AKIAIOSFODNN7EXAMPL",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
            },
            {  # invalid secret_access_key format (wrong length)
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEK",
                "region": "us-east-1",
            },
            {  # invalid region format
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "invalid-region",
            },
            {  # invalid region format (uppercase)
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "US-EAST-1",
            },
        ],
    )
    def test_bedrock_invalid_credentials(self, authenticated_client, credentials):
        """Bedrock provider with invalid credentials should error"""
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "bedrock",
                    "credentials": credentials,
                },
            }
        }
        resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_bedrock_valid_credentials_success(self, authenticated_client):
        """Bedrock provider with valid AWS credentials should succeed and mask credentials"""
        valid_credentials = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
        }
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "bedrock",
                    "credentials": valid_credentials,
                },
            }
        }
        resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp.status_code == status.HTTP_201_CREATED
        data = resp.json()["data"]

        # Verify credentials are returned masked
        masked_creds = data["attributes"].get("credentials")
        assert masked_creds is not None
        assert "access_key_id" in masked_creds
        assert "secret_access_key" in masked_creds
        assert "region" in masked_creds
        # Verify all characters are masked with asterisks
        assert all(c == "*" for c in masked_creds["access_key_id"])
        assert all(c == "*" for c in masked_creds["secret_access_key"])

    def test_bedrock_provider_duplicate_per_tenant(self, authenticated_client):
        """Creating a second Bedrock provider for same tenant should fail"""
        valid_credentials = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-west-2",
        }
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "bedrock",
                    "credentials": valid_credentials,
                },
            }
        }
        # First creation succeeds
        resp1 = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp1.status_code == status.HTTP_201_CREATED

        # Second creation should fail with validation error
        resp2 = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp2.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in str(resp2.json()).lower()

    def test_bedrock_patch_credentials_and_fields_filter(self, authenticated_client):
        """PATCH credentials and verify fields filter returns decrypted values"""
        valid_credentials = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "eu-west-1",
        }
        create_payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "bedrock",
                    "credentials": valid_credentials,
                },
            }
        }
        create_resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=create_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert create_resp.status_code == status.HTTP_201_CREATED
        provider_id = create_resp.json()["data"]["id"]

        # Update credentials with new valid ones
        new_credentials = {
            "access_key_id": "AKIAZZZZZZZZZZZZZZZZ",
            "secret_access_key": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/==",
            "region": "ap-south-1",
        }
        patch_payload = {
            "data": {
                "type": "lighthouse-providers",
                "id": provider_id,
                "attributes": {
                    "credentials": new_credentials,
                    "is_active": False,
                },
            }
        }
        patch_resp = authenticated_client.patch(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id}),
            data=patch_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert patch_resp.status_code == status.HTTP_200_OK
        updated = patch_resp.json()["data"]["attributes"]
        assert updated["is_active"] is False

        # Default GET should return masked credentials
        get_resp = authenticated_client.get(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id})
        )
        assert get_resp.status_code == status.HTTP_200_OK
        masked = get_resp.json()["data"]["attributes"]["credentials"]
        assert all(c == "*" for c in masked["access_key_id"])
        assert all(c == "*" for c in masked["secret_access_key"])

        # Fields filter should return decrypted credentials
        get_full = authenticated_client.get(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id})
            + "?fields[lighthouse-providers]=credentials"
        )
        assert get_full.status_code == status.HTTP_200_OK
        creds = get_full.json()["data"]["attributes"]["credentials"]
        assert creds["access_key_id"] == new_credentials["access_key_id"]
        assert creds["secret_access_key"] == new_credentials["secret_access_key"]
        assert creds["region"] == new_credentials["region"]

    def test_bedrock_partial_credential_update(self, authenticated_client):
        """Test partial update of Bedrock credentials (e.g., only region)"""
        # Create provider with full credentials
        initial_credentials = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
        }
        create_payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "bedrock",
                    "credentials": initial_credentials,
                },
            }
        }
        create_resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=create_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert create_resp.status_code == status.HTTP_201_CREATED
        provider_id = create_resp.json()["data"]["id"]

        # Update only the region field
        partial_update = {
            "region": "eu-west-1",
        }
        patch_payload = {
            "data": {
                "type": "lighthouse-providers",
                "id": provider_id,
                "attributes": {
                    "credentials": partial_update,
                },
            }
        }
        patch_resp = authenticated_client.patch(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id}),
            data=patch_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert patch_resp.status_code == status.HTTP_200_OK

        # Verify credentials with fields filter - region should be updated, keys preserved
        get_full = authenticated_client.get(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id})
            + "?fields[lighthouse-providers]=credentials"
        )
        assert get_full.status_code == status.HTTP_200_OK
        creds = get_full.json()["data"]["attributes"]["credentials"]

        # Original keys should be preserved
        assert creds["access_key_id"] == initial_credentials["access_key_id"]
        assert creds["secret_access_key"] == initial_credentials["secret_access_key"]
        # Region should be updated
        assert creds["region"] == "eu-west-1"

    def test_bedrock_valid_api_key_credentials_success(self, authenticated_client):
        """Bedrock provider with valid API key + region should succeed and return masked credentials"""
        valid_api_key = "ABSKQmVkcm9ja0FQSUtleS" + ("A" * 110)
        api_credentials = {
            "api_key": valid_api_key,
            "region": "us-east-1",
        }
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "bedrock",
                    "credentials": api_credentials,
                },
            }
        }
        resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp.status_code == status.HTTP_201_CREATED
        data = resp.json()["data"]

        # Verify credentials are returned masked
        masked_creds = data["attributes"].get("credentials")
        assert masked_creds is not None
        assert "api_key" in masked_creds
        assert "region" in masked_creds
        assert all(c == "*" for c in masked_creds["api_key"])

    def test_bedrock_mixed_api_key_and_access_keys_invalid_on_create(
        self, authenticated_client
    ):
        """Bedrock provider with both API key and access keys should fail validation on create"""
        valid_api_key = "ABSKQmVkcm9ja0FQSUtleS" + ("A" * 110)
        mixed_credentials = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "api_key": valid_api_key,
            "region": "us-east-1",
        }
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "bedrock",
                    "credentials": mixed_credentials,
                },
            }
        }
        resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        error_body = str(resp.json()).lower()
        assert "either access key + secret key or api key" in error_body

    def test_bedrock_cannot_switch_from_api_key_to_access_keys_on_update(
        self, authenticated_client
    ):
        """If created with API key, switching to access keys via update should be rejected"""
        valid_api_key = "ABSKQmVkcm9ja0FQSUtleS" + ("A" * 110)
        create_payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "bedrock",
                    "credentials": {
                        "api_key": valid_api_key,
                        "region": "us-east-1",
                    },
                },
            }
        }
        create_resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=create_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert create_resp.status_code == status.HTTP_201_CREATED
        provider_id = create_resp.json()["data"]["id"]

        # Attempt to introduce access keys on update
        patch_payload = {
            "data": {
                "type": "lighthouse-providers",
                "id": provider_id,
                "attributes": {
                    "credentials": {
                        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    },
                },
            }
        }
        patch_resp = authenticated_client.patch(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id}),
            data=patch_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert patch_resp.status_code == status.HTTP_400_BAD_REQUEST
        error_body = str(patch_resp.json()).lower()
        assert "cannot change bedrock authentication method from api key" in error_body

    def test_bedrock_cannot_switch_from_access_keys_to_api_key_on_update(
        self, authenticated_client
    ):
        """If created with access keys, switching to API key via update should be rejected"""
        valid_api_key = "ABSKQmVkcm9ja0FQSUtleS" + ("A" * 110)
        initial_credentials = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
        }
        create_payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "bedrock",
                    "credentials": initial_credentials,
                },
            }
        }
        create_resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=create_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert create_resp.status_code == status.HTTP_201_CREATED
        provider_id = create_resp.json()["data"]["id"]

        # Attempt to introduce API key on update
        patch_payload = {
            "data": {
                "type": "lighthouse-providers",
                "id": provider_id,
                "attributes": {
                    "credentials": {
                        "api_key": valid_api_key,
                    },
                },
            }
        }
        patch_resp = authenticated_client.patch(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id}),
            data=patch_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert patch_resp.status_code == status.HTTP_400_BAD_REQUEST
        error_body = str(patch_resp.json()).lower()
        assert (
            "cannot change bedrock authentication method from access key" in error_body
        )

    @pytest.mark.parametrize(
        "attributes",
        [
            pytest.param(
                {
                    "provider_type": "openai_compatible",
                    "credentials": {"api_key": "compat-key"},
                },
                id="missing",
            ),
            pytest.param(
                {
                    "provider_type": "openai_compatible",
                    "credentials": {"api_key": "compat-key"},
                    "base_url": "",
                },
                id="empty",
            ),
        ],
    )
    def test_openai_compatible_missing_base_url(self, authenticated_client, attributes):
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": attributes,
            }
        }

        resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        error_detail = str(resp.json()).lower()
        assert "base_url" in error_detail

    def test_openai_compatible_invalid_credentials(self, authenticated_client):
        payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "openai_compatible",
                    "base_url": "https://compat.example/v1",
                    "credentials": {"api_key": ""},
                },
            }
        }

        resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        errors = resp.json().get("errors", [])
        assert any(
            error.get("source", {}).get("pointer")
            == "/data/attributes/credentials/api_key"
            for error in errors
        )
        assert any(
            "may not be blank" in error.get("detail", "").lower() for error in errors
        )

    def test_openai_compatible_patch_credentials_and_fields(self, authenticated_client):
        create_payload = {
            "data": {
                "type": "lighthouse-providers",
                "attributes": {
                    "provider_type": "openai_compatible",
                    "base_url": "https://compat.example/v1",
                    "credentials": {"api_key": "compat-key-123"},
                },
            }
        }

        create_resp = authenticated_client.post(
            reverse("lighthouse-providers-list"),
            data=create_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert create_resp.status_code == status.HTTP_201_CREATED
        provider_id = create_resp.json()["data"]["id"]

        updated_base_url = "https://compat.example/v2"
        updated_api_key = "compat-key-456"
        patch_payload = {
            "data": {
                "type": "lighthouse-providers",
                "id": provider_id,
                "attributes": {
                    "base_url": updated_base_url,
                    "credentials": {"api_key": updated_api_key},
                },
            }
        }

        patch_resp = authenticated_client.patch(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id}),
            data=patch_payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert patch_resp.status_code == status.HTTP_200_OK
        updated_attrs = patch_resp.json()["data"]["attributes"]
        assert updated_attrs["base_url"] == updated_base_url
        assert updated_attrs["credentials"]["api_key"] == "*" * len(updated_api_key)

        get_resp = authenticated_client.get(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id})
        )
        assert get_resp.status_code == status.HTTP_200_OK
        masked = get_resp.json()["data"]["attributes"]["credentials"]["api_key"]
        assert masked == "*" * len(updated_api_key)

        get_full = authenticated_client.get(
            reverse("lighthouse-providers-detail", kwargs={"pk": provider_id})
            + "?fields[lighthouse-providers]=credentials"
        )
        assert get_full.status_code == status.HTTP_200_OK
        creds = get_full.json()["data"]["attributes"]["credentials"]
        assert creds["api_key"] == updated_api_key


@pytest.mark.django_db
class TestMuteRuleViewSet:
    """Tests for MuteRule endpoints."""

    def test_mute_rules_list(self, authenticated_client, mute_rules_fixture):
        """Test listing all mute rules for the tenant."""
        response = authenticated_client.get(reverse("mute-rule-list"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == len(mute_rules_fixture)

    def test_mute_rules_list_empty(self, authenticated_client, tenants_fixture):
        """Test listing mute rules when none exist returns empty list."""
        response = authenticated_client.get(reverse("mute-rule-list"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 0
        assert isinstance(data, list)

    def test_mute_rules_list_default_ordering(
        self, authenticated_client, mute_rules_fixture
    ):
        """Test that mute rules are ordered by -inserted_at by default."""
        response = authenticated_client.get(reverse("mute-rule-list"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]

        if len(data) >= 2:
            first_date = data[0]["attributes"]["inserted_at"]
            second_date = data[1]["attributes"]["inserted_at"]
            assert first_date >= second_date

    def test_mute_rules_retrieve(self, authenticated_client, mute_rules_fixture):
        """Test retrieving a single mute rule by ID."""
        mute_rule = mute_rules_fixture[0]
        response = authenticated_client.get(
            reverse("mute-rule-detail", kwargs={"pk": mute_rule.id})
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert data["id"] == str(mute_rule.id)
        assert data["attributes"]["name"] == mute_rule.name
        assert data["attributes"]["reason"] == mute_rule.reason
        assert data["attributes"]["enabled"] == mute_rule.enabled
        assert "finding_uids" in data["attributes"]
        assert "inserted_at" in data["attributes"]
        assert "updated_at" in data["attributes"]

    def test_mute_rules_retrieve_invalid(self, authenticated_client):
        """Test retrieving non-existent mute rule returns 404."""
        response = authenticated_client.get(
            reverse(
                "mute-rule-detail",
                kwargs={"pk": "f498b103-c760-4785-9a3e-e23fafbb7b02"},
            )
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        (
            [
                ("name", "Test Rule 1", 1),
                ("name.icontains", "rule", 2),
                ("reason.icontains", "security", 1),
                ("enabled", True, 1),
                ("enabled", False, 1),
            ]
        ),
    )
    def test_mute_rule_filters(
        self,
        authenticated_client,
        mute_rules_fixture,
        filter_name,
        filter_value,
        expected_count,
    ):
        """Test filtering mute rules by various fields."""
        filters = {f"filter[{filter_name}]": filter_value}
        response = authenticated_client.get(reverse("mute-rule-list"), filters)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    def test_mute_rule_filter_by_created_by(
        self, authenticated_client, mute_rules_fixture, create_test_user
    ):
        """Test filtering mute rules by creator."""
        response = authenticated_client.get(
            reverse("mute-rule-list"),
            {"filter[created_by]": create_test_user.id},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 2

    def test_mute_rule_search(self, authenticated_client, mute_rules_fixture):
        """Test searching mute rules by name and reason."""
        response = authenticated_client.get(
            reverse("mute-rule-list"), {"filter[search]": "Rule 1"}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1

    @pytest.mark.parametrize(
        "sort_field, first_index",
        (
            [
                ("name", 0),
                ("-name", 1),
                ("inserted_at", 0),
                ("-inserted_at", 1),
            ]
        ),
    )
    def test_mute_rule_ordering(
        self, authenticated_client, mute_rules_fixture, sort_field, first_index
    ):
        """Test ordering mute rules by various fields."""
        response = authenticated_client.get(
            reverse("mute-rule-list"), {"sort": sort_field}
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 2
        assert data[0]["id"] == str(mute_rules_fixture[first_index].id)

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_mute_rules_create_valid(
        self,
        mock_task,
        authenticated_client,
        findings_fixture,
        create_test_user,
    ):
        """Test creating a valid mute rule."""
        finding_ids = [str(findings_fixture[0].id)]
        data = {
            "data": {
                "type": "mute-rules",
                "attributes": {
                    "name": "New Mute Rule",
                    "reason": "Security exception approved",
                    "finding_ids": finding_ids,
                },
            }
        }
        response = authenticated_client.post(
            reverse("mute-rule-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

        # Verify response contains the created mute rule
        response_data = response.json()["data"]
        assert response_data["type"] == "mute-rules"
        assert response_data["attributes"]["name"] == "New Mute Rule"
        assert response_data["attributes"]["reason"] == "Security exception approved"

        # Verify the finding was immediately muted
        from api.models import Finding

        finding = Finding.objects.get(id=findings_fixture[0].id)
        assert finding.muted is True
        assert finding.muted_at is not None
        assert finding.muted_reason == "Security exception approved"

        # Verify background task was called
        mock_task.assert_called_once()

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_mute_rules_create_converts_finding_ids_to_uids(
        self,
        mock_task,
        authenticated_client,
        findings_fixture,
    ):
        """Test that finding_ids are converted to finding UIDs."""
        finding_ids = [str(findings_fixture[0].id), str(findings_fixture[1].id)]
        data = {
            "data": {
                "type": "mute-rules",
                "attributes": {
                    "name": "UID Conversion Test",
                    "reason": "Testing UID conversion",
                    "finding_ids": finding_ids,
                },
            }
        }
        response = authenticated_client.post(
            reverse("mute-rule-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

        # Verify finding_uids contains the UIDs, not IDs
        from api.models import MuteRule

        mute_rule = MuteRule.objects.get(name="UID Conversion Test")
        expected_uids = [
            findings_fixture[0].uid,
            findings_fixture[1].uid,
        ]
        assert set(mute_rule.finding_uids) == set(expected_uids)

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_mute_rules_deduplicates_uids(
        self,
        mock_task,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        scans_fixture,
    ):
        """Test that multiple findings with same UID result in only one UID in the rule."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        shared_uid = "prowler-aws-dedupe-test-001"

        finding1 = Finding.objects.create(
            tenant=tenant,
            uid=shared_uid,
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check",
            check_metadata={"CheckId": "test_check"},
            raw_result={},
        )

        finding2 = Finding.objects.create(
            tenant=tenant,
            uid=shared_uid,
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check",
            check_metadata={"CheckId": "test_check"},
            raw_result={},
        )

        finding_ids = [str(finding1.id), str(finding2.id)]
        data = {
            "data": {
                "type": "mute-rules",
                "attributes": {
                    "name": "Dedupe Test Rule",
                    "reason": "Testing UID deduplication",
                    "finding_ids": finding_ids,
                },
            }
        }
        response = authenticated_client.post(
            reverse("mute-rule-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

        from api.models import MuteRule

        mute_rule = MuteRule.objects.get(name="Dedupe Test Rule")
        assert len(mute_rule.finding_uids) == 1
        assert mute_rule.finding_uids[0] == shared_uid

        finding1.refresh_from_db()
        finding2.refresh_from_db()
        assert finding1.muted is True
        assert finding2.muted is True

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_mute_rules_create_overlap_detection_active(
        self,
        mock_task,
        authenticated_client,
        mute_rules_fixture,
        findings_fixture,
    ):
        """Test that creating a rule with overlapping UIDs in active rule fails."""
        # mute_rules_fixture[0] is active and has findings_fixture[0] UID
        finding_ids = [str(findings_fixture[0].id)]
        data = {
            "data": {
                "type": "mute-rules",
                "attributes": {
                    "name": "Overlapping Rule",
                    "reason": "This should fail",
                    "finding_ids": finding_ids,
                },
            }
        }
        response = authenticated_client.post(
            reverse("mute-rule-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_409_CONFLICT
        assert "errors" in response.json()
        error_detail = response.json()["errors"][0]["detail"]
        assert (
            "already muted" in error_detail.lower() or "overlap" in error_detail.lower()
        )

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_mute_rules_create_no_overlap_with_inactive(
        self,
        mock_task,
        authenticated_client,
        mute_rules_fixture,
        findings_fixture,
    ):
        """Test that disabled rules don't prevent new rules with same UIDs."""
        # mute_rules_fixture[1] is disabled
        # Disable the enabled rule first
        mute_rules_fixture[0].enabled = False
        mute_rules_fixture[0].save()

        finding_ids = [str(findings_fixture[0].id)]
        data = {
            "data": {
                "type": "mute-rules",
                "attributes": {
                    "name": "Non-overlapping Rule",
                    "reason": "Inactive rules don't block",
                    "finding_ids": finding_ids,
                },
            }
        }
        response = authenticated_client.post(
            reverse("mute-rule-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED

    def test_mute_rules_create_invalid_empty_finding_ids(self, authenticated_client):
        """Test creating mute rule with empty finding_ids fails."""
        data = {
            "data": {
                "type": "mute-rules",
                "attributes": {
                    "name": "Valid",
                    "reason": "Valid",
                    "finding_ids": [],
                },
            }
        }
        response = authenticated_client.post(
            reverse("mute-rule-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "errors" in response.json()
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/finding_ids"
        )

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_mute_rules_create_invalid_finding_ids(
        self, mock_task, authenticated_client
    ):
        """Test creating mute rule with non-existent finding IDs fails."""
        data = {
            "data": {
                "type": "mute-rules",
                "attributes": {
                    "name": "Invalid Findings",
                    "reason": "This should fail",
                    "finding_ids": ["f498b103-c760-4785-9a3e-e23fafbb7b02"],
                },
            }
        }
        response = authenticated_client.post(
            reverse("mute-rule-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "errors" in response.json()

    def test_mute_rules_create_duplicate_name(
        self, authenticated_client, mute_rules_fixture
    ):
        """Test creating a mute rule with duplicate name fails."""
        existing_name = mute_rules_fixture[0].name
        data = {
            "data": {
                "type": "mute-rules",
                "attributes": {
                    "name": existing_name,
                    "reason": "Duplicate name test",
                    "finding_ids": ["f498b103-c760-4785-9a3e-e23fafbb7b02"],
                },
            }
        }
        response = authenticated_client.post(
            reverse("mute-rule-list"),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "errors" in response.json()

    def test_mute_rules_update_name(self, authenticated_client, mute_rules_fixture):
        """Test updating mute rule name."""
        mute_rule = mute_rules_fixture[0]
        data = {
            "data": {
                "type": "mute-rules",
                "id": str(mute_rule.id),
                "attributes": {
                    "name": "Updated Name",
                },
            }
        }
        response = authenticated_client.patch(
            reverse("mute-rule-detail", kwargs={"pk": mute_rule.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()["data"]
        assert response_data["attributes"]["name"] == "Updated Name"

        # Verify database was updated
        mute_rule.refresh_from_db()
        assert mute_rule.name == "Updated Name"

    def test_mute_rules_update_reason(self, authenticated_client, mute_rules_fixture):
        """Test updating mute rule reason."""
        mute_rule = mute_rules_fixture[0]
        data = {
            "data": {
                "type": "mute-rules",
                "id": str(mute_rule.id),
                "attributes": {
                    "reason": "Updated reason for muting",
                },
            }
        }
        response = authenticated_client.patch(
            reverse("mute-rule-detail", kwargs={"pk": mute_rule.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()["data"]
        assert response_data["attributes"]["reason"] == "Updated reason for muting"

        mute_rule.refresh_from_db()
        assert mute_rule.reason == "Updated reason for muting"

    def test_mute_rules_update_enabled(self, authenticated_client, mute_rules_fixture):
        """Test disabling a mute rule."""
        mute_rule = mute_rules_fixture[0]
        assert mute_rule.enabled is True

        data = {
            "data": {
                "type": "mute-rules",
                "id": str(mute_rule.id),
                "attributes": {
                    "enabled": False,
                },
            }
        }
        response = authenticated_client.patch(
            reverse("mute-rule-detail", kwargs={"pk": mute_rule.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()["data"]
        assert response_data["attributes"]["enabled"] is False

        mute_rule.refresh_from_db()
        assert mute_rule.enabled is False

    def test_mute_rules_update_duplicate_name(
        self, authenticated_client, mute_rules_fixture
    ):
        """Test updating mute rule with duplicate name fails."""
        first_rule = mute_rules_fixture[0]
        second_rule = mute_rules_fixture[1]

        data = {
            "data": {
                "type": "mute-rules",
                "id": str(second_rule.id),
                "attributes": {
                    "name": first_rule.name,
                },
            }
        }
        response = authenticated_client.patch(
            reverse("mute-rule-detail", kwargs={"pk": second_rule.id}),
            data=json.dumps(data),
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "errors" in response.json()

    def test_mute_rules_delete(self, authenticated_client, mute_rules_fixture):
        """Test deleting a mute rule."""
        mute_rule = mute_rules_fixture[0]
        response = authenticated_client.delete(
            reverse("mute-rule-detail", kwargs={"pk": mute_rule.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify rule was deleted
        from api.models import MuteRule

        assert not MuteRule.objects.filter(id=mute_rule.id).exists()

    def test_mute_rules_tenant_isolation(
        self, authenticated_client, mute_rules_fixture, tenants_fixture
    ):
        """Test that users can only access mute rules from their tenant."""
        # Create a second tenant with a mute rule
        from api.models import MuteRule, Tenant

        other_tenant = Tenant.objects.create(name="Other Tenant")
        other_rule = MuteRule.objects.create(
            tenant=other_tenant,
            name="Other Tenant Rule",
            reason="Should not be visible",
            finding_uids=["test-uid"],
        )

        # Try to access other tenant's rule
        response = authenticated_client.get(
            reverse("mute-rule-detail", kwargs={"pk": other_rule.id})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

        # List should only show current tenant's rules
        response = authenticated_client.get(reverse("mute-rule-list"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == len(mute_rules_fixture)
        for rule_data in data:
            assert rule_data["id"] != str(other_rule.id)
