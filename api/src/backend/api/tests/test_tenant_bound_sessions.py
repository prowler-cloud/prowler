import pytest
from api.authentication import SSO_TENANT_CLAIM
from api.models import Membership, Role, User, UserRoleRelationship
from api.rls import Tenant
from api.v1.serializers import generate_tokens
from conftest import API_JSON_CONTENT_TYPE, TEST_PASSWORD, TEST_USER
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken


def _bearer(access):
    return {"Authorization": f"Bearer {access}"}


def _switch(client, tenant, headers):
    return client.post(
        reverse("token-switch"),
        data={
            "data": {
                "type": "tokens-switch-tenant",
                "attributes": {"tenant_id": str(tenant.id)},
            }
        },
        content_type=API_JSON_CONTENT_TYPE,
        headers=headers,
    )


def _patch_own_user(client, user, attributes, headers):
    return client.patch(
        reverse("user-detail", kwargs={"pk": user.id}),
        data={"data": {"type": "users", "id": str(user.id), "attributes": attributes}},
        content_type=API_JSON_CONTENT_TYPE,
        headers=headers,
    )


@pytest.mark.django_db
class TestSSOBoundSession:
    @pytest.fixture
    def bound(self, create_test_user, tenants_fixture):
        sso_tenant, other_tenant = tenants_fixture[0], tenants_fixture[1]
        tokens = generate_tokens(
            create_test_user, str(sso_tenant.id), sso_tenant_id=str(sso_tenant.id)
        )
        return tokens, sso_tenant, other_tenant

    def test_switch_to_another_tenant_is_rejected(self, bound):
        tokens, _, other_tenant = bound

        response = _switch(APIClient(), other_tenant, _bearer(tokens["access"]))

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "session-bound-to-tenant"

    def test_token_from_same_tenant_switch_stays_bound(self, bound):
        tokens, sso_tenant, other_tenant = bound
        client = APIClient()

        same_tenant = _switch(client, sso_tenant, _bearer(tokens["access"]))
        assert same_tenant.status_code == status.HTTP_200_OK
        reissued = same_tenant.json()["data"]["attributes"]["access"]

        response = _switch(client, other_tenant, _bearer(reissued))

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_refreshed_token_stays_bound(self, bound):
        tokens, _, other_tenant = bound
        client = APIClient()

        refreshed = client.post(
            reverse("token-refresh"),
            data={
                "data": {
                    "type": "tokens-refresh",
                    "attributes": {"refresh": tokens["refresh"]},
                }
            },
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert refreshed.status_code == status.HTTP_200_OK
        access = refreshed.json()["data"]["attributes"]["access"]

        response = _switch(client, other_tenant, _bearer(access))

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_own_password_change_is_rejected(self, bound, create_test_user):
        tokens, _, _ = bound

        response = _patch_own_user(
            APIClient(),
            create_test_user,
            {"password": "AnotherPassword123@"},
            _bearer(tokens["access"]),
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        create_test_user.refresh_from_db()
        assert create_test_user.check_password(TEST_PASSWORD)

    def test_own_email_change_is_rejected(self, bound, create_test_user):
        tokens, _, _ = bound

        response = _patch_own_user(
            APIClient(),
            create_test_user,
            {"email": "someone-else@example.com"},
            _bearer(tokens["access"]),
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        create_test_user.refresh_from_db()
        assert create_test_user.email == TEST_USER

    def test_own_name_change_is_allowed(self, bound, create_test_user):
        tokens, _, _ = bound

        response = _patch_own_user(
            APIClient(),
            create_test_user,
            {"name": "Renamed User"},
            _bearer(tokens["access"]),
        )

        assert response.status_code == status.HTTP_200_OK

    def test_own_account_deletion_is_rejected(self, bound, create_test_user):
        tokens, sso_tenant, _ = bound
        role = Role.objects.create(
            tenant_id=sso_tenant.id, name="admin", manage_users=True
        )
        UserRoleRelationship.objects.create(
            user=create_test_user, role=role, tenant_id=sso_tenant.id
        )

        response = APIClient().delete(
            reverse("user-detail", kwargs={"pk": create_test_user.id}),
            headers=_bearer(tokens["access"]),
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert User.objects.filter(id=create_test_user.id).exists()

    def test_other_tenant_is_not_listed(self, bound):
        tokens, sso_tenant, _ = bound

        response = APIClient().get(
            reverse("tenant-list"), headers=_bearer(tokens["access"])
        )

        assert response.status_code == status.HTTP_200_OK
        assert [t["id"] for t in response.json()["data"]] == [str(sso_tenant.id)]

    def test_other_tenant_cannot_be_renamed(self, bound, create_test_user):
        tokens, sso_tenant, other_tenant = bound
        role = Role.objects.create(
            tenant_id=sso_tenant.id, name="admin", manage_account=True
        )
        UserRoleRelationship.objects.create(
            user=create_test_user, role=role, tenant_id=sso_tenant.id
        )

        response = APIClient().patch(
            reverse("tenant-detail", kwargs={"pk": other_tenant.id}),
            data={
                "data": {
                    "type": "tenants",
                    "id": str(other_tenant.id),
                    "attributes": {"name": "renamed"},
                }
            },
            content_type=API_JSON_CONTENT_TYPE,
            headers=_bearer(tokens["access"]),
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        other_tenant.refresh_from_db()
        assert other_tenant.name != "renamed"

    def test_other_tenant_cannot_be_deleted(self, bound, create_test_user):
        tokens, sso_tenant, other_tenant = bound
        role = Role.objects.create(
            tenant_id=sso_tenant.id, name="admin", manage_account=True
        )
        UserRoleRelationship.objects.create(
            user=create_test_user, role=role, tenant_id=sso_tenant.id
        )
        Membership.objects.filter(user=create_test_user, tenant=other_tenant).update(
            role=Membership.RoleChoices.OWNER
        )

        response = APIClient().delete(
            reverse("tenant-detail", kwargs={"pk": other_tenant.id}),
            headers=_bearer(tokens["access"]),
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert Tenant.objects.filter(id=other_tenant.id).exists()

    def test_other_tenant_members_are_not_listed(self, bound):
        tokens, _, other_tenant = bound

        response = APIClient().get(
            reverse("tenant-membership-list", kwargs={"tenant_pk": other_tenant.id}),
            headers=_bearer(tokens["access"]),
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tenant_creation_is_rejected(self, bound):
        tokens, _, _ = bound

        response = APIClient().post(
            reverse("tenant-list"),
            data={"data": {"type": "tenants", "attributes": {"name": "another"}}},
            content_type=API_JSON_CONTENT_TYPE,
            headers=_bearer(tokens["access"]),
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert not Tenant.objects.filter(name="another").exists()


@pytest.mark.django_db
class TestSSOBoundSessionOfSingleTenantUser:
    @pytest.fixture
    def bound(self, tenants_fixture):
        user = User.objects.create_user(
            password="OriginalPassword123@", email="sso-only@example.com"
        )
        tenant = tenants_fixture[0]
        Membership.objects.create(user=user, tenant=tenant)
        role = Role.objects.create(tenant_id=tenant.id, name="admin", manage_users=True)
        UserRoleRelationship.objects.create(user=user, role=role, tenant_id=tenant.id)
        tokens = generate_tokens(user, str(tenant.id), sso_tenant_id=str(tenant.id))
        return tokens, user

    def test_own_password_change_is_allowed(self, bound):
        tokens, user = bound

        response = _patch_own_user(
            APIClient(),
            user,
            {"password": "AnotherPassword123@"},
            _bearer(tokens["access"]),
        )

        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.check_password("AnotherPassword123@")

    def test_own_account_deletion_is_allowed(self, bound):
        tokens, user = bound

        response = APIClient().delete(
            reverse("user-detail", kwargs={"pk": user.id}),
            headers=_bearer(tokens["access"]),
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.django_db
class TestPasswordSession:
    def test_switch_to_another_tenant_is_allowed_and_unbound(
        self, create_test_user, tenants_fixture
    ):
        tokens = generate_tokens(create_test_user, str(tenants_fixture[0].id))

        response = _switch(APIClient(), tenants_fixture[1], _bearer(tokens["access"]))

        assert response.status_code == status.HTTP_200_OK
        reissued = AccessToken(response.json()["data"]["attributes"]["access"])
        assert SSO_TENANT_CLAIM not in reissued.payload


@pytest.mark.django_db
class TestAPIKeySession:
    def test_switch_to_another_tenant_is_rejected(
        self, api_keys_fixture, tenants_fixture
    ):
        headers = {"Authorization": f"Api-Key {api_keys_fixture[0]._raw_key}"}

        response = _switch(APIClient(), tenants_fixture[1], headers)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_switch_to_its_own_tenant_is_rejected(
        self, api_keys_fixture, tenants_fixture
    ):
        headers = {"Authorization": f"Api-Key {api_keys_fixture[0]._raw_key}"}

        response = _switch(APIClient(), tenants_fixture[0], headers)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_own_password_change_is_rejected(self, api_keys_fixture, create_test_user):
        headers = {"Authorization": f"Api-Key {api_keys_fixture[0]._raw_key}"}

        response = _patch_own_user(
            APIClient(),
            create_test_user,
            {"password": "AnotherPassword123@"},
            headers,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        create_test_user.refresh_from_db()
        assert create_test_user.check_password(TEST_PASSWORD)
