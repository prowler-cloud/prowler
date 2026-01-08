# Example: API Test Fixtures (conftest.py)
# Source: api/src/backend/conftest.py

import pytest
from django.urls import reverse

from api.db_utils import rls_transaction
from api.models import Membership, Provider, Role, User, UserRoleRelationship
from api.rls import Tenant
from api.v1.serializers import TokenSerializer

TEST_USER = "dev@prowler.com"
TEST_PASSWORD = "testing_psswd"


@pytest.fixture(scope="session", autouse=True)
def create_test_user(django_db_setup, django_db_blocker):
    """Session-scoped fixture to create a test user once."""
    with django_db_blocker.unblock():
        user = User.objects.create_user(
            name="testing",
            email=TEST_USER,
            password=TEST_PASSWORD,
        )
    return user


@pytest.fixture
def tenants_fixture(create_test_user):
    """Create multiple tenants for multi-tenant testing."""
    user = create_test_user

    tenant1 = Tenant.objects.create(name="Tenant One")
    Membership.objects.create(user=user, tenant=tenant1)

    tenant2 = Tenant.objects.create(name="Tenant Two")
    Membership.objects.create(
        user=user, tenant=tenant2, role=Membership.RoleChoices.OWNER
    )

    # Tenant 3 - user is NOT a member (for isolation testing)
    tenant3 = Tenant.objects.create(name="Tenant Three")

    return tenant1, tenant2, tenant3


@pytest.fixture
def set_user_admin_roles_fixture(create_test_user, tenants_fixture):
    """Set up admin roles for test user in their tenants."""
    user = create_test_user
    for tenant in tenants_fixture[:2]:  # Only tenants user is a member of
        with rls_transaction(str(tenant.id)):
            role = Role.objects.create(
                name="admin",
                tenant_id=tenant.id,
                manage_users=True,
                manage_account=True,
                manage_billing=True,
                manage_providers=True,
                manage_integrations=True,
                manage_scans=True,
                unlimited_visibility=True,
            )
            UserRoleRelationship.objects.create(
                user=user,
                role=role,
                tenant_id=tenant.id,
            )


@pytest.fixture
def authenticated_client(
    create_test_user, tenants_fixture, set_user_admin_roles_fixture, client
):
    """APIClient with JWT authentication."""
    client.user = create_test_user
    serializer = TokenSerializer(
        data={"type": "tokens", "email": TEST_USER, "password": TEST_PASSWORD}
    )
    serializer.is_valid()
    access_token = serializer.validated_data["access"]
    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"
    return client


@pytest.fixture
def providers_fixture(tenants_fixture):
    """Create test providers in first tenant."""
    tenant, *_ = tenants_fixture
    provider1 = Provider.objects.create(
        provider="aws",
        uid="123456789012",
        alias="aws_testing_1",
        tenant_id=tenant.id,
    )
    provider2 = Provider.objects.create(
        provider="aws",
        uid="123456789013",
        alias="aws_testing_2",
        tenant_id=tenant.id,
    )
    return provider1, provider2


def get_api_tokens(
    api_client, user_email: str, user_password: str, tenant_id: str = None
) -> tuple[str, str]:
    """Helper to obtain JWT tokens for a specific tenant."""
    json_body = {
        "data": {
            "type": "tokens",
            "attributes": {
                "email": user_email,
                "password": user_password,
            },
        }
    }
    if tenant_id is not None:
        json_body["data"]["attributes"]["tenant_id"] = tenant_id

    response = api_client.post(
        reverse("token-obtain"),
        data=json_body,
        format="vnd.api+json",
    )
    return (
        response.json()["data"]["attributes"]["access"],
        response.json()["data"]["attributes"]["refresh"],
    )


def get_authorization_header(token: str) -> dict:
    """Helper to create authorization header."""
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}
