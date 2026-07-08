import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from allauth.socialaccount.models import SocialLogin
from api.attack_paths import (
    AttackPathsQueryDefinition,
    AttackPathsQueryParameterDefinition,
)
from api.db_utils import rls_transaction
from api.models import (
    AttackPathsScan,
    AttackSurfaceOverview,
    ComplianceOverview,
    ComplianceRequirementOverview,
    Finding,
    Integration,
    IntegrationProviderRelationship,
    Invitation,
    LighthouseConfiguration,
    Membership,
    MuteRule,
    Processor,
    Provider,
    ProviderComplianceScore,
    ProviderGroup,
    ProviderSecret,
    Resource,
    ResourceTag,
    ResourceTagMapping,
    Role,
    SAMLConfiguration,
    SAMLDomainIndex,
    Scan,
    ScanCategorySummary,
    ScanGroupSummary,
    ScanSummary,
    StateChoices,
    StatusChoices,
    Task,
    TenantAPIKey,
    TenantComplianceSummary,
    User,
    UserRoleRelationship,
)
from api.rls import Tenant
from api.v1.serializers import TokenSerializer
from django.conf import settings
from django.db import connection as django_connection
from django.db import connections as django_connections
from django.test import Client
from django.urls import reverse
from django_celery_results.models import TaskResult
from prowler.lib.check.models import Severity
from prowler.lib.outputs.finding import Status
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken
from tasks.jobs.backfill import (
    aggregate_scan_category_summaries,
    aggregate_scan_resource_group_summaries,
    backfill_resource_scan_summaries,
)

TODAY = str(datetime.today().date())
API_JSON_CONTENT_TYPE = "application/vnd.api+json"
NO_TENANT_HTTP_STATUS = status.HTTP_401_UNAUTHORIZED
TEST_USER = "dev@prowler.com"
TEST_PASSWORD = "testing_psswd"


def _install_compliance_catalog_test_cache() -> None:
    """Memoize the heavy SDK catalog loaders for the whole test session.

    ``get_bulk_compliance_frameworks_universal`` re-reads and Pydantic-validates
    ~100 compliance JSONs (≈20 MB) and ``CheckMetadata.get_bulk`` re-reads ~1k
    check metadata files on *every* call. Production amortizes this through the
    per-process lazy caches (``PROWLER_CHECKS`` / ``PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE``)
    and ``warm_compliance_caches``, but the test suite parametrizes over every
    provider and deliberately resets the API-level caches, so the same catalogs
    were re-parsed dozens of times across the suite (≈3s/call locally, ≈19s under
    coverage in CI).

    The catalog files are immutable during a run and callers treat the parsed
    objects as read-only, so caching the result per provider is safe. This is the
    test-only equivalent of an ``lru_cache`` on the SDK functions, without
    changing SDK behavior in production.

    A second, lower-level cache memoizes ``load_compliance_framework_universal``
    **per file path**. ``get_bulk_compliance_frameworks_universal`` parses *every*
    compliance JSON and only then filters by provider, so a per-provider cache
    still re-parses all ~100 files on the first load of each provider. The
    per-path cache makes the first provider parse the files once and every other
    provider/test reuse the already-parsed ``ComplianceFramework`` objects (only
    the cheap ``listdir`` + filtering re-runs). ``_load_jsons_from_dir`` calls
    ``load_compliance_framework_universal`` as a module global, so patching the
    attribute is picked up without touching the SDK.

    Installed at conftest import time (before test modules are collected) so that
    even ``from ... import get_bulk_compliance_frameworks_universal`` bindings in
    the test modules resolve to the cached wrapper.
    """
    import prowler.lib.check.compliance_models as compliance_models
    from prowler.lib.check.models import CheckMetadata

    original_bulk_frameworks = (
        compliance_models.get_bulk_compliance_frameworks_universal
    )
    original_get_bulk = CheckMetadata.get_bulk
    original_load = compliance_models.load_compliance_framework_universal

    def cached_bulk_frameworks(provider):
        if provider not in _COMPLIANCE_FRAMEWORK_CACHE:
            _COMPLIANCE_FRAMEWORK_CACHE[provider] = original_bulk_frameworks(provider)
        return _COMPLIANCE_FRAMEWORK_CACHE[provider]

    def cached_get_bulk(provider):
        if provider not in _COMPLIANCE_CHECKS_CACHE:
            _COMPLIANCE_CHECKS_CACHE[provider] = original_get_bulk(provider)
        return _COMPLIANCE_CHECKS_CACHE[provider]

    def cached_load(path):
        if path not in _COMPLIANCE_PATH_CACHE:
            _COMPLIANCE_PATH_CACHE[path] = original_load(path)
        return _COMPLIANCE_PATH_CACHE[path]

    compliance_models.get_bulk_compliance_frameworks_universal = cached_bulk_frameworks
    compliance_models.load_compliance_framework_universal = cached_load
    CheckMetadata.get_bulk = staticmethod(cached_get_bulk)

    # ``api.compliance`` does ``from ... import get_bulk_compliance_frameworks_universal``
    # so it holds its own binding; patch it too in case it was imported first.
    import api.compliance as api_compliance

    api_compliance.get_bulk_compliance_frameworks_universal = cached_bulk_frameworks


# Module-scoped so the ``_compliance_cache_guard`` fixture below can reset them.
# Keeping them out of ``_install_compliance_catalog_test_cache``'s local scope is
# what makes the caches resettable between tests; the wrappers above close over
# these names, and the original loaders stay referenced so patched behaviour is
# still honoured.
_COMPLIANCE_FRAMEWORK_CACHE: dict[str, dict] = {}
_COMPLIANCE_CHECKS_CACHE: dict[str, dict] = {}
_COMPLIANCE_PATH_CACHE: dict[str, object] = {}


_install_compliance_catalog_test_cache()


@pytest.fixture(autouse=True)
def _compliance_cache_guard(request):
    """Reset the compliance catalog caches after any test that used ``monkeypatch``.

    The session-wide caches in ``_install_compliance_catalog_test_cache`` let the
    read-only, parametrized compliance tests parse the ~100 catalog JSONs once
    instead of dozens of times. A test that swaps a loader (or mutates a returned
    object) could otherwise leak that state into later tests through the shared
    dicts. Using ``monkeypatch`` as the opt-in signal keeps the full speed-up for
    catalog-reading tests while giving patching tests a clean slate afterwards;
    the next test simply repopulates the caches from disk.
    """
    yield
    if "monkeypatch" in request.fixturenames:
        _COMPLIANCE_FRAMEWORK_CACHE.clear()
        _COMPLIANCE_CHECKS_CACHE.clear()
        _COMPLIANCE_PATH_CACHE.clear()
        import api.compliance as api_compliance

        api_compliance.AVAILABLE_COMPLIANCE_FRAMEWORKS.clear()


def today_after_n_days(n_days: int) -> str:
    return datetime.strftime(
        datetime.today().date() + timedelta(days=n_days), "%Y-%m-%d"
    )


@pytest.fixture(scope="module")
def enforce_test_user_db_connection(django_db_setup, django_db_blocker):
    """Ensure tests use the test user for database connections."""
    test_user = "test"
    test_password = "test"

    with django_db_blocker.unblock():
        with django_connection.cursor() as cursor:
            # Required for testing purposes using APIClient
            cursor.execute(f"GRANT ALL PRIVILEGES ON django_session TO {test_user};")

        original_user = settings.DATABASES["default"]["USER"]
        original_password = settings.DATABASES["default"]["PASSWORD"]

        django_connections["default"].settings_dict["USER"] = test_user
        django_connections["default"].settings_dict["PASSWORD"] = test_password

        django_connections["default"].close()
        django_connections["default"].connect()

    yield

    with django_db_blocker.unblock():
        django_connections["default"].settings_dict["USER"] = original_user
        django_connections["default"].settings_dict["PASSWORD"] = original_password

        django_connections["default"].close()
        django_connections["default"].connect()


@pytest.fixture(autouse=True)
def disable_logging():
    logging.disable(logging.CRITICAL)


@pytest.fixture(scope="session")
def _session_test_user(django_db_setup, django_db_blocker):
    """Create the test user once per session. Internal; use create_test_user instead."""
    with django_db_blocker.unblock():
        user = User.objects.create_user(
            name="testing",
            email=TEST_USER,
            password=TEST_PASSWORD,
        )
    return user


@pytest.fixture(autouse=True)
def create_test_user(_session_test_user, django_db_blocker):
    """Re-create the session-scoped test user when a TransactionTestCase
    has truncated the users table."""
    with django_db_blocker.unblock():
        if not User.objects.filter(pk=_session_test_user.pk).exists():
            User.objects.create_user(
                id=_session_test_user.pk,
                name="testing",
                email=TEST_USER,
                password=TEST_PASSWORD,
            )
    return _session_test_user


@pytest.fixture(scope="function")
def create_test_user_rbac(django_db_setup, django_db_blocker, tenants_fixture):
    with django_db_blocker.unblock():
        user = User.objects.create_user(
            name="testing",
            email="rbac@rbac.com",
            password=TEST_PASSWORD,
        )
        tenant = tenants_fixture[0]
        Membership.objects.create(
            user=user,
            tenant=tenant,
            role=Membership.RoleChoices.OWNER,
        )
        Role.objects.create(
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
            role=Role.objects.get(name="admin"),
            tenant_id=tenant.id,
        )
    return user


@pytest.fixture(scope="function")
def create_test_user_rbac_no_roles(django_db_setup, django_db_blocker, tenants_fixture):
    with django_db_blocker.unblock():
        user = User.objects.create_user(
            name="testing",
            email="rbac_noroles@rbac.com",
            password=TEST_PASSWORD,
        )
        tenant = tenants_fixture[0]
        Membership.objects.create(
            user=user,
            tenant=tenant,
            role=Membership.RoleChoices.OWNER,
        )

    return user


@pytest.fixture(scope="function")
def create_test_user_rbac_limited(django_db_setup, django_db_blocker, tenants_fixture):
    with django_db_blocker.unblock():
        user = User.objects.create_user(
            name="testing_limited",
            email="rbac_limited@rbac.com",
            password=TEST_PASSWORD,
        )
        tenant = tenants_fixture[0]
        Membership.objects.create(
            user=user,
            tenant=tenant,
            role=Membership.RoleChoices.OWNER,
        )
        role = Role.objects.create(
            name="limited",
            tenant_id=tenant.id,
            manage_users=False,
            manage_account=False,
            manage_billing=False,
            manage_providers=False,
            manage_integrations=False,
            manage_scans=False,
            unlimited_visibility=False,
        )
        UserRoleRelationship.objects.create(
            user=user,
            role=role,
            tenant_id=tenant.id,
        )
    return user


@pytest.fixture(scope="function")
def create_test_user_rbac_manage_account(django_db_setup, django_db_blocker):
    """User with only manage_account permission (no manage_users)."""
    with django_db_blocker.unblock():
        user = User.objects.create_user(
            name="testing_manage_account",
            email="rbac_manage_account@rbac.com",
            password=TEST_PASSWORD,
        )
        tenant = Tenant.objects.create(
            name="Tenant Test Manage Account",
        )
        Membership.objects.create(
            user=user,
            tenant=tenant,
            role=Membership.RoleChoices.OWNER,
        )
        role = Role.objects.create(
            name="manage_account",
            tenant_id=tenant.id,
            manage_users=False,
            manage_account=True,
            manage_billing=False,
            manage_providers=False,
            manage_integrations=False,
            manage_scans=False,
            unlimited_visibility=False,
        )
        UserRoleRelationship.objects.create(
            user=user,
            role=role,
            tenant_id=tenant.id,
        )
    return user


def first_membership_tenant(user):
    return user.memberships.order_by("date_joined").first().tenant


def access_token_for_tenant(user, tenant):
    access_token = AccessToken.for_user(user)
    access_token["tenant_id"] = str(tenant.id)
    access_token.payload["nbf"] = access_token["iat"]
    return str(access_token)


def authenticate_client_for_tenant(client, user, tenant):
    client.user = user
    client.defaults["HTTP_AUTHORIZATION"] = (
        f"Bearer {access_token_for_tenant(user, tenant)}"
    )
    return client


@pytest.fixture
def authenticated_client_for_tenant_factory():
    def create_authenticated_client(user, tenant):
        return authenticate_client_for_tenant(Client(), user, tenant)

    return create_authenticated_client


@pytest.fixture
def authenticated_client_rbac_manage_account(
    create_test_user_rbac_manage_account, client
):
    return authenticate_client_for_tenant(
        client,
        create_test_user_rbac_manage_account,
        first_membership_tenant(create_test_user_rbac_manage_account),
    )


@pytest.fixture(scope="function")
def create_test_user_rbac_manage_users_only(django_db_setup, django_db_blocker):
    """User with only manage_users permission (no manage_account)."""
    with django_db_blocker.unblock():
        user = User.objects.create_user(
            name="testing_manage_users_only",
            email="rbac_manage_users_only@rbac.com",
            password=TEST_PASSWORD,
        )
        tenant = Tenant.objects.create(name="Tenant Test Manage Users Only")
        Membership.objects.create(
            user=user,
            tenant=tenant,
            role=Membership.RoleChoices.OWNER,
        )
        role = Role.objects.create(
            name="manage_users_only",
            tenant_id=tenant.id,
            manage_users=True,
            manage_account=False,
            manage_billing=False,
            manage_providers=False,
            manage_integrations=False,
            manage_scans=False,
            unlimited_visibility=False,
        )
        UserRoleRelationship.objects.create(user=user, role=role, tenant_id=tenant.id)
    return user


@pytest.fixture
def authenticated_client_rbac_manage_users_only(
    create_test_user_rbac_manage_users_only, client
):
    return authenticate_client_for_tenant(
        client,
        create_test_user_rbac_manage_users_only,
        first_membership_tenant(create_test_user_rbac_manage_users_only),
    )


@pytest.fixture
def authenticated_client_rbac(create_test_user_rbac, tenants_fixture, client):
    return authenticate_client_for_tenant(
        client, create_test_user_rbac, tenants_fixture[0]
    )


@pytest.fixture
def authenticated_client_rbac_noroles(
    create_test_user_rbac_no_roles, tenants_fixture, client
):
    return authenticate_client_for_tenant(
        client, create_test_user_rbac_no_roles, tenants_fixture[0]
    )


@pytest.fixture
def authenticated_client_no_permissions_rbac(
    create_test_user_rbac_limited, tenants_fixture, client
):
    return authenticate_client_for_tenant(
        client, create_test_user_rbac_limited, tenants_fixture[0]
    )


@pytest.fixture
def authenticated_client(
    create_test_user, tenants_fixture, set_user_admin_roles_fixture, client
):
    return authenticate_client_for_tenant(client, create_test_user, tenants_fixture[0])


@pytest.fixture
def authenticated_api_client(create_test_user, tenants_fixture):
    client = APIClient()
    serializer = TokenSerializer(
        data={"type": "tokens", "email": TEST_USER, "password": TEST_PASSWORD}
    )
    serializer.is_valid()
    access_token = serializer.validated_data["access"]
    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"

    return client


@pytest.fixture
def tenants_fixture(create_test_user):
    user = create_test_user
    tenant1 = Tenant.objects.create(
        name="Tenant One",
    )
    Membership.objects.create(
        user=user,
        tenant=tenant1,
    )
    tenant2 = Tenant.objects.create(
        name="Tenant Two",
    )
    Membership.objects.create(
        user=user,
        tenant=tenant2,
        role=Membership.RoleChoices.OWNER,
    )
    tenant3 = Tenant.objects.create(
        name="Tenant Three",
    )

    return tenant1, tenant2, tenant3


@pytest.fixture
def set_user_admin_roles_fixture(create_test_user, tenants_fixture):
    user = create_test_user
    for tenant in tenants_fixture[:2]:
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
def invitations_fixture(create_test_user, tenants_fixture):
    user = create_test_user
    tenant = tenants_fixture[0]
    valid_invitation = Invitation.objects.create(
        email="testing@prowler.com",
        state=Invitation.State.PENDING,
        token="TESTING1234567",
        inviter=user,
        tenant=tenant,
    )
    expired_invitation = Invitation.objects.create(
        email="testing@prowler.com",
        state=Invitation.State.EXPIRED,
        token="TESTING1234568",
        expires_at=datetime.now(UTC) - timedelta(days=1),
        inviter=user,
        tenant=tenant,
    )
    return valid_invitation, expired_invitation


@pytest.fixture
def users_fixture(django_user_model):
    user1 = User.objects.create_user(
        name="user1", email="test_unit0@prowler.com", password="S3cret"
    )
    user2 = User.objects.create_user(
        name="user2", email="test_unit1@prowler.com", password="S3cret"
    )
    user3 = User.objects.create_user(
        name="user3", email="test_unit2@prowler.com", password="S3cret"
    )
    return user1, user2, user3


@pytest.fixture
def provider_factory(tenants_fixture):
    tenant = tenants_fixture[0]
    counters = {}

    def next_counter(provider):
        counters[provider] = counters.get(provider, 0) + 1
        return counters[provider]

    def defaults_for(provider, sequence):
        return {
            Provider.ProviderChoices.AWS.value: {
                "uid": f"{123456789011 + sequence:012d}",
                "alias": f"aws_testing_{sequence}",
            },
            Provider.ProviderChoices.AZURE.value: {
                "uid": str(uuid4()),
                "alias": f"azure_testing_{sequence}",
                "scanner_args": {"key1": "value1", "key2": {"key21": "value21"}},
            },
            Provider.ProviderChoices.GCP.value: {
                "uid": f"a12322-test{sequence:05d}",
                "alias": f"gcp_testing_{sequence}",
            },
            Provider.ProviderChoices.KUBERNETES.value: {
                "uid": f"kubernetes-test-{sequence}",
                "alias": f"k8s_testing_{sequence}",
            },
            Provider.ProviderChoices.M365.value: {
                "uid": f"m365-{sequence}.test.com",
                "alias": f"m365_testing_{sequence}",
            },
            Provider.ProviderChoices.GITHUB.value: {
                "uid": f"github-test-{sequence}",
                "alias": f"github_testing_{sequence}",
            },
            Provider.ProviderChoices.MONGODBATLAS.value: {
                "uid": f"64b1d3c0e4b03b{sequence:010x}",
                "alias": f"mongodbatlas_testing_{sequence}",
            },
            Provider.ProviderChoices.IAC.value: {
                "uid": f"https://github.com/prowler-cloud/test-{sequence}.git",
                "alias": f"iac_testing_{sequence}",
            },
            Provider.ProviderChoices.ORACLECLOUD.value: {
                "uid": f"ocid1.tenancy.oc1..aaaaaaaa{sequence:024d}",
                "alias": f"oci_testing_{sequence}",
            },
            Provider.ProviderChoices.ALIBABACLOUD.value: {
                "uid": f"{1234567890123455 + sequence:016d}",
                "alias": f"alibabacloud_testing_{sequence}",
            },
            Provider.ProviderChoices.CLOUDFLARE.value: {
                "uid": f"{0x1000000000000000000000000000000 + sequence:032x}",
                "alias": f"cloudflare_testing_{sequence}",
            },
            Provider.ProviderChoices.OPENSTACK.value: {
                "uid": f"openstack-project-{sequence}",
                "alias": f"openstack_testing_{sequence}",
            },
            Provider.ProviderChoices.IMAGE.value: {
                "uid": f"registry.example.com/prowler/test:{sequence}",
                "alias": f"image_testing_{sequence}",
            },
            Provider.ProviderChoices.GOOGLEWORKSPACE.value: {
                "uid": f"C{12345677 + sequence}",
                "alias": f"googleworkspace_testing_{sequence}",
            },
            Provider.ProviderChoices.VERCEL.value: {
                "uid": f"team_{sequence:016x}",
                "alias": f"vercel_testing_{sequence}",
            },
            Provider.ProviderChoices.OKTA.value: {
                "uid": f"acme-{sequence}.okta.com",
                "alias": f"okta_testing_{sequence}",
            },
        }[provider]

    def create_provider(provider=Provider.ProviderChoices.AWS.value, **overrides):
        provider_value = getattr(provider, "value", provider)
        selected_tenant = overrides.pop("tenant", tenant)
        sequence = next_counter(provider_value)
        attributes = {
            "provider": provider_value,
            "tenant_id": selected_tenant.id,
            **defaults_for(provider_value, sequence),
        }
        attributes.update(overrides)
        return Provider.objects.create(**attributes)

    return create_provider


@pytest.fixture
def aws_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.AWS.value)


@pytest.fixture
def aws_provider_pair(aws_provider, provider_factory):
    return (
        aws_provider,
        provider_factory(Provider.ProviderChoices.AWS.value),
    )


@pytest.fixture
def azure_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.AZURE.value)


@pytest.fixture
def gcp_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.GCP.value)


@pytest.fixture
def kubernetes_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.KUBERNETES.value)


@pytest.fixture
def m365_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.M365.value)


@pytest.fixture
def github_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.GITHUB.value)


@pytest.fixture
def mongodbatlas_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.MONGODBATLAS.value)


@pytest.fixture
def iac_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.IAC.value)


@pytest.fixture
def oraclecloud_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.ORACLECLOUD.value)


@pytest.fixture
def alibabacloud_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.ALIBABACLOUD.value)


@pytest.fixture
def cloudflare_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.CLOUDFLARE.value)


@pytest.fixture
def openstack_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.OPENSTACK.value)


@pytest.fixture
def image_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.IMAGE.value)


@pytest.fixture
def googleworkspace_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.GOOGLEWORKSPACE.value)


@pytest.fixture
def vercel_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.VERCEL.value)


@pytest.fixture
def okta_provider(provider_factory):
    return provider_factory(Provider.ProviderChoices.OKTA.value)


@pytest.fixture
def all_provider_types_fixture(provider_factory):
    return tuple(
        provider_factory(provider_choice.value)
        for provider_choice in Provider.ProviderChoices
    )


@pytest.fixture
def processor_fixture(tenants_fixture):
    tenant, *_ = tenants_fixture
    processor = Processor.objects.create(
        tenant_id=tenant.id,
        processor_type="mutelist",
        configuration="Mutelist:\n  Accounts:\n    *:\n      Checks:\n        iam_user_hardware_mfa_enabled:\n         "
        " Regions:\n            - *\n          Resources:\n            - *",
    )

    return processor


@pytest.fixture
def provider_groups_fixture(tenants_fixture):
    tenant, *_ = tenants_fixture
    pgroup1 = ProviderGroup.objects.create(
        name="Group One",
        tenant_id=tenant.id,
    )
    pgroup2 = ProviderGroup.objects.create(
        name="Group Two",
        tenant_id=tenant.id,
    )
    pgroup3 = ProviderGroup.objects.create(
        name="Group Three",
        tenant_id=tenant.id,
    )

    return pgroup1, pgroup2, pgroup3


@pytest.fixture
def admin_role_fixture(tenants_fixture):
    tenant, *_ = tenants_fixture

    return Role.objects.get_or_create(
        name="admin",
        tenant_id=tenant.id,
        manage_users=True,
        manage_account=True,
        manage_billing=True,
        manage_providers=True,
        manage_integrations=True,
        manage_scans=True,
        unlimited_visibility=True,
    )[0]


@pytest.fixture
def roles_fixture(tenants_fixture):
    tenant, *_ = tenants_fixture
    role1 = Role.objects.create(
        name="Role One",
        tenant_id=tenant.id,
        manage_users=True,
        manage_account=True,
        manage_billing=True,
        manage_providers=True,
        manage_integrations=False,
        manage_scans=True,
        unlimited_visibility=False,
    )
    role2 = Role.objects.create(
        name="Role Two",
        tenant_id=tenant.id,
        manage_users=False,
        manage_account=False,
        manage_billing=False,
        manage_providers=True,
        manage_integrations=True,
        manage_scans=True,
        unlimited_visibility=True,
    )
    role3 = Role.objects.create(
        name="Role Three",
        tenant_id=tenant.id,
        manage_users=True,
        manage_account=True,
        manage_billing=True,
        manage_providers=True,
        manage_integrations=True,
        manage_scans=True,
        unlimited_visibility=True,
    )
    role4 = Role.objects.create(
        name="Role Four",
        tenant_id=tenant.id,
        manage_users=False,
        manage_account=False,
        manage_billing=False,
        manage_providers=False,
        manage_integrations=False,
        manage_scans=False,
        unlimited_visibility=False,
    )

    return role1, role2, role3, role4


@pytest.fixture
def provider_secret_fixture(all_provider_types_fixture):
    return tuple(
        ProviderSecret.objects.create(
            tenant_id=provider.tenant_id,
            provider=provider,
            secret_type=ProviderSecret.TypeChoices.STATIC,
            secret={"key": "value"},
            name=provider.alias,
        )
        for provider in all_provider_types_fixture
    )


@pytest.fixture
def scans_fixture(tenants_fixture, aws_provider_pair):
    tenant, *_ = tenants_fixture
    provider, provider2 = aws_provider_pair

    now = datetime.now(UTC)

    scan1 = Scan.objects.create(
        name="Scan 1",
        provider=provider,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        tenant_id=tenant.id,
        started_at=now,
        completed_at=now,
    )
    scan2 = Scan.objects.create(
        name="Scan 2",
        provider=provider2,
        trigger=Scan.TriggerChoices.SCHEDULED,
        state=StateChoices.COMPLETED,
        tenant_id=tenant.id,
        started_at=now,
        completed_at=now,
    )
    scan3 = Scan.objects.create(
        name="Scan 3",
        provider=provider2,
        trigger=Scan.TriggerChoices.SCHEDULED,
        state=StateChoices.AVAILABLE,
        tenant_id=tenant.id,
        started_at="2024-01-02T00:00:00Z",
    )
    return scan1, scan2, scan3


@pytest.fixture
def tasks_fixture(tenants_fixture):
    tenant, *_ = tenants_fixture

    task_runner_task1 = TaskResult.objects.create(
        task_id="81a1b34b-ff6e-498e-979c-d6a83260167f",
        task_name="task_runner_task1",
        task_kwargs='{"kwarg1": "value1"}',
        status="SUCCESS",
    )
    task_runner_task2 = TaskResult.objects.create(
        task_id="4d0260a5-2e1f-4a34-a976-8c5acb9f5499",
        task_name="task_runner_task1",
        status="PENDING",
    )
    task1 = Task.objects.create(
        id=task_runner_task1.task_id,
        task_runner_task=task_runner_task1,
        tenant_id=tenant.id,
    )
    task2 = Task.objects.create(
        id=task_runner_task2.task_id,
        task_runner_task=task_runner_task2,
        tenant_id=tenant.id,
    )

    return task1, task2


@pytest.fixture
def resources_fixture(aws_provider_pair):
    provider, provider2 = aws_provider_pair

    tags = [
        ResourceTag.objects.create(
            tenant_id=provider.tenant_id,
            key="key",
            value="value",
        ),
        ResourceTag.objects.create(
            tenant_id=provider.tenant_id,
            key="key2",
            value="value2",
        ),
    ]

    resource1 = Resource.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        uid="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        name="My Instance 1",
        region="us-east-1",
        service="ec2",
        type="prowler-test",
        groups=["compute"],
    )

    resource1.upsert_or_delete_tags(tags)

    resource2 = Resource.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        uid="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef1",
        name="My Instance 2",
        region="eu-west-1",
        service="s3",
        type="prowler-test",
        groups=["storage"],
    )
    resource2.upsert_or_delete_tags(tags)

    resource3 = Resource.objects.create(
        tenant_id=provider2.tenant_id,
        provider=provider2,
        uid="arn:aws:ec2:us-east-1:123456789012:bucket/i-1234567890abcdef2",
        name="My Bucket 3",
        region="us-east-1",
        service="ec2",
        type="test",
        groups=["compute"],
    )

    tags = [
        ResourceTag.objects.create(
            tenant_id=provider.tenant_id,
            key="key3",
            value="multi word value3",
        ),
    ]
    resource3.upsert_or_delete_tags(tags)

    return resource1, resource2, resource3


@pytest.fixture
def findings_fixture(scans_fixture, resources_fixture):
    scan, *_ = scans_fixture
    resource1, resource2, *_ = resources_fixture

    finding1 = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid="test_finding_uid_1",
        scan=scan,
        delta=None,
        status=Status.FAIL,
        status_extended="test status extended ",
        impact=Severity.critical,
        impact_extended="test impact extended one",
        severity=Severity.critical,
        raw_result={
            "status": Status.FAIL,
            "impact": Severity.critical,
            "severity": Severity.critical,
        },
        tags={"test": "dev-qa"},
        check_id="test_check_id",
        check_metadata={
            "CheckId": "test_check_id",
            "Description": "test description apple sauce",
            "servicename": "ec2",
        },
        first_seen_at="2024-01-02T00:00:00Z",
    )

    finding1.add_resources([resource1])

    finding2 = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid="test_finding_uid_2",
        scan=scan,
        delta="new",
        status=Status.FAIL,
        status_extended="Load Balancer exposed to internet",
        impact=Severity.medium,
        impact_extended="test impact extended two",
        severity=Severity.medium,
        raw_result={
            "status": Status.FAIL,
            "impact": Severity.medium,
            "severity": Severity.medium,
        },
        tags={"test": "test"},
        check_id="test_check_id",
        check_metadata={
            "CheckId": "test_check_id",
            "Description": "test description orange juice",
            "servicename": "s3",
        },
        first_seen_at="2024-01-02T00:00:00Z",
        muted=True,
    )

    finding2.add_resources([resource2])

    return finding1, finding2


@pytest.fixture
def compliance_overviews_fixture(scans_fixture, tenants_fixture):
    tenant = tenants_fixture[0]
    scan1, scan2, scan3 = scans_fixture

    compliance_overview1 = ComplianceOverview.objects.create(
        tenant=tenant,
        scan=scan1,
        compliance_id="aws_account_security_onboarding_aws",
        framework="AWS-Account-Security-Onboarding",
        version="1.0",
        description="Description for AWS Account Security Onboarding",
        region="eu-west-1",
        requirements={
            "requirement1": {
                "name": "Requirement 1",
                "checks": {"check1.1": "PASS", "check1.2": None},
                "status": "PASS",
                "attributes": [],
                "description": "Description of requirement 1",
                "checks_status": {
                    "total": 2,
                    "failed": 0,
                    "passed": 2,
                },
            },
            "requirement2": {
                "name": "Requirement 2",
                "checks": {"check2.1": "PASS", "check2.2": "PASS"},
                "status": "PASS",
                "attributes": [],
                "description": "Description of requirement 2",
                "checks_status": {
                    "total": 2,
                    "failed": 0,
                    "passed": 2,
                },
            },
            "requirement3": {
                "name": "Requirement 3 - manual",
                "checks": {},
                "status": "PASS",
                "attributes": [],
                "description": "Description of requirement 2",
                "checks_status": {
                    "total": 0,
                    "failed": 0,
                    "passed": 0,
                },
            },
        },
        requirements_passed=2,
        requirements_failed=0,
        requirements_manual=1,
        total_requirements=3,
    )

    compliance_overview2 = ComplianceOverview.objects.create(
        tenant=tenant,
        scan=scan1,
        compliance_id="aws_account_security_onboarding_aws",
        framework="AWS-Account-Security-Onboarding",
        version="1.0",
        description="Description for AWS Account Security Onboarding",
        region="eu-west-2",
        requirements={
            "requirement1": {
                "name": "Requirement 1",
                "checks": {"check1.1": "PASS", "check1.2": None},
                "status": "PASS",
                "attributes": [],
                "description": "Description of requirement 1",
                "checks_status": {
                    "total": 2,
                    "failed": 0,
                    "passed": 2,
                },
            },
            "requirement2": {
                "name": "Requirement 2",
                "checks": {"check2.1": "PASS", "check2.2": "FAIL"},
                "status": "FAIL",
                "attributes": [],
                "description": "Description of requirement 2",
                "checks_status": {
                    "total": 2,
                    "failed": 1,
                    "passed": 1,
                },
            },
            "requirement3": {
                "name": "Requirement 3 - manual",
                "checks": {},
                "status": "PASS",
                "attributes": [],
                "description": "Description of requirement 2",
                "checks_status": {
                    "total": 0,
                    "failed": 0,
                    "passed": 0,
                },
            },
        },
        requirements_passed=1,
        requirements_failed=1,
        requirements_manual=1,
        total_requirements=3,
    )

    # Return the created compliance overviews
    return compliance_overview1, compliance_overview2


@pytest.fixture
def compliance_requirements_overviews_fixture(scans_fixture, tenants_fixture):
    """Fixture for ComplianceRequirementOverview objects used by the new ComplianceOverviewViewSet."""
    tenant = tenants_fixture[0]
    scan1, scan2, scan3 = scans_fixture

    # Create ComplianceRequirementOverview objects for scan1
    requirement_overview1 = ComplianceRequirementOverview.objects.create(
        tenant=tenant,
        scan=scan1,
        compliance_id="aws_account_security_onboarding_aws",
        framework="AWS-Account-Security-Onboarding",
        version="1.0",
        description="Description for AWS Account Security Onboarding",
        region="eu-west-1",
        requirement_id="requirement1",
        requirement_status=StatusChoices.PASS,
        passed_checks=2,
        failed_checks=0,
        total_checks=2,
    )

    requirement_overview2 = ComplianceRequirementOverview.objects.create(
        tenant=tenant,
        scan=scan1,
        compliance_id="aws_account_security_onboarding_aws",
        framework="AWS-Account-Security-Onboarding",
        version="1.0",
        description="Description for AWS Account Security Onboarding",
        region="eu-west-1",
        requirement_id="requirement2",
        requirement_status=StatusChoices.PASS,
        passed_checks=2,
        failed_checks=0,
        total_checks=2,
    )

    requirement_overview3 = ComplianceRequirementOverview.objects.create(
        tenant=tenant,
        scan=scan1,
        compliance_id="aws_account_security_onboarding_aws",
        framework="AWS-Account-Security-Onboarding",
        version="1.0",
        description="Description for AWS Account Security Onboarding",
        region="eu-west-2",
        requirement_id="requirement1",
        requirement_status=StatusChoices.PASS,
        passed_checks=2,
        failed_checks=0,
        total_checks=2,
    )

    requirement_overview4 = ComplianceRequirementOverview.objects.create(
        tenant=tenant,
        scan=scan1,
        compliance_id="aws_account_security_onboarding_aws",
        framework="AWS-Account-Security-Onboarding",
        version="1.0",
        description="Description for AWS Account Security Onboarding",
        region="eu-west-2",
        requirement_id="requirement2",
        requirement_status=StatusChoices.FAIL,
        passed_checks=1,
        failed_checks=1,
        total_checks=2,
    )

    requirement_overview5 = ComplianceRequirementOverview.objects.create(
        tenant=tenant,
        scan=scan1,
        compliance_id="aws_account_security_onboarding_aws",
        framework="AWS-Account-Security-Onboarding",
        version="1.0",
        description="Description for AWS Account Security Onboarding (MANUAL)",
        region="eu-west-2",
        requirement_id="requirement3",
        requirement_status=StatusChoices.MANUAL,
        passed_checks=0,
        failed_checks=0,
        total_checks=0,
    )

    # Create a different compliance framework for testing
    requirement_overview6 = ComplianceRequirementOverview.objects.create(
        tenant=tenant,
        scan=scan1,
        compliance_id="cis_1.4_aws",
        framework="CIS-1.4-AWS",
        version="1.4",
        description="CIS AWS Foundations Benchmark v1.4.0",
        region="eu-west-1",
        requirement_id="cis_requirement1",
        requirement_status=StatusChoices.FAIL,
        passed_checks=0,
        failed_checks=3,
        total_checks=3,
    )

    # Create another compliance framework for testing MITRE ATT&CK
    requirement_overview7 = ComplianceRequirementOverview.objects.create(
        tenant=tenant,
        scan=scan1,
        compliance_id="mitre_attack_aws",
        framework="MITRE-ATTACK",
        version="1.0",
        description="MITRE ATT&CK",
        region="eu-west-1",
        requirement_id="mitre_requirement1",
        requirement_status=StatusChoices.FAIL,
        passed_checks=0,
        failed_checks=0,
        total_checks=0,
    )

    return (
        requirement_overview1,
        requirement_overview2,
        requirement_overview3,
        requirement_overview4,
        requirement_overview5,
        requirement_overview6,
        requirement_overview7,
    )


def get_api_tokens(
    api_client, user_email: str, user_password: str, tenant_id: str = None
) -> tuple[str, str]:
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


@pytest.fixture
def scan_summaries_fixture(tenants_fixture, aws_provider):
    tenant = tenants_fixture[0]
    provider = aws_provider
    scan = Scan.objects.create(
        name="overview scan",
        provider=provider,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        tenant=tenant,
    )

    ScanSummary.objects.create(
        tenant=tenant,
        check_id="check1",
        service="service1",
        severity="high",
        region="region1",
        _pass=1,
        fail=0,
        muted=2,
        total=3,
        new=1,
        changed=0,
        unchanged=0,
        fail_new=0,
        fail_changed=0,
        pass_new=1,
        pass_changed=0,
        muted_new=2,
        muted_changed=0,
        scan=scan,
    )

    ScanSummary.objects.create(
        tenant=tenant,
        check_id="check1",
        service="service1",
        severity="high",
        region="region2",
        _pass=0,
        fail=1,
        muted=3,
        total=4,
        new=2,
        changed=0,
        unchanged=0,
        fail_new=1,
        fail_changed=0,
        pass_new=0,
        pass_changed=0,
        muted_new=3,
        muted_changed=0,
        scan=scan,
    )

    ScanSummary.objects.create(
        tenant=tenant,
        check_id="check2",
        service="service2",
        severity="critical",
        region="region1",
        _pass=1,
        fail=0,
        muted=1,
        total=2,
        new=1,
        changed=0,
        unchanged=0,
        fail_new=0,
        fail_changed=0,
        pass_new=1,
        pass_changed=0,
        muted_new=1,
        muted_changed=0,
        scan=scan,
    )


@pytest.fixture
def integrations_fixture(aws_provider_pair):
    provider1, provider2 = aws_provider_pair
    tenant_id = provider1.tenant_id
    integration1 = Integration.objects.create(
        tenant_id=tenant_id,
        enabled=True,
        connected=True,
        integration_type="amazon_s3",
        configuration={"key": "value"},
        credentials={"psswd": "1234"},
    )
    IntegrationProviderRelationship.objects.create(
        tenant_id=tenant_id,
        integration=integration1,
        provider=provider1,
    )

    integration2 = Integration.objects.create(
        tenant_id=tenant_id,
        enabled=True,
        connected=True,
        integration_type="amazon_s3",
        configuration={"key": "value1"},
        credentials={"psswd": "1234"},
    )
    IntegrationProviderRelationship.objects.create(
        tenant_id=tenant_id,
        integration=integration2,
        provider=provider1,
    )
    IntegrationProviderRelationship.objects.create(
        tenant_id=tenant_id,
        integration=integration2,
        provider=provider2,
    )

    return integration1, integration2


@pytest.fixture
def backfill_scan_metadata_fixture(scans_fixture, findings_fixture):
    for scan_instance in scans_fixture:
        tenant_id = scan_instance.tenant_id
        scan_id = scan_instance.id
        backfill_resource_scan_summaries(tenant_id=tenant_id, scan_id=scan_id)


@pytest.fixture
def lighthouse_config_fixture(authenticated_client, tenants_fixture):
    return LighthouseConfiguration.objects.create(
        tenant_id=tenants_fixture[0].id,
        name="OpenAI",
        api_key_decoded="sk-fake-test-key-for-unit-testing-only",
        model="gpt-4o",
        temperature=0,
        max_tokens=4000,
        business_context="Test business context",
        is_active=True,
    )


@pytest.fixture(scope="function")
def latest_scan_finding(authenticated_client, aws_provider, resources_fixture):
    provider = aws_provider
    tenant_id = str(aws_provider.tenant_id)
    resource = resources_fixture[0]
    scan = Scan.objects.create(
        name="latest completed scan",
        provider=provider,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        tenant_id=tenant_id,
    )
    finding = Finding.objects.create(
        tenant_id=tenant_id,
        uid="test_finding_uid_1",
        scan=scan,
        delta="new",
        status=Status.FAIL,
        status_extended="test status extended ",
        impact=Severity.critical,
        impact_extended="test impact extended one",
        severity=Severity.critical,
        raw_result={
            "status": Status.FAIL,
            "impact": Severity.critical,
            "severity": Severity.critical,
        },
        tags={"test": "dev-qa"},
        check_id="test_check_id",
        check_metadata={
            "CheckId": "test_check_id",
            "Description": "test description apple sauce",
        },
        first_seen_at="2024-01-02T00:00:00Z",
    )

    finding.add_resources([resource])
    backfill_resource_scan_summaries(tenant_id, str(scan.id))
    return finding


@pytest.fixture(scope="function")
def findings_with_categories(scans_fixture, resources_fixture):
    scan = scans_fixture[0]
    resource = resources_fixture[0]

    finding = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid="finding_with_categories_1",
        scan=scan,
        delta=None,
        status=Status.FAIL,
        status_extended="test status",
        impact=Severity.critical,
        impact_extended="test impact",
        severity=Severity.critical,
        raw_result={"status": Status.FAIL},
        check_id="genai_check",
        check_metadata={"CheckId": "genai_check"},
        categories=["gen-ai", "security"],
        first_seen_at="2024-01-02T00:00:00Z",
    )
    finding.add_resources([resource])
    backfill_resource_scan_summaries(str(scan.tenant_id), str(scan.id))
    return finding


@pytest.fixture(scope="function")
def findings_with_multiple_categories(scans_fixture, resources_fixture):
    scan = scans_fixture[0]
    resource1, resource2 = resources_fixture[:2]

    finding1 = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid="finding_multi_cat_1",
        scan=scan,
        delta=None,
        status=Status.FAIL,
        status_extended="test status",
        impact=Severity.critical,
        impact_extended="test impact",
        severity=Severity.critical,
        raw_result={"status": Status.FAIL},
        check_id="genai_check",
        check_metadata={"CheckId": "genai_check"},
        categories=["gen-ai", "security"],
        first_seen_at="2024-01-02T00:00:00Z",
    )
    finding1.add_resources([resource1])

    finding2 = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid="finding_multi_cat_2",
        scan=scan,
        delta=None,
        status=Status.FAIL,
        status_extended="test status 2",
        impact=Severity.high,
        impact_extended="test impact 2",
        severity=Severity.high,
        raw_result={"status": Status.FAIL},
        check_id="iam_check",
        check_metadata={"CheckId": "iam_check"},
        categories=["iam", "security"],
        first_seen_at="2024-01-02T00:00:00Z",
    )
    finding2.add_resources([resource2])

    backfill_resource_scan_summaries(str(scan.tenant_id), str(scan.id))
    return finding1, finding2


@pytest.fixture(scope="function")
def latest_scan_finding_with_categories(
    authenticated_client, aws_provider, resources_fixture
):
    provider = aws_provider
    tenant_id = str(aws_provider.tenant_id)
    resource = resources_fixture[0]
    scan = Scan.objects.create(
        name="latest completed scan with categories",
        provider=provider,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        tenant_id=tenant_id,
    )
    finding = Finding.objects.create(
        tenant_id=tenant_id,
        uid="latest_finding_with_categories",
        scan=scan,
        delta="new",
        status=Status.FAIL,
        status_extended="test status",
        impact=Severity.critical,
        impact_extended="test impact",
        severity=Severity.critical,
        raw_result={"status": Status.FAIL},
        check_id="genai_iam_check",
        check_metadata={"CheckId": "genai_iam_check"},
        categories=["gen-ai", "iam"],
        resource_groups="ai_ml",
        first_seen_at="2024-01-02T00:00:00Z",
    )
    finding.add_resources([resource])
    backfill_resource_scan_summaries(tenant_id, str(scan.id))
    aggregate_scan_category_summaries(tenant_id, str(scan.id))
    aggregate_scan_resource_group_summaries(tenant_id, str(scan.id))
    return finding


@pytest.fixture(scope="function")
def latest_scan_resource(authenticated_client, aws_provider):
    provider = aws_provider
    tenant_id = str(aws_provider.tenant_id)
    scan = Scan.objects.create(
        name="latest completed scan for resource",
        provider=provider,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        tenant_id=tenant_id,
    )
    resource = Resource.objects.create(
        tenant_id=tenant_id,
        provider=provider,
        uid="latest_resource_uid",
        name="Latest Resource",
        region="us-east-1",
        service="ec2",
        type="instance",
        metadata='{"test": "metadata"}',
        details='{"test": "details"}',
    )

    resource_tag = ResourceTag.objects.create(
        tenant_id=tenant_id,
        key="environment",
        value="test",
    )
    ResourceTagMapping.objects.create(
        tenant_id=tenant_id,
        resource=resource,
        tag=resource_tag,
    )

    finding = Finding.objects.create(
        tenant_id=tenant_id,
        uid="test_finding_uid_latest",
        scan=scan,
        delta="new",
        status=Status.FAIL,
        status_extended="test status extended ",
        impact=Severity.critical,
        impact_extended="test impact extended",
        severity=Severity.critical,
        raw_result={
            "status": Status.FAIL,
            "impact": Severity.critical,
            "severity": Severity.critical,
        },
        tags={"test": "latest"},
        check_id="test_check_id_latest",
        check_metadata={
            "CheckId": "test_check_id_latest",
            "Description": "test description latest",
        },
        first_seen_at="2024-01-02T00:00:00Z",
    )
    finding.add_resources([resource])

    backfill_resource_scan_summaries(tenant_id, str(scan.id))
    return resource


@pytest.fixture
def saml_setup(tenants_fixture):
    tenant_id = tenants_fixture[0].id
    domain = "prowler.com"

    SAMLDomainIndex.objects.create(email_domain=domain, tenant_id=tenant_id)

    metadata_xml = """<?xml version='1.0' encoding='UTF-8'?>
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
    """
    SAMLConfiguration.objects.create(
        tenant_id=str(tenant_id),
        email_domain=domain,
        metadata_xml=metadata_xml,
    )

    return {
        "email": f"user@{domain}",
        "domain": domain,
        "tenant_id": tenant_id,
    }


@pytest.fixture
def saml_sociallogin(users_fixture):
    user = users_fixture[0]
    user.email = "samlsso@acme.com"
    extra_data = {
        "firstName": ["Test"],
        "lastName": ["User"],
        "organization": ["Prowler"],
        "userType": ["member"],
    }

    account = MagicMock()
    account.provider = "saml"
    account.extra_data = extra_data

    sociallogin = MagicMock(spec=SocialLogin)
    sociallogin.account = account
    sociallogin.user = user

    return sociallogin


@pytest.fixture
def api_keys_fixture(tenants_fixture, create_test_user):
    """Create test API keys for testing."""
    tenant = tenants_fixture[0]
    user = create_test_user

    # Create and assign role to user for API key authentication
    role = Role.objects.create(
        tenant_id=tenant.id,
        name="Test API Key Role",
        unlimited_visibility=True,
        manage_account=True,
    )
    UserRoleRelationship.objects.create(
        user=user,
        role=role,
        tenant_id=tenant.id,
    )

    # Create API keys with different states
    api_key1, raw_key1 = TenantAPIKey.objects.create_api_key(
        name="Test API Key 1",
        tenant_id=tenant.id,
        entity=user,
    )

    api_key2, raw_key2 = TenantAPIKey.objects.create_api_key(
        name="Test API Key 2",
        tenant_id=tenant.id,
        entity=user,
        expiry_date=datetime.now(UTC) + timedelta(days=60),
    )

    # Revoked API key
    api_key3, raw_key3 = TenantAPIKey.objects.create_api_key(
        name="Revoked API Key",
        tenant_id=tenant.id,
        entity=user,
    )
    api_key3.revoked = True
    api_key3.save()

    # Store raw keys on instances for testing
    api_key1._raw_key = raw_key1
    api_key2._raw_key = raw_key2
    api_key3._raw_key = raw_key3

    return [api_key1, api_key2, api_key3]


@pytest.fixture
def mute_rules_fixture(tenants_fixture, create_test_user, findings_fixture):
    """Create test mute rules for testing."""
    tenant = tenants_fixture[0]
    user = create_test_user

    # Create two mute rules: one enabled, one disabled
    mute_rule1 = MuteRule.objects.create(
        tenant_id=tenant.id,
        name="Test Rule 1",
        reason="Security exception for testing",
        enabled=True,
        created_by=user,
        finding_uids=[findings_fixture[0].uid],
    )

    mute_rule2 = MuteRule.objects.create(
        tenant_id=tenant.id,
        name="Test Rule 2",
        reason="Compliance exception approved",
        enabled=False,
        created_by=user,
        finding_uids=[findings_fixture[1].uid],
    )

    return mute_rule1, mute_rule2


@pytest.fixture
def create_attack_paths_scan():
    """Factory fixture to create Attack Paths scans for tests."""

    def _create(
        provider,
        *,
        scan=None,
        state=StateChoices.COMPLETED,
        progress=0,
        **extra_fields,
    ):
        scan_instance = scan or Scan.objects.create(
            name=extra_fields.pop("scan_name", "Attack Paths Supporting Scan"),
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=extra_fields.pop("scan_state", StateChoices.COMPLETED),
            tenant_id=provider.tenant_id,
        )

        payload = {
            "tenant_id": provider.tenant_id,
            "provider": provider,
            "scan": scan_instance,
            "state": state,
            "progress": progress,
        }
        payload.update(extra_fields)

        return AttackPathsScan.objects.create(**payload)

    return _create


@pytest.fixture
def attack_paths_query_definition_factory():
    """Factory fixture for building Attack Paths query definitions."""

    def _create(**overrides):
        cast_type = overrides.pop("cast_type", str)
        parameters = overrides.pop(
            "parameters",
            [
                AttackPathsQueryParameterDefinition(
                    name="limit",
                    label="Limit",
                    cast=cast_type,
                )
            ],
        )
        definition_payload = {
            "id": "aws-test",
            "name": "Attack Paths Test Query",
            "short_description": "Synthetic short description for tests.",
            "description": "Synthetic Attack Paths definition for tests.",
            "provider": "aws",
            "cypher": "RETURN 1",
            "parameters": parameters,
        }
        definition_payload.update(overrides)
        return AttackPathsQueryDefinition(**definition_payload)

    return _create


@pytest.fixture
def sink_backend_stub():
    """Install a stub `SinkDatabase` into the sink factory for the test's duration.

    The sink factory caches a process-wide backend and lazily initializes it
    against `settings.DATABASES["neo4j"]` / `["neptune"]`. Tests that don't
    want to stand up a real Bolt driver can yield this fixture's mock and
    configure its return values directly:

        sink_backend_stub.execute_read_query.return_value = some_graph

    Both the active backend and the secondary-backend cache are restored on
    teardown so tests stay isolated.
    """
    from api.attack_paths.sink import factory
    from api.attack_paths.sink.base import SinkDatabase

    stub = MagicMock(spec=SinkDatabase)
    previous_backend = factory._backend
    previous_secondary = dict(factory._secondary_backends)
    factory._backend = stub
    factory._secondary_backends.clear()
    try:
        yield stub
    finally:
        factory._backend = previous_backend
        factory._secondary_backends.clear()
        factory._secondary_backends.update(previous_secondary)


@pytest.fixture
def attack_paths_graph_stub_classes():
    """Provide lightweight graph element stubs for Attack Paths serialization tests."""

    class AttackPathsNativeValue:
        def __init__(self, value):
            self._value = value

        def to_native(self):
            return self._value

    class AttackPathsNode:
        def __init__(self, element_id, labels, properties):
            self.element_id = element_id
            self.labels = labels
            self._properties = properties

    class AttackPathsRelationship:
        def __init__(self, element_id, rel_type, start_node, end_node, properties):
            self.element_id = element_id
            self.type = rel_type
            self.start_node = start_node
            self.end_node = end_node
            self._properties = properties

    return SimpleNamespace(
        NativeValue=AttackPathsNativeValue,
        Node=AttackPathsNode,
        Relationship=AttackPathsRelationship,
    )


@pytest.fixture
def create_attack_surface_overview():
    def _create(tenant, scan, attack_surface_type, total=10, failed=5, muted_failed=2):
        return AttackSurfaceOverview.objects.create(
            tenant=tenant,
            scan=scan,
            attack_surface_type=attack_surface_type,
            total_findings=total,
            failed_findings=failed,
            muted_failed_findings=muted_failed,
        )

    return _create


@pytest.fixture
def create_scan_category_summary():
    def _create(
        tenant,
        scan,
        category,
        severity,
        total_findings=10,
        failed_findings=5,
        new_failed_findings=2,
    ):
        return ScanCategorySummary.objects.create(
            tenant=tenant,
            scan=scan,
            category=category,
            severity=severity,
            total_findings=total_findings,
            failed_findings=failed_findings,
            new_failed_findings=new_failed_findings,
        )

    return _create


@pytest.fixture(scope="function")
def findings_with_group(scans_fixture, resources_fixture):
    scan = scans_fixture[0]
    resource = resources_fixture[0]

    finding = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid="finding_with_group_1",
        scan=scan,
        delta=None,
        status=Status.FAIL,
        status_extended="test status",
        impact=Severity.critical,
        impact_extended="test impact",
        severity=Severity.critical,
        raw_result={"status": Status.FAIL},
        check_id="storage_check",
        check_metadata={"CheckId": "storage_check"},
        resource_groups="storage",
        first_seen_at="2024-01-02T00:00:00Z",
    )
    finding.add_resources([resource])
    backfill_resource_scan_summaries(str(scan.tenant_id), str(scan.id))
    return finding


@pytest.fixture(scope="function")
def findings_with_multiple_groups(scans_fixture, resources_fixture):
    scan = scans_fixture[0]
    resource1, resource2 = resources_fixture[:2]

    finding1 = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid="finding_multi_grp_1",
        scan=scan,
        delta=None,
        status=Status.FAIL,
        status_extended="test status",
        impact=Severity.critical,
        impact_extended="test impact",
        severity=Severity.critical,
        raw_result={"status": Status.FAIL},
        check_id="storage_check",
        check_metadata={"CheckId": "storage_check"},
        resource_groups="storage",
        first_seen_at="2024-01-02T00:00:00Z",
    )
    finding1.add_resources([resource1])

    finding2 = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid="finding_multi_grp_2",
        scan=scan,
        delta=None,
        status=Status.FAIL,
        status_extended="test status 2",
        impact=Severity.high,
        impact_extended="test impact 2",
        severity=Severity.high,
        raw_result={"status": Status.FAIL},
        check_id="security_check",
        check_metadata={"CheckId": "security_check"},
        resource_groups="security",
        first_seen_at="2024-01-02T00:00:00Z",
    )
    finding2.add_resources([resource2])

    backfill_resource_scan_summaries(str(scan.tenant_id), str(scan.id))
    return finding1, finding2


@pytest.fixture
def create_scan_resource_group_summary():
    def _create(
        tenant,
        scan,
        resource_group,
        severity,
        total_findings=10,
        failed_findings=5,
        new_failed_findings=2,
        resources_count=3,
    ):
        return ScanGroupSummary.objects.create(
            tenant=tenant,
            scan=scan,
            resource_group=resource_group,
            severity=severity,
            total_findings=total_findings,
            failed_findings=failed_findings,
            new_failed_findings=new_failed_findings,
            resources_count=resources_count,
        )

    return _create


def get_authorization_header(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def provider_compliance_scores_fixture(
    tenants_fixture, aws_provider_pair, scans_fixture
):
    """Create ProviderComplianceScore entries for compliance watchlist tests."""
    tenant = tenants_fixture[0]
    provider1, provider2 = aws_provider_pair
    scan1, _, scan3 = scans_fixture

    scan1.completed_at = datetime.now(UTC) - timedelta(hours=1)
    scan1.save()
    scan3.state = StateChoices.COMPLETED
    scan3.completed_at = datetime.now(UTC)
    scan3.save()

    scores = [
        ProviderComplianceScore.objects.create(
            tenant_id=tenant.id,
            provider=provider1,
            scan=scan1,
            compliance_id="aws_cis_2.0",
            requirement_id="req_1",
            requirement_status=StatusChoices.PASS,
            scan_completed_at=scan1.completed_at,
        ),
        ProviderComplianceScore.objects.create(
            tenant_id=tenant.id,
            provider=provider1,
            scan=scan1,
            compliance_id="aws_cis_2.0",
            requirement_id="req_2",
            requirement_status=StatusChoices.FAIL,
            scan_completed_at=scan1.completed_at,
        ),
        ProviderComplianceScore.objects.create(
            tenant_id=tenant.id,
            provider=provider1,
            scan=scan1,
            compliance_id="aws_cis_2.0",
            requirement_id="req_3",
            requirement_status=StatusChoices.MANUAL,
            scan_completed_at=scan1.completed_at,
        ),
        ProviderComplianceScore.objects.create(
            tenant_id=tenant.id,
            provider=provider2,
            scan=scan3,
            compliance_id="aws_cis_2.0",
            requirement_id="req_1",
            requirement_status=StatusChoices.FAIL,
            scan_completed_at=scan3.completed_at,
        ),
        ProviderComplianceScore.objects.create(
            tenant_id=tenant.id,
            provider=provider2,
            scan=scan3,
            compliance_id="aws_cis_2.0",
            requirement_id="req_2",
            requirement_status=StatusChoices.PASS,
            scan_completed_at=scan3.completed_at,
        ),
        ProviderComplianceScore.objects.create(
            tenant_id=tenant.id,
            provider=provider1,
            scan=scan1,
            compliance_id="gdpr_aws",
            requirement_id="gdpr_req_1",
            requirement_status=StatusChoices.PASS,
            scan_completed_at=scan1.completed_at,
        ),
    ]

    return scores


@pytest.fixture
def tenant_compliance_summary_fixture(tenants_fixture):
    """Create TenantComplianceSummary entries for compliance watchlist tests."""
    tenant = tenants_fixture[0]

    summaries = [
        TenantComplianceSummary.objects.create(
            tenant_id=tenant.id,
            compliance_id="aws_cis_2.0",
            requirements_passed=1,
            requirements_failed=2,
            requirements_manual=1,
            total_requirements=4,
        ),
        TenantComplianceSummary.objects.create(
            tenant_id=tenant.id,
            compliance_id="gdpr_aws",
            requirements_passed=5,
            requirements_failed=0,
            requirements_manual=2,
            total_requirements=7,
        ),
    ]

    return summaries


@pytest.fixture
def finding_groups_fixture(tenants_fixture, scans_fixture, resources_fixture):
    """
    Create a comprehensive set of findings for testing Finding Groups aggregation.

    Creates findings for multiple check_ids with varying:
    - Statuses (PASS, FAIL)
    - Severities (critical, high, medium, low)
    - Deltas (new, changed, None)
    - Muted states (True, False)

    This fixture tests aggregation logic for:
    - Multiple findings per check_id
    - Status aggregation (FAIL > PASS > MUTED)
    - Severity aggregation (max severity)
    - Provider aggregation (distinct list)
    - Resource counts
    - Finding counts (pass, fail, muted, new, changed)
    """
    tenant = tenants_fixture[0]
    scan1, scan2, *_ = scans_fixture
    resource1, resource2, *_ = resources_fixture

    findings = []

    # Check 1: s3_bucket_public_access - Multiple FAIL findings (critical)
    # Should aggregate to: status=FAIL, severity=critical, fail_count=2, pass_count=0
    finding1a = Finding.objects.create(
        tenant_id=tenant.id,
        uid="fg_s3_check_1a",
        scan=scan1,
        delta="new",
        status=Status.FAIL,
        status_extended="S3 bucket allows public access",
        impact=Severity.critical,
        impact_extended="Critical security risk",
        severity=Severity.critical,
        raw_result={"status": Status.FAIL, "severity": Severity.critical},
        tags={"env": "prod"},
        check_id="s3_bucket_public_access",
        check_metadata={
            "CheckId": "s3_bucket_public_access",
            "checktitle": "Ensure S3 buckets do not allow public access",
            "Description": "S3 buckets should be configured to restrict public access.",
            "resourcegroup": "storage",
        },
        first_seen_at="2024-01-02T00:00:00Z",
        muted=False,
    )
    finding1a.add_resources([resource1])
    findings.append(finding1a)

    finding1b = Finding.objects.create(
        tenant_id=tenant.id,
        uid="fg_s3_check_1b",
        scan=scan1,
        delta="changed",
        status=Status.FAIL,
        status_extended="S3 bucket allows public read",
        impact=Severity.high,
        impact_extended="High security risk",
        severity=Severity.high,
        raw_result={"status": Status.FAIL, "severity": Severity.high},
        tags={"env": "staging"},
        check_id="s3_bucket_public_access",
        check_metadata={
            "CheckId": "s3_bucket_public_access",
            "checktitle": "Ensure S3 buckets do not allow public access",
            "Description": "S3 buckets should be configured to restrict public access.",
            "resourcegroup": "storage",
        },
        first_seen_at="2024-01-03T00:00:00Z",
        muted=False,
    )
    finding1b.add_resources([resource2])
    findings.append(finding1b)

    # Check 2: ec2_instance_public_ip - Mixed PASS/FAIL (high severity max)
    # Should aggregate to: status=FAIL, severity=high, fail_count=1, pass_count=1
    finding2a = Finding.objects.create(
        tenant_id=tenant.id,
        uid="fg_ec2_check_2a",
        scan=scan1,
        delta=None,
        status=Status.PASS,
        status_extended="EC2 instance has no public IP",
        impact=Severity.medium,
        impact_extended="Medium risk",
        severity=Severity.medium,
        raw_result={"status": Status.PASS, "severity": Severity.medium},
        tags={"env": "dev"},
        check_id="ec2_instance_public_ip",
        check_metadata={
            "CheckId": "ec2_instance_public_ip",
            "checktitle": "Ensure EC2 instances do not have public IPs",
            "Description": "EC2 instances should use private IPs only.",
        },
        first_seen_at="2024-01-04T00:00:00Z",
        muted=False,
    )
    finding2a.add_resources([resource1])
    findings.append(finding2a)

    finding2b = Finding.objects.create(
        tenant_id=tenant.id,
        uid="fg_ec2_check_2b",
        scan=scan1,
        delta="new",
        status=Status.FAIL,
        status_extended="EC2 instance has public IP assigned",
        impact=Severity.high,
        impact_extended="High risk",
        severity=Severity.high,
        raw_result={"status": Status.FAIL, "severity": Severity.high},
        tags={"env": "prod"},
        check_id="ec2_instance_public_ip",
        check_metadata={
            "CheckId": "ec2_instance_public_ip",
            "checktitle": "Ensure EC2 instances do not have public IPs",
            "Description": "EC2 instances should use private IPs only.",
        },
        first_seen_at="2024-01-05T00:00:00Z",
        muted=False,
    )
    finding2b.add_resources([resource2])
    findings.append(finding2b)

    # Check 3: iam_password_policy - All PASS (low severity)
    # Should aggregate to: status=PASS, severity=low, fail_count=0, pass_count=2
    finding3a = Finding.objects.create(
        tenant_id=tenant.id,
        uid="fg_iam_check_3a",
        scan=scan1,
        delta=None,
        status=Status.PASS,
        status_extended="Password policy is compliant",
        impact=Severity.low,
        impact_extended="Low risk",
        severity=Severity.low,
        raw_result={"status": Status.PASS, "severity": Severity.low},
        tags={"env": "prod"},
        check_id="iam_password_policy",
        check_metadata={
            "CheckId": "iam_password_policy",
            "checktitle": "Ensure IAM password policy is strong",
            "Description": "IAM password policy should enforce complexity.",
        },
        first_seen_at="2024-01-06T00:00:00Z",
        muted=False,
    )
    finding3a.add_resources([resource1])
    findings.append(finding3a)

    finding3b = Finding.objects.create(
        tenant_id=tenant.id,
        uid="fg_iam_check_3b",
        scan=scan1,
        delta=None,
        status=Status.PASS,
        status_extended="Password policy meets requirements",
        impact=Severity.low,
        impact_extended="Low risk",
        severity=Severity.low,
        raw_result={"status": Status.PASS, "severity": Severity.low},
        tags={"env": "staging"},
        check_id="iam_password_policy",
        check_metadata={
            "CheckId": "iam_password_policy",
            "checktitle": "Ensure IAM password policy is strong",
            "Description": "IAM password policy should enforce complexity.",
        },
        first_seen_at="2024-01-07T00:00:00Z",
        muted=False,
    )
    finding3b.add_resources([resource2])
    findings.append(finding3b)

    # Check 4: rds_encryption - All muted (medium severity)
    # Should aggregate to: status=MUTED, severity=medium, fail_count=0, pass_count=0, muted_count=2
    finding4a = Finding.objects.create(
        tenant_id=tenant.id,
        uid="fg_rds_check_4a",
        scan=scan1,
        delta=None,
        status=Status.FAIL,
        status_extended="RDS instance not encrypted",
        impact=Severity.medium,
        impact_extended="Medium risk",
        severity=Severity.medium,
        raw_result={"status": Status.FAIL, "severity": Severity.medium},
        tags={"env": "dev"},
        check_id="rds_encryption",
        check_metadata={
            "CheckId": "rds_encryption",
            "checktitle": "Ensure RDS instances are encrypted",
            "Description": "RDS instances should use encryption at rest.",
        },
        first_seen_at="2024-01-08T00:00:00Z",
        muted=True,
    )
    finding4a.add_resources([resource1])
    findings.append(finding4a)

    finding4b = Finding.objects.create(
        tenant_id=tenant.id,
        uid="fg_rds_check_4b",
        scan=scan1,
        delta=None,
        status=Status.FAIL,
        status_extended="RDS encryption disabled",
        impact=Severity.medium,
        impact_extended="Medium risk",
        severity=Severity.medium,
        raw_result={"status": Status.FAIL, "severity": Severity.medium},
        tags={"env": "test"},
        check_id="rds_encryption",
        check_metadata={
            "CheckId": "rds_encryption",
            "checktitle": "Ensure RDS instances are encrypted",
            "Description": "RDS instances should use encryption at rest.",
        },
        first_seen_at="2024-01-09T00:00:00Z",
        muted=True,
    )
    finding4b.add_resources([resource2])
    findings.append(finding4b)

    # Check 5: cloudtrail_enabled - Multiple providers (from scan2 which uses provider2)
    # Should aggregate to: impacted_providers contains both provider types
    finding5 = Finding.objects.create(
        tenant_id=tenant.id,
        uid="fg_cloudtrail_check_5",
        scan=scan2,
        delta="new",
        status=Status.FAIL,
        status_extended="CloudTrail not enabled",
        impact=Severity.critical,
        impact_extended="Critical risk",
        severity=Severity.critical,
        raw_result={"status": Status.FAIL, "severity": Severity.critical},
        tags={"env": "prod"},
        check_id="cloudtrail_enabled",
        check_metadata={
            "CheckId": "cloudtrail_enabled",
            "checktitle": "Ensure CloudTrail is enabled",
            "Description": "CloudTrail should be enabled for audit logging.",
        },
        first_seen_at="2024-01-10T00:00:00Z",
        muted=False,
    )
    finding5.add_resources([resource1])
    findings.append(finding5)

    # Aggregate findings into FindingGroupDailySummary for the endpoint to read
    from tasks.jobs.scan import aggregate_finding_group_summaries

    aggregate_finding_group_summaries(
        tenant_id=str(tenant.id),
        scan_id=str(scan1.id),
    )
    aggregate_finding_group_summaries(
        tenant_id=str(tenant.id),
        scan_id=str(scan2.id),
    )

    return findings


@pytest.fixture
def finding_groups_title_variants_fixture(
    tenants_fixture, scans_fixture, resources_fixture
):
    """
    Two providers report the same check_id with different checktitle values.

    Simulates a Prowler version upgrade where the check title changed but the
    check_id stayed the same.  Used to verify that check_title__icontains
    resolves to check_id first, so results include all providers regardless
    of which title variant matches the search term.
    """
    tenant = tenants_fixture[0]
    scan1, scan2, *_ = scans_fixture
    resource1, resource2, *_ = resources_fixture

    findings = []

    # Provider 1 — OLD title variant
    finding_old = Finding.objects.create(
        tenant_id=tenant.id,
        uid="fg_title_variant_old",
        scan=scan1,
        delta="new",
        status=Status.FAIL,
        status_extended="Secret scanning not enabled",
        impact=Severity.high,
        impact_extended="High risk",
        severity=Severity.high,
        raw_result={"status": Status.FAIL, "severity": Severity.high},
        tags={},
        check_id="github_secret_scanning_enabled",
        check_metadata={
            "CheckId": "github_secret_scanning_enabled",
            "checktitle": "Ensure repository has secret scanning enabled",
            "Description": "Checks if secret scanning is enabled.",
        },
        first_seen_at="2024-01-01T00:00:00Z",
        muted=False,
    )
    finding_old.add_resources([resource1])
    findings.append(finding_old)

    # Provider 2 — NEW title variant (same check_id, different checktitle)
    finding_new = Finding.objects.create(
        tenant_id=tenant.id,
        uid="fg_title_variant_new",
        scan=scan2,
        delta="new",
        status=Status.FAIL,
        status_extended="Secret scanning not enabled on repo",
        impact=Severity.high,
        impact_extended="High risk",
        severity=Severity.high,
        raw_result={"status": Status.FAIL, "severity": Severity.high},
        tags={},
        check_id="github_secret_scanning_enabled",
        check_metadata={
            "CheckId": "github_secret_scanning_enabled",
            "checktitle": "Check if secret scanning is enabled in GitHub",
            "Description": "Checks if secret scanning is enabled.",
        },
        first_seen_at="2024-01-02T00:00:00Z",
        muted=False,
    )
    finding_new.add_resources([resource2])
    findings.append(finding_new)

    from tasks.jobs.scan import aggregate_finding_group_summaries

    aggregate_finding_group_summaries(
        tenant_id=str(tenant.id),
        scan_id=str(scan1.id),
    )
    aggregate_finding_group_summaries(
        tenant_id=str(tenant.id),
        scan_id=str(scan2.id),
    )

    return findings


def pytest_collection_modifyitems(items):
    """Ensure test_rbac.py is executed first."""
    items.sort(key=lambda item: 0 if "test_rbac.py" in item.nodeid else 1)


def pytest_configure(config):
    # Apply the mock before the test session starts. This is necessary to avoid admin error when running the
    # 0004_rbac_missing_admin_roles migration
    patch("api.db_router.MainRouter.admin_db", new="default").start()


def pytest_unconfigure(config):
    # Stop all patches after the test session ends. This is necessary to avoid admin error when running the
    # 0004_rbac_missing_admin_roles migration
    patch.stopall()
