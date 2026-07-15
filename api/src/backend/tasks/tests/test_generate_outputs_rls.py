import pytest
from api.db_utils import rls_transaction
from api.models import (
    Integration,
    IntegrationProviderRelationship,
    Provider,
    ProviderSecret,
)
from django.db import DataError, connections


@pytest.fixture
def enforce_rls():
    """
    Run the assertions under the unprivileged `test` role, on a fresh session.

    The suite normally connects as `prowler_admin`, a superuser, and superusers
    bypass row-level security even on FORCE ROW LEVEL SECURITY tables. Under that
    role a query with no tenant context still returns rows, so nothing here would
    fail. `test` is the role the RLS policies are actually written for.

    The reconnect matters: a session that has already run an `rls_transaction`
    reports the tenant variable as "" rather than NULL, which sends the policy down
    a different branch. Starting clean keeps each test independent of suite order.
    """
    connections["default"].close()
    with connections["default"].cursor() as cursor:
        cursor.execute("SET ROLE test;")
    yield
    with connections["default"].cursor() as cursor:
        cursor.execute("RESET ROLE;")
    connections["default"].close()


@pytest.fixture
def provider_with_secret(tenants_fixture):
    tenant = tenants_fixture[0]
    provider = Provider.objects.create(
        tenant_id=tenant.id,
        provider=Provider.ProviderChoices.AWS.value,
        uid="123456789012",
        alias="rls-scoping",
    )
    ProviderSecret.objects.create(
        tenant_id=tenant.id,
        provider=provider,
        secret_type=ProviderSecret.TypeChoices.STATIC,
        secret={"key": "value"},
        name=provider.alias,
    )
    integration = Integration.objects.create(
        tenant_id=tenant.id,
        enabled=True,
        connected=True,
        integration_type=Integration.IntegrationChoices.AMAZON_S3,
        configuration={"key": "value"},
        credentials={"psswd": "1234"},
    )
    IntegrationProviderRelationship.objects.create(
        tenant_id=tenant.id,
        integration=integration,
        provider=provider,
    )
    return str(tenant.id), str(provider.id)


@pytest.mark.django_db(transaction=True)
class TestGenerateOutputsTenantScoping:
    """
    Pins the assumptions that let `generate_outputs_task` drop `@set_tenant`: every
    query it runs must sit inside an `rls_transaction`, and anything it reads after
    one closes must already be in memory.

    `transaction=True` is required, not incidental. Plain `django_db` wraps the test
    in its own atomic block, which demotes each `rls_transaction` to a savepoint and
    leaves the transaction-scoped tenant variable set for the rest of the test. Every
    assertion about a query running *outside* tenant context would then pass for the
    wrong reason.
    """

    def test_rls_denies_reads_without_tenant_context(
        self, provider_with_secret, enforce_rls
    ):
        # enforce_rls reconnects as the unprivileged `test` role for the whole
        # test; pytest injects it by parameter name, so it is referenced
        # explicitly to keep static analysers from flagging it as unused.
        del enforce_rls
        # Guard for the tests below: proves the `test` role really is subject to
        # RLS, otherwise passing assertions here would mean nothing.
        _, provider_id = provider_with_secret

        assert not Provider.objects.filter(id=provider_id).exists()

    def test_rls_allows_reads_inside_an_rls_transaction(
        self, provider_with_secret, enforce_rls
    ):
        del enforce_rls
        tenant_id, provider_id = provider_with_secret

        with rls_transaction(tenant_id):
            assert Provider.objects.filter(id=provider_id).exists()

    def test_select_related_secret_survives_the_transaction(
        self, provider_with_secret, enforce_rls
    ):
        del enforce_rls
        tenant_id, provider_id = provider_with_secret

        with rls_transaction(tenant_id):
            provider = Provider.objects.select_related("secret").get(id=provider_id)

        # initialize_prowler_provider reads `secret` out here, with no tenant
        # context. It only works because select_related already cached it.
        assert provider.secret.secret == {"key": "value"}

    def test_secret_without_select_related_is_lost_after_the_transaction(
        self, provider_with_secret, enforce_rls
    ):
        del enforce_rls
        tenant_id, provider_id = provider_with_secret

        with rls_transaction(tenant_id):
            provider = Provider.objects.get(id=provider_id)

        # The regression select_related guards against: a lazy relation resolved
        # after the transaction never reaches the row.
        with pytest.raises(DataError):
            provider.secret

    def test_lazy_queryset_does_not_reach_the_rows_after_the_transaction(
        self, provider_with_secret, enforce_rls
    ):
        del enforce_rls
        tenant_id, provider_id = provider_with_secret

        with rls_transaction(tenant_id):
            lazy = Integration.objects.filter(
                integrationproviderrelationship__provider_id=provider_id,
                integration_type=Integration.IntegrationChoices.AMAZON_S3,
                enabled=True,
            )
            materialized = list(
                Integration.objects.filter(
                    integrationproviderrelationship__provider_id=provider_id,
                    integration_type=Integration.IntegrationChoices.AMAZON_S3,
                    enabled=True,
                )
            )

        # The lazy queryset only runs its query here, and by then the tenant
        # variable is gone. Once a transaction has set and discarded it,
        # current_setting returns "" rather than NULL, so the policy's
        # ""::uuid cast errors instead of taking the NULL branch that yields no
        # rows (see test_rls_denies_reads_without_tenant_context). Wrong either
        # way, which is why the S3 lookup is materialized with list().
        assert len(materialized) == 1
        with pytest.raises(DataError):
            list(lazy)
