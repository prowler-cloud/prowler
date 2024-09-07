import logging

import pytest
from django.conf import settings
from django.db import connections as django_connections
from rest_framework import status
from django_celery_results.models import TaskResult
from api.models import Provider, Scan, StateChoices, Task
from api.rls import Tenant

API_JSON_CONTENT_TYPE = "application/vnd.api+json"
# TODO Change to 401 when authentication/authorization is implemented
NO_TENANT_HTTP_STATUS = status.HTTP_403_FORBIDDEN


@pytest.fixture(scope="module")
def enforce_test_user_db_connection(django_db_setup, django_db_blocker):
    """Ensure tests use the test user for database connections."""
    with django_db_blocker.unblock():
        test_user = "test"
        test_password = "test"
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


@pytest.fixture
def tenants_fixture():
    tenant1 = Tenant.objects.create(
        name="Tenant One",
        inserted_at="2023-01-01T00:00:00Z",
        updated_at="2023-01-02T00:00:00Z",
    )
    tenant2 = Tenant.objects.create(
        name="Tenant Two",
        inserted_at="2023-01-03T00:00:00Z",
        updated_at="2023-01-04T00:00:00Z",
    )
    return tenant1, tenant2


@pytest.fixture
def providers_fixture(tenants_fixture):
    tenant, _ = tenants_fixture
    provider1 = Provider.objects.create(
        provider="aws",
        provider_id="123456789012",
        alias="aws_testing_1",
        tenant_id=tenant.id,
    )
    provider2 = Provider.objects.create(
        provider="aws",
        provider_id="123456789013",
        alias="aws_testing_2",
        tenant_id=tenant.id,
    )
    provider3 = Provider.objects.create(
        provider="gcp",
        provider_id="a12322-test321",
        alias="gcp_testing",
        tenant_id=tenant.id,
    )
    provider4 = Provider.objects.create(
        provider="kubernetes",
        provider_id="kubernetes-test-12345",
        alias="k8s_testing",
        tenant_id=tenant.id,
    )
    provider5 = Provider.objects.create(
        provider="azure",
        provider_id="37b065f8-26b0-4218-a665-0b23d07b27d9",
        alias="azure_testing",
        tenant_id=tenant.id,
        scanner_args={"key1": "value1", "key2": {"key21": "value21"}},
    )

    return provider1, provider2, provider3, provider4, provider5


@pytest.fixture
def scans_fixture(tenants_fixture, providers_fixture):
    tenant, _ = tenants_fixture
    provider, *_ = providers_fixture

    scan1 = Scan.objects.create(
        name="Scan 1",
        provider=provider,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.AVAILABLE,
        tenant_id=tenant.id,
    )
    scan2 = Scan.objects.create(
        name="Scan 2",
        provider=provider,
        trigger=Scan.TriggerChoices.SCHEDULED,
        state=StateChoices.FAILED,
        tenant_id=tenant.id,
    )
    scan3 = Scan.objects.create(
        name="Scan 3",
        provider=provider,
        trigger=Scan.TriggerChoices.SCHEDULED,
        state=StateChoices.AVAILABLE,
        tenant_id=tenant.id,
    )
    return scan1, scan2, scan3


@pytest.fixture
def tasks_fixture(tenants_fixture):
    tenant, _ = tenants_fixture

    task_runner_task1 = TaskResult.objects.create(
        task_id="81a1b34b-ff6e-498e-979c-d6a83260167f",
        task_name="task_runner_task1",
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
def tenant_header(tenants_fixture):
    return {"X-Tenant-ID": str(tenants_fixture[0].id)}
