import logging

import pytest
from django.conf import settings
from django.db import connections as django_connections
from rest_framework import status
from django_celery_results.models import TaskResult
from api.models import Provider, Resource, ResourceTag, Scan, StateChoices, Task
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
    )
    tenant2 = Tenant.objects.create(
        name="Tenant Two",
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
    provider, provider2, *_ = providers_fixture

    scan1 = Scan.objects.create(
        name="Scan 1",
        provider=provider,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.AVAILABLE,
        tenant_id=tenant.id,
        started_at="2024-01-02T00:00:00Z",
    )
    scan2 = Scan.objects.create(
        name="Scan 2",
        provider=provider,
        trigger=Scan.TriggerChoices.SCHEDULED,
        state=StateChoices.FAILED,
        tenant_id=tenant.id,
        started_at="2024-01-02T00:00:00Z",
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
    tenant, _ = tenants_fixture

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
def resources_fixture(providers_fixture):
    provider, *_ = providers_fixture

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
    )

    resource1.upsert_or_delete_tags(tags)

    resource2 = Resource.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        uid="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef1",
        name="My Instance 2",
        region="eu-west-1",
        service="ec2",
        type="prowler-test",
    )
    resource2.upsert_or_delete_tags(tags)

    resource3 = Resource.objects.create(
        tenant_id=providers_fixture[1].tenant_id,
        provider=providers_fixture[1],
        uid="arn:aws:ec2:us-east-1:123456789012:bucket/i-1234567890abcdef2",
        name="My Bucket 3",
        region="us-east-1",
        service="s3",
        type="test",
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
def tenant_header(tenants_fixture):
    return {"X-Tenant-ID": str(tenants_fixture[0].id)}
