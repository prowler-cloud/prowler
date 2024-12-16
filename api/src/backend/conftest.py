import logging
from datetime import datetime, timedelta, timezone

import pytest
from django.conf import settings
from django.db import connection as django_connection
from django.db import connections as django_connections
from django.urls import reverse
from django_celery_results.models import TaskResult
from rest_framework import status
from rest_framework.test import APIClient

from api.models import (
    ComplianceOverview,
    Finding,
    Invitation,
    Membership,
    Provider,
    ProviderGroup,
    ProviderSecret,
    Resource,
    ResourceTag,
    Scan,
    StateChoices,
    Task,
    User,
)
from api.rls import Tenant
from api.v1.serializers import TokenSerializer
from prowler.lib.check.models import Severity
from prowler.lib.outputs.finding import Status

API_JSON_CONTENT_TYPE = "application/vnd.api+json"
NO_TENANT_HTTP_STATUS = status.HTTP_401_UNAUTHORIZED
TEST_USER = "dev@prowler.com"
TEST_PASSWORD = "testing_psswd"


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


@pytest.fixture(scope="session", autouse=True)
def create_test_user(django_db_setup, django_db_blocker):
    with django_db_blocker.unblock():
        user = User.objects.create_user(
            name="testing",
            email=TEST_USER,
            password=TEST_PASSWORD,
        )
    return user


@pytest.fixture
def authenticated_client(create_test_user, tenants_fixture, client):
    client.user = create_test_user
    serializer = TokenSerializer(
        data={"type": "tokens", "email": TEST_USER, "password": TEST_PASSWORD}
    )
    serializer.is_valid()
    access_token = serializer.validated_data["access"]
    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"
    return client


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
def invitations_fixture(create_test_user, tenants_fixture):
    user = create_test_user
    *_, tenant = tenants_fixture
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
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        inviter=user,
        tenant=tenant,
    )
    return valid_invitation, expired_invitation


@pytest.fixture
def providers_fixture(tenants_fixture):
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
    provider3 = Provider.objects.create(
        provider="gcp",
        uid="a12322-test321",
        alias="gcp_testing",
        tenant_id=tenant.id,
    )
    provider4 = Provider.objects.create(
        provider="kubernetes",
        uid="kubernetes-test-12345",
        alias="k8s_testing",
        tenant_id=tenant.id,
    )
    provider5 = Provider.objects.create(
        provider="azure",
        uid="37b065f8-26b0-4218-a665-0b23d07b27d9",
        alias="azure_testing",
        tenant_id=tenant.id,
        scanner_args={"key1": "value1", "key2": {"key21": "value21"}},
    )

    return provider1, provider2, provider3, provider4, provider5


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
def provider_secret_fixture(providers_fixture):
    return tuple(
        ProviderSecret.objects.create(
            tenant_id=provider.tenant_id,
            provider=provider,
            secret_type=ProviderSecret.TypeChoices.STATIC,
            secret={"key": "value"},
            name=provider.alias,
        )
        for provider in providers_fixture
    )


@pytest.fixture
def scans_fixture(tenants_fixture, providers_fixture):
    tenant, *_ = tenants_fixture
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
        service="s3",
        type="prowler-test",
    )
    resource2.upsert_or_delete_tags(tags)

    resource3 = Resource.objects.create(
        tenant_id=providers_fixture[1].tenant_id,
        provider=providers_fixture[1],
        uid="arn:aws:ec2:us-east-1:123456789012:bucket/i-1234567890abcdef2",
        name="My Bucket 3",
        region="us-east-1",
        service="ec2",
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
        },
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
        },
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


def get_authorization_header(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}
