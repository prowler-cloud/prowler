# Example: Prowler API Test Patterns
# Source: api/src/backend/api/tests/test_views.py

from unittest.mock import Mock, patch

import pytest
from conftest import (
    API_JSON_CONTENT_TYPE,
    TEST_PASSWORD,
    TEST_USER,
    get_api_tokens,
    get_authorization_header,
)
from django.urls import reverse
from rest_framework import status

from api.models import Provider, Scan, StateChoices
from api.rls import Tenant


@pytest.mark.django_db
class TestProviderViewSet:
    """Example API tests for Provider endpoints."""

    def test_list_providers(self, authenticated_client, providers_fixture):
        """GET list returns all providers for authenticated tenant."""
        response = authenticated_client.get(reverse("provider-list"))

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(providers_fixture)

    def test_create_provider(self, authenticated_client):
        """POST with JSON:API format creates provider."""
        response = authenticated_client.post(
            reverse("provider-list"),
            data={
                "data": {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "123456789012",
                        "alias": "my-aws-account",
                    },
                }
            },
            format="vnd.api+json",  # Use format= for POST
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["data"]["attributes"]["uid"] == "123456789012"

    def test_update_provider(self, authenticated_client, providers_fixture):
        """PATCH with JSON:API format updates provider."""
        provider = providers_fixture[0]

        payload = {
            "data": {
                "type": "providers",
                "id": str(provider.id),  # ID required for PATCH
                "attributes": {"alias": "updated-alias"},
            }
        }

        response = authenticated_client.patch(
            reverse("provider-detail", kwargs={"pk": provider.id}),
            data=payload,
            content_type="application/vnd.api+json",  # Use content_type= for PATCH
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["alias"] == "updated-alias"


@pytest.mark.django_db
class TestRLSIsolation:
    """Example RLS cross-tenant isolation tests."""

    def test_cross_tenant_access_returns_404(
        self, authenticated_client, tenants_fixture
    ):
        """User cannot see resources from other tenants - returns 404 NOT 403."""
        # Create resource in tenant user has NO access to (tenant[2] is isolated)
        other_tenant = tenants_fixture[2]
        foreign_provider = Provider.objects.create(
            provider="aws",
            uid="999888777666",
            alias="foreign_provider",
            tenant_id=other_tenant.id,
        )

        # Try to access - should get 404 (not 403!)
        response = authenticated_client.get(
            reverse("provider-detail", args=[foreign_provider.id])
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_excludes_other_tenants(
        self, authenticated_client, providers_fixture, tenants_fixture
    ):
        """List endpoints only return resources from user's tenants."""
        # Create provider in isolated tenant
        other_tenant = tenants_fixture[2]
        Provider.objects.create(
            provider="aws",
            uid="foreign123",
            tenant_id=other_tenant.id,
        )

        response = authenticated_client.get(reverse("provider-list"))
        assert response.status_code == status.HTTP_200_OK

        # Should only see providers_fixture (9 providers in tenant[0])
        assert len(response.json()["data"]) == len(providers_fixture)


@pytest.mark.django_db
class TestRBACPermissions:
    """Example RBAC permission tests."""

    def test_requires_permission(self, authenticated_client_no_permissions_rbac):
        """Users without manage_providers cannot create providers."""
        response = authenticated_client_no_permissions_rbac.post(
            reverse("provider-list"),
            data={
                "data": {
                    "type": "providers",
                    "attributes": {"provider": "aws", "uid": "123456789012"},
                }
            },
            format="vnd.api+json",
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_user_with_no_roles_denied(self, authenticated_client_rbac_noroles):
        """User with membership but no roles gets 403."""
        response = authenticated_client_rbac_noroles.get(reverse("user-list"))
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_admin_sees_all(self, authenticated_client_rbac, providers_fixture):
        """Admin with unlimited_visibility=True sees all providers."""
        response = authenticated_client_rbac.get(reverse("provider-list"))
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
class TestAsyncOperations:
    """Example async task tests - mock BOTH .delay() AND Task.objects.get."""

    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.delete_provider_task.delay")
    def test_delete_provider_returns_202(
        self,
        mock_delete_task,
        mock_task_get,
        authenticated_client,
        providers_fixture,
        tasks_fixture,
    ):
        """DELETE returns 202 Accepted with Content-Location header."""
        provider = providers_fixture[0]
        prowler_task = tasks_fixture[0]

        # Mock the Celery task
        task_mock = Mock()
        task_mock.id = prowler_task.id
        mock_delete_task.return_value = task_mock
        mock_task_get.return_value = prowler_task

        response = authenticated_client.delete(
            reverse("provider-detail", kwargs={"pk": provider.id})
        )

        assert response.status_code == status.HTTP_202_ACCEPTED
        assert "Content-Location" in response.headers
        assert f"/api/v1/tasks/{prowler_task.id}" in response.headers["Content-Location"]

        # Verify task was called
        mock_delete_task.assert_called_once()

    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.perform_scan_task.delay")
    def test_trigger_scan_returns_202(
        self,
        mock_scan_task,
        mock_task_get,
        authenticated_client,
        providers_fixture,
        tasks_fixture,
    ):
        """POST to scan trigger returns 202 with task location."""
        provider = providers_fixture[0]
        prowler_task = tasks_fixture[0]

        task_mock = Mock()
        task_mock.id = prowler_task.id
        mock_scan_task.return_value = task_mock
        mock_task_get.return_value = prowler_task

        response = authenticated_client.post(
            reverse("provider-scan", kwargs={"pk": provider.id}),
            format="vnd.api+json",
        )

        assert response.status_code == status.HTTP_202_ACCEPTED


@pytest.mark.django_db
class TestJSONAPIResponses:
    """Example JSON:API response handling."""

    def test_read_single_resource(self, authenticated_client, providers_fixture):
        """Read data from single resource response."""
        provider = providers_fixture[0]
        response = authenticated_client.get(
            reverse("provider-detail", kwargs={"pk": provider.id})
        )

        data = response.json()["data"]
        attrs = data["attributes"]
        resource_id = data["id"]

        assert resource_id == str(provider.id)
        assert attrs["provider"] == provider.provider

    def test_read_list_response(self, authenticated_client, providers_fixture):
        """Read data from list response."""
        response = authenticated_client.get(reverse("provider-list"))

        items = response.json()["data"]
        assert len(items) == len(providers_fixture)

    def test_read_relationships(self, authenticated_client, scans_fixture):
        """Read relationship data."""
        scan = scans_fixture[0]
        response = authenticated_client.get(
            reverse("scan-detail", kwargs={"pk": scan.id})
        )

        data = response.json()["data"]
        relationships = data["relationships"]
        provider_rel = relationships["provider"]["data"]

        assert provider_rel["type"] == "providers"
        assert provider_rel["id"] == str(scan.provider_id)

    def test_error_response(self, authenticated_client):
        """Read error response structure."""
        response = authenticated_client.post(
            reverse("user-list"),
            data={"email": "invalid"},  # Missing required fields
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        # Error has source.pointer and detail
        assert "source" in errors[0]
        assert "detail" in errors[0]


@pytest.mark.django_db
class TestSoftDelete:
    """Example soft-delete manager tests."""

    def test_objects_excludes_soft_deleted(self, providers_fixture):
        """Default manager excludes soft-deleted records."""
        provider = providers_fixture[0]
        provider.is_deleted = True
        provider.save()

        # objects manager excludes deleted
        assert provider not in Provider.objects.all()

        # all_objects includes deleted
        assert provider in Provider.all_objects.all()


# =============================================================================
# CELERY TASK TESTING
# =============================================================================


@pytest.mark.django_db
class TestCeleryTaskLogic:
    """Example: Testing Celery task logic directly with apply()."""

    def test_task_logic_directly(self, tenants_fixture, providers_fixture):
        """Use apply() for synchronous execution without Celery worker."""
        from tasks.tasks import check_provider_connection_task

        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        # Execute task synchronously (no broker needed)
        result = check_provider_connection_task.apply(
            kwargs={"tenant_id": str(tenant.id), "provider_id": str(provider.id)}
        )

        assert result.successful()
        assert result.result["connected"] is True


@pytest.mark.django_db
class TestCeleryCanvas:
    """Example: Testing Canvas (chain/group) task orchestration."""

    @patch("tasks.tasks.chain")
    @patch("tasks.tasks.group")
    def test_post_scan_workflow(self, mock_group, mock_chain, tenants_fixture):
        """Mock chain/group to verify task orchestration."""
        from tasks.tasks import _perform_scan_complete_tasks

        tenant = tenants_fixture[0]

        # Mock chain.apply_async
        mock_chain_instance = Mock()
        mock_chain.return_value = mock_chain_instance

        _perform_scan_complete_tasks(str(tenant.id), "scan-123", "provider-456")

        # Verify chain was called
        assert mock_chain.called
        mock_chain_instance.apply_async.assert_called()


@pytest.mark.django_db
class TestSetTenantDecorator:
    """Example: Testing @set_tenant decorator behavior."""

    @patch("api.decorators.connection")
    def test_sets_rls_context(self, mock_conn, tenants_fixture, providers_fixture):
        """Verify @set_tenant sets RLS context via SET_CONFIG_QUERY."""
        from tasks.tasks import check_provider_connection_task

        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        # Call task with tenant_id - decorator sets RLS and pops it
        check_provider_connection_task.apply(
            kwargs={"tenant_id": str(tenant.id), "provider_id": str(provider.id)}
        )

        # Verify SET_CONFIG_QUERY was executed
        mock_conn.cursor.return_value.__enter__.return_value.execute.assert_called()


@pytest.mark.django_db
class TestBeatScheduling:
    """Example: Testing Beat scheduled task creation."""

    @patch("tasks.beat.perform_scheduled_scan_task.apply_async")
    def test_schedule_provider_scan(self, mock_apply, providers_fixture):
        """Verify periodic task is created with correct settings."""
        from django_celery_beat.models import PeriodicTask

        from tasks.beat import schedule_provider_scan

        provider = providers_fixture[0]
        mock_apply.return_value = Mock(id="task-123")

        schedule_provider_scan(provider)

        # Verify periodic task created
        assert PeriodicTask.objects.filter(
            name=f"scan-perform-scheduled-{provider.id}"
        ).exists()

        # Verify immediate execution with countdown
        mock_apply.assert_called_once()
        call_kwargs = mock_apply.call_args
        assert call_kwargs.kwargs.get("countdown") == 5
