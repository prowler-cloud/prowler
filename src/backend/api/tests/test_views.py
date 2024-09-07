from unittest.mock import Mock, patch

import pytest
from django.urls import reverse
from rest_framework import status

from api.models import Provider, Scan
from api.rls import Tenant
from conftest import API_JSON_CONTENT_TYPE, NO_TENANT_HTTP_STATUS


@pytest.mark.django_db
class TestTenantViewSet:
    @pytest.fixture
    def valid_tenant_payload(self):
        return {
            "name": "Tenant Three",
            "inserted_at": "2023-01-05T00:00:00Z",
            "updated_at": "2023-01-06T00:00:00Z",
        }

    @pytest.fixture
    def invalid_tenant_payload(self):
        return {
            "name": "",
            "inserted_at": "2023-01-05T00:00:00Z",
            "updated_at": "2023-01-06T00:00:00Z",
        }

    def test_tenants_list(self, client, tenants_fixture):
        response = client.get(reverse("tenant-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(tenants_fixture)

    def test_tenants_retrieve(self, client, tenants_fixture):
        tenant1, _ = tenants_fixture
        response = client.get(reverse("tenant-detail", kwargs={"pk": tenant1.id}))
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["name"] == tenant1.name

    def test_tenants_invalid_retrieve(self, client):
        response = client.get(reverse("tenant-detail", kwargs={"pk": "random_id"}))
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tenants_create(self, client, valid_tenant_payload):
        response = client.post(
            reverse("tenant-list"), data=valid_tenant_payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Tenant.objects.count() == 1
        assert Tenant.objects.get().name == valid_tenant_payload["name"]

    def test_tenants_invalid_create(self, client, invalid_tenant_payload):
        response = client.post(
            reverse("tenant-list"),
            data=invalid_tenant_payload,
            format="json",
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_partial_update(self, client, tenants_fixture):
        tenant1, _ = tenants_fixture
        new_name = "This is the new name"
        payload = {
            "data": {
                "type": "Tenant",
                "id": tenant1.id,
                "attributes": {"name": new_name},
            },
        }
        response = client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_200_OK
        tenant1.refresh_from_db()
        assert tenant1.name == new_name

    def test_tenants_partial_update_invalid_content_type(self, client, tenants_fixture):
        tenant1, _ = tenants_fixture
        response = client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}), data={}
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_tenants_partial_update_invalid_content(self, client, tenants_fixture):
        tenant1, _ = tenants_fixture
        new_name = "This is the new name"
        payload = {"name": new_name}
        response = client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_delete(self, client, tenants_fixture):
        tenant1, _ = tenants_fixture
        response = client.delete(reverse("tenant-detail", kwargs={"pk": tenant1.id}))
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert Tenant.objects.count() == 1

    def test_tenants_delete_invalid(self, client):
        response = client.delete(reverse("tenant-detail", kwargs={"pk": "random_id"}))
        # To change if we implement RBAC
        # (user might not have permissions to see if the tenant exists or not -> 200 empty)
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tenants_list_filter_search(self, client, tenants_fixture):
        """Search is applied to tenants_fixture  name."""
        tenant1, _ = tenants_fixture
        response = client.get(reverse("tenant-list"), {"filter[search]": tenant1.name})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["name"] == tenant1.name

    def test_tenants_list_query_param_name(self, client, tenants_fixture):
        tenant1, _ = tenants_fixture
        response = client.get(reverse("tenant-list"), {"name": tenant1.name})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_list_invalid_query_param(self, client):
        response = client.get(reverse("tenant-list"), {"random": "value"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_list_filter_name(self, client, tenants_fixture):
        tenant1, _ = tenants_fixture
        response = client.get(reverse("tenant-list"), {"filter[name]": tenant1.name})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["name"] == tenant1.name

    def test_tenants_list_filter_invalid(self, client):
        response = client.get(reverse("tenant-list"), {"filter[invalid]": "whatever"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_list_page_size(self, client, tenants_fixture):
        page_size = 1

        response = client.get(reverse("tenant-list"), {"page[size]": page_size})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == page_size
        assert response.json()["meta"]["pagination"]["page"] == 1
        assert response.json()["meta"]["pagination"]["pages"] == len(tenants_fixture)

    def test_tenants_list_page_number(self, client, tenants_fixture):
        page_size = 1
        page_number = 2

        response = client.get(
            reverse("tenant-list"),
            {"page[size]": page_size, "page[number]": page_number},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == page_size
        assert response.json()["meta"]["pagination"]["page"] == page_number
        assert response.json()["meta"]["pagination"]["pages"] == len(tenants_fixture)

    def test_tenants_list_sort_name(self, client, tenants_fixture):
        _, tenant2 = tenants_fixture
        response = client.get(reverse("tenant-list"), {"sort": "-name"})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2
        assert response.json()["data"][0]["attributes"]["name"] == tenant2.name


@pytest.mark.django_db
class TestProviderViewSet:
    def test_providers_rls(self, client):
        response = client.get(reverse("provider-list"))
        assert response.status_code == NO_TENANT_HTTP_STATUS

    def test_providers_list(self, client, providers_fixture, tenant_header):
        response = client.get(reverse("provider-list"), headers=tenant_header)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(providers_fixture)

    def test_providers_retrieve(self, client, providers_fixture, tenant_header):
        provider1, *_ = providers_fixture
        response = client.get(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["provider"] == provider1.provider
        assert (
            response.json()["data"]["attributes"]["provider_id"]
            == provider1.provider_id
        )
        assert response.json()["data"]["attributes"]["alias"] == provider1.alias

    def test_providers_invalid_retrieve(self, client, tenant_header):
        response = client.get(
            reverse("provider-detail", kwargs={"pk": "random_id"}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "provider_json_payload",
        (
            [
                {"provider": "aws", "provider_id": "111111111111", "alias": "test"},
                {"provider": "gcp", "provider_id": "a12322-test54321", "alias": "test"},
                {
                    "provider": "kubernetes",
                    "provider_id": "kubernetes-test-123456789",
                    "alias": "test",
                },
                {
                    "provider": "azure",
                    "provider_id": "8851db6b-42e5-4533-aa9e-30a32d67e875",
                    "alias": "test",
                },
            ]
        ),
    )
    def test_providers_create_valid(self, client, tenant_header, provider_json_payload):
        response = client.post(
            reverse("provider-list"),
            data=provider_json_payload,
            format="json",
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Provider.objects.count() == 1
        assert Provider.objects.get().provider == provider_json_payload["provider"]
        assert (
            Provider.objects.get().provider_id == provider_json_payload["provider_id"]
        )
        assert Provider.objects.get().alias == provider_json_payload["alias"]

    @pytest.mark.parametrize(
        "provider_json_payload, error_code, error_pointer",
        (
            [
                (
                    {"provider": "aws", "provider_id": "1", "alias": "test"},
                    "min_length",
                    "provider_id",
                ),
                (
                    {
                        "provider": "aws",
                        "provider_id": "1111111111111",
                        "alias": "test",
                    },
                    "aws-provider-id",
                    "provider_id",
                ),
                (
                    {"provider": "aws", "provider_id": "aaaaaaaaaaaa", "alias": "test"},
                    "aws-provider-id",
                    "provider_id",
                ),
                (
                    {"provider": "gcp", "provider_id": "1234asdf", "alias": "test"},
                    "gcp-provider-id",
                    "provider_id",
                ),
                (
                    {
                        "provider": "kubernetes",
                        "provider_id": "-1234asdf",
                        "alias": "test",
                    },
                    "kubernetes-provider-id",
                    "provider_id",
                ),
                (
                    {
                        "provider": "azure",
                        "provider_id": "8851db6b-42e5-4533-aa9e-30a32d67e87",
                        "alias": "test",
                    },
                    "azure-provider-id",
                    "provider_id",
                ),
                (
                    {
                        "provider": "does-not-exist",
                        "provider_id": "8851db6b-42e5-4533-aa9e-30a32d67e87",
                        "alias": "test",
                    },
                    "invalid_choice",
                    "provider",
                ),
            ]
        ),
    )
    def test_providers_invalid_create(
        self, client, tenant_header, provider_json_payload, error_code, error_pointer
    ):
        response = client.post(
            reverse("provider-list"),
            data=provider_json_payload,
            format="json",
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == error_code
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == f"/data/attributes/{error_pointer}"
        )

    def test_providers_partial_update(self, client, providers_fixture, tenant_header):
        provider1, *_ = providers_fixture
        new_alias = "This is the new name"
        payload = {
            "data": {
                "type": "Provider",
                "id": provider1.id,
                "attributes": {"alias": new_alias},
            },
        }
        response = client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        provider1.refresh_from_db()
        assert provider1.alias == new_alias

    def test_providers_partial_update_invalid_content_type(
        self, client, providers_fixture, tenant_header
    ):
        provider1, *_ = providers_fixture
        response = client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data={},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_providers_partial_update_invalid_content(
        self, client, providers_fixture, tenant_header
    ):
        provider1, *_ = providers_fixture
        new_name = "This is the new name"
        payload = {"alias": new_name}
        response = client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "attribute_key, attribute_value",
        [
            ("provider", "aws"),
            ("provider_id", "123456789012"),
        ],
    )
    def test_providers_partial_update_invalid_fields(
        self, client, providers_fixture, tenant_header, attribute_key, attribute_value
    ):
        provider1, *_ = providers_fixture
        payload = {
            "data": {
                "type": "Provider",
                "id": provider1.id,
                "attributes": {attribute_key: attribute_value},
            },
        }
        response = client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @patch("api.v1.views.delete_provider_task.delay")
    def test_providers_delete(
        self, mock_delete_task, client, providers_fixture, tenant_header
    ):
        task_mock = Mock()
        task_mock.id = "12345"
        mock_delete_task.return_value = task_mock

        provider1, *_ = providers_fixture
        response = client.delete(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        mock_delete_task.assert_called_once_with(
            provider_id=str(provider1.id), tenant_id=tenant_header["X-Tenant-ID"]
        )
        assert "Content-Location" in response.headers
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task_mock.id}"

    def test_providers_delete_invalid(self, client, tenant_header):
        response = client.delete(
            reverse("provider-detail", kwargs={"pk": "random_id"}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @patch("api.v1.views.check_provider_connection_task.delay")
    def test_providers_connection(
        self, mock_provider_connection, client, providers_fixture, tenant_header
    ):
        task_mock = Mock()
        task_mock.id = "12345"
        task_mock.status = "PENDING"
        mock_provider_connection.return_value = task_mock

        provider1, *_ = providers_fixture
        assert provider1.connected is None
        assert provider1.connection_last_checked_at is None

        response = client.post(
            reverse("provider-connection", kwargs={"pk": provider1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        mock_provider_connection.assert_called_once_with(
            provider_id=str(provider1.id), tenant_id=tenant_header["X-Tenant-ID"]
        )
        assert "Content-Location" in response.headers
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task_mock.id}"

    def test_providers_connection_invalid_provider(
        self, client, providers_fixture, tenant_header
    ):
        response = client.post(
            reverse("provider-connection", kwargs={"pk": "random_id"}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "filter_name, filter_value",
        (
            [
                ("provider", "aws"),
                ("provider_id", "12345"),
                ("alias", "test"),
                ("search", "test"),
                ("inserted_at", "2024-01-01 00:00:00"),
                ("updated_at", "2024-01-01 00:00:00"),
            ]
        ),
    )
    def test_providers_filters(self, client, tenant_header, filter_name, filter_value):
        response = client.get(
            reverse("provider-list"),
            {f"filter[{filter_name}]": filter_value},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.parametrize(
        "filter_name",
        (
            [
                "provider",  # Valid filter, invalid value
                "invalid",
            ]
        ),
    )
    def test_providers_filters_invalid(self, client, tenant_header, filter_name):
        response = client.get(
            reverse("provider-list"),
            {f"filter[{filter_name}]": "whatever"},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "sort_field",
        (
            [
                "provider",
                "provider_id",
                "alias",
                "connected",
                "inserted_at",
                "updated_at",
            ]
        ),
    )
    def test_providers_sort(self, client, tenant_header, sort_field):
        response = client.get(
            reverse("provider-list"), {"sort": sort_field}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_200_OK

    def test_providers_sort_invalid(self, client, tenant_header):
        response = client.get(
            reverse("provider-list"), {"sort": "invalid"}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestScanViewSet:
    def test_scans_list(self, client, scans_fixture, tenant_header):
        response = client.get(reverse("scan-list"), headers=tenant_header)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(scans_fixture)

    def test_scans_retrieve(self, client, scans_fixture, tenant_header):
        scan1, *_ = scans_fixture
        response = client.get(
            reverse("scan-detail", kwargs={"pk": scan1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["name"] == scan1.name
        assert response.json()["data"]["relationships"]["provider"]["data"][
            "id"
        ] == str(scan1.provider.id)

    def test_scans_invalid_retrieve(self, client, tenant_header):
        response = client.get(
            reverse("scan-detail", kwargs={"pk": "random_id"}),
            headers=tenant_header,
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
    def test_scans_create_valid(
        self,
        client,
        tenant_header,
        scan_json_payload,
        expected_scanner_args,
        providers_fixture,
    ):
        *_, provider5 = providers_fixture
        # Provider5 has these scanner_args
        # scanner_args={"key1": "value1", "key2": {"key21": "value21"}}

        scan_json_payload["data"]["relationships"]["provider"]["data"]["id"] = str(
            provider5.id
        )

        response = client.post(
            reverse("scan-list"),
            data=scan_json_payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
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
        self, client, tenant_header, scan_json_payload, providers_fixture, error_code
    ):
        provider1, *_ = providers_fixture
        scan_json_payload["data"]["relationships"]["provider"]["data"]["id"] = str(
            provider1.id
        )
        response = client.post(
            reverse("scan-list"),
            data=scan_json_payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == error_code
        assert (
            response.json()["errors"][0]["source"]["pointer"] == "/data/attributes/name"
        )

    def test_scans_partial_update(self, client, scans_fixture, tenant_header):
        scan1, *_ = scans_fixture
        new_name = "Updated Scan Name"
        payload = {
            "data": {
                "type": "Scan",
                "id": scan1.id,
                "attributes": {"name": new_name},
            },
        }
        response = client.patch(
            reverse("scan-detail", kwargs={"pk": scan1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        scan1.refresh_from_db()
        assert scan1.name == new_name

    def test_scans_partial_update_invalid_content_type(
        self, client, scans_fixture, tenant_header
    ):
        scan1, *_ = scans_fixture
        response = client.patch(
            reverse("scan-detail", kwargs={"pk": scan1.id}),
            data={},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_scans_partial_update_invalid_content(
        self, client, scans_fixture, tenant_header
    ):
        scan1, *_ = scans_fixture
        new_name = "Updated Scan Name"
        payload = {"name": new_name}
        response = client.patch(
            reverse("scan-detail", kwargs={"pk": scan1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "filter_name, filter_value",
        [
            ("provider", "aws"),
            ("trigger", Scan.TriggerChoices.MANUAL),
            ("name", "Scan 1"),
            ("started_at", "2024-01-01 00:00:00"),
        ],
    )
    def test_scans_filters(self, client, tenant_header, filter_name, filter_value):
        response = client.get(
            reverse("scan-list"),
            {f"filter[{filter_name}]": filter_value},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.parametrize(
        "filter_name",
        [
            "provider",  # Valid filter, invalid value
            "invalid",
        ],
    )
    def test_scans_filters_invalid(self, client, tenant_header, filter_name):
        response = client.get(
            reverse("scan-list"),
            {f"filter[{filter_name}]": "invalid_value"},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "sort_field",
        [
            "provider_id",
            "name",
            "trigger",
            "inserted_at",
            "updated_at",
        ],
    )
    def test_scans_sort(self, client, tenant_header, sort_field):
        response = client.get(
            reverse("scan-list"), {"sort": sort_field}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_200_OK

    def test_scans_sort_invalid(self, client, tenant_header):
        response = client.get(
            reverse("scan-list"), {"sort": "invalid"}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestTaskViewSet:
    def test_tasks_list(self, client, tasks_fixture, tenant_header):
        response = client.get(reverse("task-list"), headers=tenant_header)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(tasks_fixture)

    def test_tasks_retrieve(self, client, tasks_fixture, tenant_header):
        task1, *_ = tasks_fixture
        response = client.get(
            reverse("task-detail", kwargs={"pk": task1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        assert (
            response.json()["data"]["attributes"]["name"]
            == task1.task_runner_task.task_name
        )

    def test_tasks_invalid_retrieve(self, client, tenant_header):
        response = client.get(
            reverse("task-detail", kwargs={"pk": "invalid_id"}), headers=tenant_header
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @patch("api.v1.views.AsyncResult", return_value=Mock())
    def test_tasks_revoke(
        self, mock_async_result, client, tasks_fixture, tenant_header
    ):
        _, task2 = tasks_fixture
        response = client.delete(
            reverse("task-detail", kwargs={"pk": task2.id}), headers=tenant_header
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task2.id}"
        mock_async_result.return_value.revoke.assert_called_once()

    def test_tasks_invalid_revoke(self, client, tenant_header):
        response = client.delete(
            reverse("task-detail", kwargs={"pk": "invalid_id"}), headers=tenant_header
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tasks_revoke_invalid_status(self, client, tasks_fixture, tenant_header):
        task1, _ = tasks_fixture
        response = client.delete(
            reverse("task-detail", kwargs={"pk": task1.id}), headers=tenant_header
        )
        # Task status is SUCCESS
        assert response.status_code == status.HTTP_400_BAD_REQUEST
