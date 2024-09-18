from datetime import datetime
from unittest.mock import Mock, patch

import pytest
from django.urls import reverse
from rest_framework import status

from api.models import User, Provider, Scan
from api.rls import Tenant
from conftest import API_JSON_CONTENT_TYPE, NO_TENANT_HTTP_STATUS

TODAY = str(datetime.today().date())


@pytest.mark.django_db
class TestUserViewSet:
    def test_users_list_not_allowed(self, authenticated_client):
        response = authenticated_client.get(reverse("user-list"))
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_users_retrieve_not_allowed(self, authenticated_client, create_test_user):
        response = authenticated_client.get(
            reverse("user-detail", kwargs={"pk": create_test_user.id})
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_users_me(self, authenticated_client, create_test_user):
        response = authenticated_client.get(reverse("user-me"))
        assert response.status_code == status.HTTP_200_OK
        assert (
            response.json()["data"]["attributes"]["username"]
            == create_test_user.username
        )

    def test_users_create(self, client):
        valid_user_payload = {
            "username": "newuser",
            "password": "newpassword123",
            "email": "newuser@example.com",
        }
        response = client.post(
            reverse("user-list"), data=valid_user_payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert User.objects.filter(username="newuser").exists()
        assert response.json()["data"]["attributes"]["username"] == "newuser"

    def test_users_invalid_create(self, client):
        invalid_user_payload = {
            "username": "theusernameisfine",
            "password": "thepasswordisfine123",
            "email": "invalidemail",
        }
        response = client.post(
            reverse("user-list"), data=invalid_user_payload, format="json"
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            response.json()["errors"][0]["source"]["pointer"]
            == "/data/attributes/email"
        )

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
            # Fails UserAttributeSimilarityValidator (too similar to username or email)
            "thisisfine",
            "thisisfine1",
            "thisisafineemail",
            "thisisafineemail@prowler.com",
            # Fails multiple validators
            "password1",  # Common password and too similar to a common password
            "thisisfine123",  # Similar to username
            ("querty12" * 9) + "a",  # Too long, 73 characters
        ],
    )
    def test_users_create_invalid_passwords(self, authenticated_client, password):
        invalid_user_payload = {
            "username": "thisisfine",
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

    def test_users_partial_update(self, authenticated_client, create_test_user):
        new_email = "updated@example.com"
        payload = {
            "data": {
                "type": "User",
                "id": str(create_test_user.id),
                "attributes": {"email": new_email},
            },
        }
        response = authenticated_client.patch(
            reverse("user-detail", kwargs={"pk": create_test_user.id}),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        create_test_user.refresh_from_db()
        assert create_test_user.email == new_email

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
            username="otheruser", password="otherpassword", email="other@example.com"
        )
        new_email = "new@example.com"
        payload = {
            "data": {
                "type": "User",
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
            # Fails UserAttributeSimilarityValidator (too similar to username or email)
            "testing123",
            "thisistesting",
            "testing@gmail.com",
        ],
    )
    def test_users_partial_update_invalid_password(
        self, authenticated_client, create_test_user, password
    ):
        payload = {
            "data": {
                "type": "User",
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

    def test_users_destroy_invalid_user(self, authenticated_client, create_test_user):
        another_user = User.objects.create_user(
            username="otheruser", password="otherpassword", email="other@example.com"
        )
        response = authenticated_client.delete(
            reverse("user-detail", kwargs={"pk": another_user.id})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert User.objects.filter(id=another_user.id).exists()

    @pytest.mark.parametrize(
        "attribute_key, attribute_value, error_field",
        [
            ("username", "", "username"),
            ("password", "", "password"),
            ("email", "invalidemail", "email"),
        ],
    )
    def test_users_create_invalid_fields(
        self, client, attribute_key, attribute_value, error_field
    ):
        invalid_payload = {
            "username": "testuser",
            "password": "testpassword",
            "email": "test@example.com",
        }
        invalid_payload[attribute_key] = attribute_value
        response = client.post(
            reverse("user-list"), data=invalid_payload, format="json"
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert error_field in response.json()["errors"][0]["source"]["pointer"]

    def test_users_create_existing_username(self, client, create_test_user):
        payload = {
            "username": create_test_user.username,
            "password": "newpassword123",
            "email": "newemail@example.com",
        }
        response = client.post(reverse("user-list"), data=payload, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST


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

    def test_tenants_list(self, authenticated_client, tenants_fixture):
        response = authenticated_client.get(reverse("tenant-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(tenants_fixture)

    def test_tenants_retrieve(self, authenticated_client, tenants_fixture):
        tenant1, _ = tenants_fixture
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
        assert Tenant.objects.count() == 1
        assert Tenant.objects.get().name == valid_tenant_payload["name"]

    def test_tenants_invalid_create(self, authenticated_client, invalid_tenant_payload):
        response = authenticated_client.post(
            reverse("tenant-list"),
            data=invalid_tenant_payload,
            format="json",
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_partial_update(self, authenticated_client, tenants_fixture):
        tenant1, _ = tenants_fixture
        new_name = "This is the new name"
        payload = {
            "data": {
                "type": "Tenant",
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
        tenant1, _ = tenants_fixture
        response = authenticated_client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}), data={}
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_tenants_partial_update_invalid_content(
        self, authenticated_client, tenants_fixture
    ):
        tenant1, _ = tenants_fixture
        new_name = "This is the new name"
        payload = {"name": new_name}
        response = authenticated_client.patch(
            reverse("tenant-detail", kwargs={"pk": tenant1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_tenants_delete(self, authenticated_client, tenants_fixture):
        tenant1, _ = tenants_fixture
        response = authenticated_client.delete(
            reverse("tenant-detail", kwargs={"pk": tenant1.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert Tenant.objects.count() == 1

    def test_tenants_delete_invalid(self, authenticated_client):
        response = authenticated_client.delete(
            reverse("tenant-detail", kwargs={"pk": "random_id"})
        )
        # To change if we implement RBAC
        # (user might not have permissions to see if the tenant exists or not -> 200 empty)
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tenants_list_filter_search(self, authenticated_client, tenants_fixture):
        """Search is applied to tenants_fixture  name."""
        tenant1, _ = tenants_fixture
        response = authenticated_client.get(
            reverse("tenant-list"), {"filter[search]": tenant1.name}
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 1
        assert response.json()["data"][0]["attributes"]["name"] == tenant1.name

    def test_tenants_list_query_param_name(self, authenticated_client, tenants_fixture):
        tenant1, _ = tenants_fixture
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
        tenant_header,
        filter_name,
        filter_value,
        expected_count,
    ):
        response = authenticated_client.get(
            reverse("tenant-list"),
            {f"filter[{filter_name}]": filter_value},
            headers=tenant_header,
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
        assert response.json()["meta"]["pagination"]["pages"] == len(tenants_fixture)

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
        assert response.json()["meta"]["pagination"]["pages"] == len(tenants_fixture)

    def test_tenants_list_sort_name(self, authenticated_client, tenants_fixture):
        _, tenant2 = tenants_fixture
        response = authenticated_client.get(reverse("tenant-list"), {"sort": "-name"})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2
        assert response.json()["data"][0]["attributes"]["name"] == tenant2.name


@pytest.mark.django_db
class TestProviderViewSet:
    def test_providers_rls(self, authenticated_client):
        response = authenticated_client.get(reverse("provider-list"))
        assert response.status_code == NO_TENANT_HTTP_STATUS

    def test_providers_list(
        self, authenticated_client, providers_fixture, tenant_header
    ):
        response = authenticated_client.get(
            reverse("provider-list"), headers=tenant_header
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(providers_fixture)

    def test_providers_retrieve(
        self, authenticated_client, providers_fixture, tenant_header
    ):
        provider1, *_ = providers_fixture
        response = authenticated_client.get(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["provider"] == provider1.provider
        assert response.json()["data"]["attributes"]["uid"] == provider1.uid
        assert response.json()["data"]["attributes"]["alias"] == provider1.alias

    def test_providers_invalid_retrieve(self, authenticated_client, tenant_header):
        response = authenticated_client.get(
            reverse("provider-detail", kwargs={"pk": "random_id"}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "provider_json_payload",
        (
            [
                {"provider": "aws", "uid": "111111111111", "alias": "test"},
                {"provider": "gcp", "uid": "a12322-test54321", "alias": "test"},
                {
                    "provider": "kubernetes",
                    "uid": "kubernetes-test-123456789",
                    "alias": "test",
                },
                {
                    "provider": "azure",
                    "uid": "8851db6b-42e5-4533-aa9e-30a32d67e875",
                    "alias": "test",
                },
            ]
        ),
    )
    def test_providers_create_valid(
        self, authenticated_client, tenant_header, provider_json_payload
    ):
        response = authenticated_client.post(
            reverse("provider-list"),
            data=provider_json_payload,
            format="json",
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert Provider.objects.count() == 1
        assert Provider.objects.get().provider == provider_json_payload["provider"]
        assert Provider.objects.get().uid == provider_json_payload["uid"]
        assert Provider.objects.get().alias == provider_json_payload["alias"]

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
            ]
        ),
    )
    def test_providers_invalid_create(
        self,
        authenticated_client,
        tenant_header,
        provider_json_payload,
        error_code,
        error_pointer,
    ):
        response = authenticated_client.post(
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

    def test_providers_partial_update(
        self, authenticated_client, providers_fixture, tenant_header
    ):
        provider1, *_ = providers_fixture
        new_alias = "This is the new name"
        payload = {
            "data": {
                "type": "Provider",
                "id": provider1.id,
                "attributes": {"alias": new_alias},
            },
        }
        response = authenticated_client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        provider1.refresh_from_db()
        assert provider1.alias == new_alias

    def test_providers_partial_update_invalid_content_type(
        self, authenticated_client, providers_fixture, tenant_header
    ):
        provider1, *_ = providers_fixture
        response = authenticated_client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data={},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_providers_partial_update_invalid_content(
        self, authenticated_client, providers_fixture, tenant_header
    ):
        provider1, *_ = providers_fixture
        new_name = "This is the new name"
        payload = {"alias": new_name}
        response = authenticated_client.patch(
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
            ("uid", "123456789012"),
        ],
    )
    def test_providers_partial_update_invalid_fields(
        self,
        authenticated_client,
        providers_fixture,
        tenant_header,
        attribute_key,
        attribute_value,
    ):
        provider1, *_ = providers_fixture
        payload = {
            "data": {
                "type": "Provider",
                "id": provider1.id,
                "attributes": {attribute_key: attribute_value},
            },
        }
        response = authenticated_client.patch(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @patch("api.v1.views.delete_provider_task.delay")
    def test_providers_delete(
        self, mock_delete_task, authenticated_client, providers_fixture, tenant_header
    ):
        task_mock = Mock()
        task_mock.id = "12345"
        mock_delete_task.return_value = task_mock

        provider1, *_ = providers_fixture
        response = authenticated_client.delete(
            reverse("provider-detail", kwargs={"pk": provider1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        mock_delete_task.assert_called_once_with(
            provider_id=str(provider1.id), tenant_id=tenant_header["X-Tenant-ID"]
        )
        assert "Content-Location" in response.headers
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task_mock.id}"

    def test_providers_delete_invalid(self, authenticated_client, tenant_header):
        response = authenticated_client.delete(
            reverse("provider-detail", kwargs={"pk": "random_id"}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @patch("api.v1.views.check_provider_connection_task.delay")
    def test_providers_connection(
        self,
        mock_provider_connection,
        authenticated_client,
        providers_fixture,
        tenant_header,
    ):
        task_mock = Mock()
        task_mock.id = "12345"
        task_mock.status = "PENDING"
        mock_provider_connection.return_value = task_mock

        provider1, *_ = providers_fixture
        assert provider1.connected is None
        assert provider1.connection_last_checked_at is None

        response = authenticated_client.post(
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
        self, authenticated_client, providers_fixture, tenant_header
    ):
        response = authenticated_client.post(
            reverse("provider-connection", kwargs={"pk": "random_id"}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize(
        "filter_name, filter_value, expected_count",
        (
            [
                ("provider", "aws", 2),
                ("provider.in", "azure,gcp", 2),
                ("uid", "123456789012", 1),
                ("uid.icontains", "1", 5),
                ("alias", "aws_testing_1", 1),
                ("alias.icontains", "aws", 2),
                ("inserted_at", TODAY, 5),
                ("inserted_at.gte", "2024-01-01", 5),
                ("inserted_at.lte", "2024-01-01", 0),
                ("updated_at.gte", "2024-01-01", 5),
                ("updated_at.lte", "2024-01-01", 0),
            ]
        ),
    )
    def test_providers_filters(
        self,
        authenticated_client,
        providers_fixture,
        tenant_header,
        filter_name,
        filter_value,
        expected_count,
    ):
        response = authenticated_client.get(
            reverse("provider-list"),
            {f"filter[{filter_name}]": filter_value},
            headers=tenant_header,
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
    def test_providers_filters_invalid(
        self, authenticated_client, tenant_header, filter_name
    ):
        response = authenticated_client.get(
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
                "uid",
                "alias",
                "connected",
                "inserted_at",
                "updated_at",
            ]
        ),
    )
    def test_providers_sort(self, authenticated_client, tenant_header, sort_field):
        response = authenticated_client.get(
            reverse("provider-list"), {"sort": sort_field}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_200_OK

    def test_providers_sort_invalid(self, authenticated_client, tenant_header):
        response = authenticated_client.get(
            reverse("provider-list"), {"sort": "invalid"}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestScanViewSet:
    def test_scans_list(self, authenticated_client, scans_fixture, tenant_header):
        response = authenticated_client.get(reverse("scan-list"), headers=tenant_header)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(scans_fixture)

    def test_scans_retrieve(self, authenticated_client, scans_fixture, tenant_header):
        scan1, *_ = scans_fixture
        response = authenticated_client.get(
            reverse("scan-detail", kwargs={"pk": scan1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["name"] == scan1.name
        assert response.json()["data"]["relationships"]["provider"]["data"][
            "id"
        ] == str(scan1.provider.id)

    def test_scans_invalid_retrieve(self, authenticated_client, tenant_header):
        response = authenticated_client.get(
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
        authenticated_client,
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

        response = authenticated_client.post(
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
        self,
        authenticated_client,
        tenant_header,
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
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == error_code
        assert (
            response.json()["errors"][0]["source"]["pointer"] == "/data/attributes/name"
        )

    def test_scans_partial_update(
        self, authenticated_client, scans_fixture, tenant_header
    ):
        scan1, *_ = scans_fixture
        new_name = "Updated Scan Name"
        payload = {
            "data": {
                "type": "Scan",
                "id": scan1.id,
                "attributes": {"name": new_name},
            },
        }
        response = authenticated_client.patch(
            reverse("scan-detail", kwargs={"pk": scan1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        scan1.refresh_from_db()
        assert scan1.name == new_name

    def test_scans_partial_update_invalid_content_type(
        self, authenticated_client, scans_fixture, tenant_header
    ):
        scan1, *_ = scans_fixture
        response = authenticated_client.patch(
            reverse("scan-detail", kwargs={"pk": scan1.id}),
            data={},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    def test_scans_partial_update_invalid_content(
        self, authenticated_client, scans_fixture, tenant_header
    ):
        scan1, *_ = scans_fixture
        new_name = "Updated Scan Name"
        payload = {"name": new_name}
        response = authenticated_client.patch(
            reverse("scan-detail", kwargs={"pk": scan1.id}),
            data=payload,
            content_type=API_JSON_CONTENT_TYPE,
            headers=tenant_header,
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
            ]
        ),
    )
    def test_scans_filters(
        self,
        authenticated_client,
        scans_fixture,
        tenant_header,
        filter_name,
        filter_value,
        expected_count,
    ):
        response = authenticated_client.get(
            reverse("scan-list"),
            {f"filter[{filter_name}]": filter_value},
            headers=tenant_header,
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
    def test_scans_filters_invalid(
        self, authenticated_client, tenant_header, filter_name
    ):
        response = authenticated_client.get(
            reverse("scan-list"),
            {f"filter[{filter_name}]": "invalid_value"},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_scan_filter_by_provider_id_exact(
        self, authenticated_client, scans_fixture, tenant_header
    ):
        response = authenticated_client.get(
            reverse("scan-list"),
            {"filter[provider]": scans_fixture[0].provider.id},
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 2

    def test_scan_filter_by_provider_id_in(
        self, authenticated_client, scans_fixture, tenant_header
    ):
        response = authenticated_client.get(
            reverse("scan-list"),
            {
                "filter[provider.in]": [
                    scans_fixture[0].provider.id,
                    scans_fixture[1].provider.id,
                ]
            },
            headers=tenant_header,
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
    def test_scans_sort(self, authenticated_client, tenant_header, sort_field):
        response = authenticated_client.get(
            reverse("scan-list"), {"sort": sort_field}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_200_OK

    def test_scans_sort_invalid(self, authenticated_client, tenant_header):
        response = authenticated_client.get(
            reverse("scan-list"), {"sort": "invalid"}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestTaskViewSet:
    def test_tasks_list(self, authenticated_client, tasks_fixture, tenant_header):
        response = authenticated_client.get(reverse("task-list"), headers=tenant_header)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(tasks_fixture)

    def test_tasks_retrieve(self, authenticated_client, tasks_fixture, tenant_header):
        task1, *_ = tasks_fixture
        response = authenticated_client.get(
            reverse("task-detail", kwargs={"pk": task1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        assert (
            response.json()["data"]["attributes"]["name"]
            == task1.task_runner_task.task_name
        )

    def test_tasks_invalid_retrieve(self, authenticated_client, tenant_header):
        response = authenticated_client.get(
            reverse("task-detail", kwargs={"pk": "invalid_id"}), headers=tenant_header
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @patch("api.v1.views.AsyncResult", return_value=Mock())
    def test_tasks_revoke(
        self, mock_async_result, authenticated_client, tasks_fixture, tenant_header
    ):
        _, task2 = tasks_fixture
        response = authenticated_client.delete(
            reverse("task-detail", kwargs={"pk": task2.id}), headers=tenant_header
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task2.id}"
        mock_async_result.return_value.revoke.assert_called_once()

    def test_tasks_invalid_revoke(self, authenticated_client, tenant_header):
        response = authenticated_client.delete(
            reverse("task-detail", kwargs={"pk": "invalid_id"}), headers=tenant_header
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_tasks_revoke_invalid_status(
        self, authenticated_client, tasks_fixture, tenant_header
    ):
        task1, _ = tasks_fixture
        response = authenticated_client.delete(
            reverse("task-detail", kwargs={"pk": task1.id}), headers=tenant_header
        )
        # Task status is SUCCESS
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestResourceViewSet:
    def test_resources_list_none(self, authenticated_client, tenant_header):
        response = authenticated_client.get(
            reverse("resource-list"), headers=tenant_header
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    def test_resources_list(
        self, authenticated_client, resources_fixture, tenant_header
    ):
        response = authenticated_client.get(
            reverse("resource-list"), headers=tenant_header
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(resources_fixture)
        assert (
            response.json()["data"][0]["attributes"]["uid"] == resources_fixture[0].uid
        )

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
                ("inserted_at.gte", "2024-01-01 00:00:00", 3),
                ("updated_at.lte", "2024-01-01 00:00:00", 0),
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
                ("search", "def1", 1),
                # full text search on resource tags
                ("search", "multi word", 1),
                ("search", "key2", 2),
            ]
        ),
    )
    def test_resource_filters(
        self,
        authenticated_client,
        resources_fixture,
        tenant_header,
        filter_name,
        filter_value,
        expected_count,
    ):
        response = authenticated_client.get(
            reverse("resource-list"),
            {f"filter[{filter_name}]": filter_value},
            headers=tenant_header,
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == expected_count

    def test_resource_filter_by_provider_id_in(
        self, authenticated_client, resources_fixture, tenant_header
    ):
        response = authenticated_client.get(
            reverse("resource-list"),
            {
                "filter[provider.in]": [
                    resources_fixture[0].provider.id,
                    resources_fixture[1].provider.id,
                ]
            },
            headers=tenant_header,
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
    def test_resources_filters_invalid(
        self, authenticated_client, tenant_header, filter_name
    ):
        response = authenticated_client.get(
            reverse("resource-list"),
            {f"filter[{filter_name}]": "whatever"},
            headers=tenant_header,
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
    def test_resources_sort(self, authenticated_client, tenant_header, sort_field):
        response = authenticated_client.get(
            reverse("resource-list"), {"sort": sort_field}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_200_OK

    def test_resources_sort_invalid(self, authenticated_client, tenant_header):
        response = authenticated_client.get(
            reverse("resource-list"), {"sort": "invalid"}, headers=tenant_header
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "invalid"
        assert response.json()["errors"][0]["source"]["pointer"] == "/data"
        assert (
            response.json()["errors"][0]["detail"] == "invalid sort parameter: invalid"
        )

    def test_resources_retrieve(
        self, authenticated_client, resources_fixture, tenant_header
    ):
        resource_1, *_ = resources_fixture
        response = authenticated_client.get(
            reverse("resource-detail", kwargs={"pk": resource_1.id}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["uid"] == resource_1.uid
        assert response.json()["data"]["attributes"]["name"] == resource_1.name
        assert response.json()["data"]["attributes"]["region"] == resource_1.region
        assert response.json()["data"]["attributes"]["service"] == resource_1.service
        assert response.json()["data"]["attributes"]["type"] == resource_1.type
        assert response.json()["data"]["attributes"]["tags"] == resource_1.get_tags()

    def test_resources_invalid_retrieve(self, authenticated_client, tenant_header):
        response = authenticated_client.get(
            reverse("resource-detail", kwargs={"pk": "random_id"}),
            headers=tenant_header,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
