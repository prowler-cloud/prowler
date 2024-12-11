import pytest
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch, ANY, Mock


@pytest.mark.django_db
class TestUserViewSet:
    def test_list_users_with_all_permissions(self, authenticated_client_rbac):
        response = authenticated_client_rbac.get(reverse("user-list"))
        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.json()["data"], list)

    def test_list_users_with_no_permissions(
        self, authenticated_client_no_permissions_rbac
    ):
        response = authenticated_client_no_permissions_rbac.get(reverse("user-list"))
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_retrieve_user_with_all_permissions(
        self, authenticated_client_rbac, create_test_user_rbac
    ):
        response = authenticated_client_rbac.get(
            reverse("user-detail", kwargs={"pk": create_test_user_rbac.id})
        )
        assert response.status_code == status.HTTP_200_OK
        assert (
            response.json()["data"]["attributes"]["email"]
            == create_test_user_rbac.email
        )

    def test_retrieve_user_with_no_roles(
        self, authenticated_client_rbac_noroles, create_test_user_rbac_no_roles
    ):
        response = authenticated_client_rbac_noroles.get(
            reverse("user-detail", kwargs={"pk": create_test_user_rbac_no_roles.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_retrieve_user_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, create_test_user
    ):
        response = authenticated_client_no_permissions_rbac.get(
            reverse("user-detail", kwargs={"pk": create_test_user.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_create_user_with_all_permissions(self, authenticated_client_rbac):
        valid_user_payload = {
            "name": "test",
            "password": "newpassword123",
            "email": "new_user@test.com",
        }
        response = authenticated_client_rbac.post(
            reverse("user-list"), data=valid_user_payload, format="vnd.api+json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["data"]["attributes"]["email"] == "new_user@test.com"

    def test_create_user_with_no_permissions(
        self, authenticated_client_no_permissions_rbac
    ):
        valid_user_payload = {
            "name": "test",
            "password": "newpassword123",
            "email": "new_user@test.com",
        }
        response = authenticated_client_no_permissions_rbac.post(
            reverse("user-list"), data=valid_user_payload, format="vnd.api+json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["data"]["attributes"]["email"] == "new_user@test.com"

    def test_partial_update_user_with_all_permissions(
        self, authenticated_client_rbac, create_test_user_rbac
    ):
        updated_data = {
            "data": {
                "type": "users",
                "id": str(create_test_user_rbac.id),
                "attributes": {"name": "Updated Name"},
            },
        }
        response = authenticated_client_rbac.patch(
            reverse("user-detail", kwargs={"pk": create_test_user_rbac.id}),
            data=updated_data,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["name"] == "Updated Name"

    def test_partial_update_user_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, create_test_user
    ):
        updated_data = {
            "data": {
                "type": "users",
                "attributes": {"name": "Updated Name"},
            }
        }
        response = authenticated_client_no_permissions_rbac.patch(
            reverse("user-detail", kwargs={"pk": create_test_user.id}),
            data=updated_data,
            format="vnd.api+json",
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_delete_user_with_all_permissions(
        self, authenticated_client_rbac, create_test_user_rbac
    ):
        response = authenticated_client_rbac.delete(
            reverse("user-detail", kwargs={"pk": create_test_user_rbac.id})
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_delete_user_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, create_test_user
    ):
        response = authenticated_client_no_permissions_rbac.delete(
            reverse("user-detail", kwargs={"pk": create_test_user.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_me_with_all_permissions(
        self, authenticated_client_rbac, create_test_user_rbac
    ):
        response = authenticated_client_rbac.get(reverse("user-me"))
        assert response.status_code == status.HTTP_200_OK
        assert (
            response.json()["data"]["attributes"]["email"]
            == create_test_user_rbac.email
        )

    def test_me_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, create_test_user
    ):
        response = authenticated_client_no_permissions_rbac.get(reverse("user-me"))
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["email"] == "rbac_limited@rbac.com"


@pytest.mark.django_db
class TestProviderViewSet:
    def test_list_providers_with_all_permissions(
        self, authenticated_client_rbac, providers_fixture
    ):
        response = authenticated_client_rbac.get(reverse("provider-list"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == len(providers_fixture)

    def test_list_providers_with_no_permissions(
        self, authenticated_client_no_permissions_rbac
    ):
        response = authenticated_client_no_permissions_rbac.get(
            reverse("provider-list")
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["data"]) == 0

    def test_retrieve_provider_with_all_permissions(
        self, authenticated_client_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        response = authenticated_client_rbac.get(
            reverse("provider-detail", kwargs={"pk": provider.id})
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["alias"] == provider.alias

    def test_retrieve_provider_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        response = authenticated_client_no_permissions_rbac.get(
            reverse("provider-detail", kwargs={"pk": provider.id})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_create_provider_with_all_permissions(self, authenticated_client_rbac):
        payload = {"provider": "aws", "uid": "111111111111", "alias": "new_alias"}
        response = authenticated_client_rbac.post(
            reverse("provider-list"), data=payload, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["data"]["attributes"]["alias"] == "new_alias"

    def test_create_provider_with_no_permissions(
        self, authenticated_client_no_permissions_rbac
    ):
        payload = {"provider": "aws", "uid": "111111111111", "alias": "new_alias"}
        response = authenticated_client_no_permissions_rbac.post(
            reverse("provider-list"), data=payload, format="json"
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_partial_update_provider_with_all_permissions(
        self, authenticated_client_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        payload = {
            "data": {
                "type": "providers",
                "id": provider.id,
                "attributes": {"alias": "updated_alias"},
            },
        }
        response = authenticated_client_rbac.patch(
            reverse("provider-detail", kwargs={"pk": provider.id}),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["alias"] == "updated_alias"

    def test_partial_update_provider_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        update_payload = {
            "data": {
                "type": "providers",
                "attributes": {"alias": "updated_alias"},
            }
        }
        response = authenticated_client_no_permissions_rbac.patch(
            reverse("provider-detail", kwargs={"pk": provider.id}),
            data=update_payload,
            format="vnd.api+json",
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.delete_provider_task.delay")
    def test_delete_provider_with_all_permissions(
        self,
        mock_delete_task,
        mock_task_get,
        authenticated_client_rbac,
        providers_fixture,
        tasks_fixture,
    ):
        prowler_task = tasks_fixture[0]
        task_mock = Mock()
        task_mock.id = prowler_task.id
        mock_delete_task.return_value = task_mock
        mock_task_get.return_value = prowler_task

        provider1, *_ = providers_fixture
        response = authenticated_client_rbac.delete(
            reverse("provider-detail", kwargs={"pk": provider1.id})
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        mock_delete_task.assert_called_once_with(
            provider_id=str(provider1.id), tenant_id=ANY
        )
        assert "Content-Location" in response.headers
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task_mock.id}"

    def test_delete_provider_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        response = authenticated_client_no_permissions_rbac.delete(
            reverse("provider-detail", kwargs={"pk": provider.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.check_provider_connection_task.delay")
    def test_connection_with_all_permissions(
        self,
        mock_provider_connection,
        mock_task_get,
        authenticated_client_rbac,
        providers_fixture,
        tasks_fixture,
    ):
        prowler_task = tasks_fixture[0]
        task_mock = Mock()
        task_mock.id = prowler_task.id
        task_mock.status = "PENDING"
        mock_provider_connection.return_value = task_mock
        mock_task_get.return_value = prowler_task

        provider1, *_ = providers_fixture
        assert provider1.connected is None
        assert provider1.connection_last_checked_at is None

        response = authenticated_client_rbac.post(
            reverse("provider-connection", kwargs={"pk": provider1.id})
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        mock_provider_connection.assert_called_once_with(
            provider_id=str(provider1.id), tenant_id=ANY
        )
        assert "Content-Location" in response.headers
        assert response.headers["Content-Location"] == f"/api/v1/tasks/{task_mock.id}"

    def test_connection_with_no_permissions(
        self, authenticated_client_no_permissions_rbac, providers_fixture
    ):
        provider = providers_fixture[0]
        response = authenticated_client_no_permissions_rbac.post(
            reverse("provider-connection", kwargs={"pk": provider.id})
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
