from unittest.mock import Mock, patch

import pytest
from conftest import get_api_tokens, get_authorization_header
from django.urls import reverse
from rest_framework.test import APIClient

from api.models import Provider


@patch("api.db_router.MainRouter.admin_db", new="default")
@patch("api.v1.views.Task.objects.get")
@patch("api.v1.views.delete_provider_task.delay")
@pytest.mark.django_db
def test_delete_provider_without_executing_task(
    mock_delete_task, mock_task_get, create_test_user, tenants_fixture, tasks_fixture
):
    client = APIClient()

    test_user = "test_email@prowler.com"
    test_password = "test_password"

    prowler_task = tasks_fixture[0]
    task_mock = Mock()
    task_mock.id = prowler_task.id
    mock_delete_task.return_value = task_mock
    mock_task_get.return_value = prowler_task

    user_creation_response = client.post(
        reverse("user-list"),
        data={
            "data": {
                "type": "users",
                "attributes": {
                    "name": "test",
                    "email": test_user,
                    "password": test_password,
                },
            }
        },
        format="vnd.api+json",
    )
    assert user_creation_response.status_code == 201

    access_token, _ = get_api_tokens(client, test_user, test_password)
    auth_headers = get_authorization_header(access_token)

    create_provider_response = client.post(
        reverse("provider-list"),
        data={
            "data": {
                "type": "providers",
                "attributes": {
                    "provider": Provider.ProviderChoices.AWS,
                    "uid": "123456789012",
                },
            }
        },
        format="vnd.api+json",
        headers=auth_headers,
    )
    assert create_provider_response.status_code == 201
    provider_id = create_provider_response.json()["data"]["id"]
    provider_uid = create_provider_response.json()["data"]["attributes"]["uid"]

    remove_provider = client.delete(
        reverse("provider-detail", kwargs={"pk": provider_id}),
        headers=auth_headers,
    )
    assert remove_provider.status_code == 202

    recreate_provider_response = client.post(
        reverse("provider-list"),
        data={
            "data": {
                "type": "providers",
                "attributes": {
                    "provider": Provider.ProviderChoices.AWS,
                    "uid": provider_uid,
                },
            }
        },
        format="vnd.api+json",
        headers=auth_headers,
    )
    assert recreate_provider_response.status_code == 201
