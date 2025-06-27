from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from tasks.jobs.connection import check_lighthouse_connection, check_provider_connection

from api.models import LighthouseConfiguration, Provider


@pytest.mark.parametrize(
    "provider_data",
    [
        {"provider": "aws", "uid": "123456789012", "alias": "aws"},
    ],
)
@patch("tasks.jobs.connection.prowler_provider_connection_test")
@pytest.mark.django_db
def test_check_provider_connection(
    mock_provider_connection_test, tenants_fixture, provider_data
):
    provider = Provider.objects.create(**provider_data, tenant_id=tenants_fixture[0].id)

    mock_test_connection_result = MagicMock()
    mock_test_connection_result.is_connected = True

    mock_provider_connection_test.return_value = mock_test_connection_result

    check_provider_connection(
        provider_id=str(provider.id),
    )
    provider.refresh_from_db()

    mock_provider_connection_test.assert_called_once()
    assert provider.connected is True
    assert provider.connection_last_checked_at is not None
    assert provider.connection_last_checked_at <= datetime.now(tz=timezone.utc)


@patch("tasks.jobs.connection.Provider.objects.get")
@pytest.mark.django_db
def test_check_provider_connection_unsupported_provider(mock_provider_get):
    mock_provider_instance = MagicMock()
    mock_provider_instance.provider = "UNSUPPORTED_PROVIDER"
    mock_provider_get.return_value = mock_provider_instance

    with pytest.raises(
        ValueError, match="Provider type UNSUPPORTED_PROVIDER not supported"
    ):
        check_provider_connection("provider_id")


@patch("tasks.jobs.connection.Provider.objects.get")
@patch("tasks.jobs.connection.prowler_provider_connection_test")
@pytest.mark.django_db
def test_check_provider_connection_exception(
    mock_provider_connection_test, mock_provider_get
):
    mock_provider_instance = MagicMock()
    mock_provider_instance.provider = Provider.ProviderChoices.AWS.value
    mock_provider_get.return_value = mock_provider_instance

    mock_provider_connection_test.return_value = MagicMock()
    mock_provider_connection_test.return_value.is_connected = False
    mock_provider_connection_test.return_value.error = Exception()

    result = check_provider_connection(provider_id="provider_id")

    assert result["connected"] is False
    assert result["error"] is not None

    mock_provider_instance.save.assert_called_once()
    assert mock_provider_instance.connected is False


@pytest.mark.parametrize(
    "lighthouse_data",
    [
        {
            "name": "OpenAI",
            "api_key_decoded": "sk-test1234567890T3BlbkFJtest1234567890",
            "model": "gpt-4o",
            "temperature": 0,
            "max_tokens": 4000,
            "business_context": "Test business context",
            "is_active": True,
        },
    ],
)
@patch("tasks.jobs.connection.openai.OpenAI")
@pytest.mark.django_db
def test_check_lighthouse_connection(
    mock_openai_client, tenants_fixture, lighthouse_data
):
    lighthouse_config = LighthouseConfiguration.objects.create(
        **lighthouse_data, tenant_id=tenants_fixture[0].id
    )

    mock_models = MagicMock()
    mock_models.data = [MagicMock(id="gpt-4o"), MagicMock(id="gpt-4o-mini")]
    mock_openai_client.return_value.models.list.return_value = mock_models

    result = check_lighthouse_connection(
        lighthouse_config_id=str(lighthouse_config.id),
    )
    lighthouse_config.refresh_from_db()

    mock_openai_client.assert_called_once_with(
        api_key=lighthouse_data["api_key_decoded"]
    )
    assert lighthouse_config.is_active is True
    assert result["connected"] is True
    assert result["error"] is None
    assert result["available_models"] == ["gpt-4o", "gpt-4o-mini"]


@patch("tasks.jobs.connection.LighthouseConfiguration.objects.get")
@pytest.mark.django_db
def test_check_lighthouse_connection_missing_api_key(mock_lighthouse_get):
    mock_lighthouse_instance = MagicMock()
    mock_lighthouse_instance.api_key_decoded = None
    mock_lighthouse_get.return_value = mock_lighthouse_instance

    result = check_lighthouse_connection("lighthouse_config_id")

    assert result["connected"] is False
    assert result["error"] == "API key is invalid or missing."
    assert result["available_models"] == []
    assert mock_lighthouse_instance.is_active is False
    mock_lighthouse_instance.save.assert_called_once()
