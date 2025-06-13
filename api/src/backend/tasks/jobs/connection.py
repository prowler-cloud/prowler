from datetime import datetime, timezone

import openai
from celery.utils.log import get_task_logger

from api.models import LighthouseConfiguration, Provider
from api.utils import prowler_provider_connection_test

logger = get_task_logger(__name__)


def check_provider_connection(provider_id: str):
    """
    Business logic to check the connection status of a provider.

    Args:
        provider_id (str): The primary key of the Provider instance to check.

    Returns:
        dict: A dictionary containing:
            - 'connected' (bool): Indicates whether the provider is successfully connected.
            - 'error' (str or None): The error message if the connection failed, otherwise `None`.

    Raises:
        ValueError: If the provider type is not supported.
        Model.DoesNotExist: If the provider does not exist.
    """
    provider_instance = Provider.objects.get(pk=provider_id)
    try:
        connection_result = prowler_provider_connection_test(provider_instance)
    except Exception as e:
        logger.warning(
            f"Unexpected exception checking {provider_instance.provider} provider connection: {str(e)}"
        )
        raise e

    provider_instance.connected = connection_result.is_connected
    provider_instance.connection_last_checked_at = datetime.now(tz=timezone.utc)
    provider_instance.save()

    connection_error = f"{connection_result.error}" if connection_result.error else None
    return {"connected": connection_result.is_connected, "error": connection_error}


def check_lighthouse_connection(lighthouse_config_id: str):
    """
    Business logic to check the connection status of a Lighthouse configuration.

    Args:
        lighthouse_config_id (str): The primary key of the LighthouseConfiguration instance to check.

    Returns:
        dict: A dictionary containing:
            - 'connected' (bool): Indicates whether the connection is successful.
            - 'error' (str or None): The error message if the connection failed, otherwise `None`.
            - 'available_models' (list): List of available models if connection is successful.

    Raises:
        Model.DoesNotExist: If the lighthouse configuration does not exist.
    """
    lighthouse_config = LighthouseConfiguration.objects.get(pk=lighthouse_config_id)

    if not lighthouse_config.api_key_decoded:
        lighthouse_config.is_active = False
        lighthouse_config.save()
        return {
            "connected": False,
            "error": "API key is invalid or missing.",
            "available_models": [],
        }

    try:
        client = openai.OpenAI(api_key=lighthouse_config.api_key_decoded)
        models = client.models.list()
        lighthouse_config.is_active = True
        lighthouse_config.save()
        return {
            "connected": True,
            "error": None,
            "available_models": [model.id for model in models.data],
        }
    except Exception as e:
        lighthouse_config.is_active = False
        lighthouse_config.save()
        return {"connected": False, "error": str(e), "available_models": []}
