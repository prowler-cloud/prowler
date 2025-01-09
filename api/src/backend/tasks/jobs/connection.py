from datetime import datetime, timezone

from celery.utils.log import get_task_logger

from api.models import Provider
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
