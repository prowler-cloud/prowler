from datetime import datetime, timezone

from celery.utils.log import get_task_logger
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider

from api.models import Provider

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
    match provider_instance.provider:
        # TODO Refactor when proper credentials are implemented
        case Provider.ProviderChoices.AWS.value:
            prowler_provider = AwsProvider
        case Provider.ProviderChoices.GCP.value:
            prowler_provider = GcpProvider
        case Provider.ProviderChoices.AZURE.value:
            prowler_provider = AzureProvider
        case Provider.ProviderChoices.KUBERNETES.value:
            prowler_provider = KubernetesProvider
        case _:
            raise ValueError(
                f"Provider type {provider_instance.provider} not supported"
            )
    try:
        connection_result = prowler_provider.test_connection(raise_on_exception=False)
    except Exception as e:
        logger.warning(
            f"Unexpected exception checking {provider_instance.provider} provider connection: {str(e)}"
        )
        raise e

    provider_instance.connected = connection_result.is_connected
    provider_instance.connection_last_checked_at = datetime.now(tz=timezone.utc)
    provider_instance.save()

    connection_error = (
        f"{connection_result.error.__class__.__name__}: {connection_result.error}"
        if connection_result.error
        else None
    )
    return {"connected": connection_result.is_connected, "error": connection_error}
