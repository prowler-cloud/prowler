from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.common.models import Connection
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider

from api.models import Provider


def merge_dicts(default_dict: dict, replacement_dict: dict) -> dict:
    """
    Recursively merge two dictionaries, using `default_dict` as the base and `replacement_dict` for overriding values.

    Args:
        default_dict (dict): The base dictionary containing default key-value pairs.
        replacement_dict (dict): The dictionary containing values that should override those in `default_dict`.

    Returns:
        dict: A new dictionary containing all keys from `default_dict` with values from `replacement_dict` replacing
              any overlapping keys. If a key in both `default_dict` and `replacement_dict` contains dictionaries,
              this function will merge them recursively.
    """
    result = default_dict.copy()

    for key, value in replacement_dict.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            if value:
                result[key] = merge_dicts(result[key], value)
            else:
                result[key] = value
        else:
            result[key] = value

    return result


def return_prowler_provider(
    provider: Provider,
) -> [AwsProvider | AzureProvider | GcpProvider | KubernetesProvider]:
    """Return the Prowler provider class based on the given provider type.

    Args:
        provider (Provider): The provider object containing the provider type and associated secrets.

    Returns:
        AwsProvider | AzureProvider | GcpProvider | KubernetesProvider: The corresponding provider class.

    Raises:
        ValueError: If the provider type specified in `provider.provider` is not supported.
    """
    match provider.provider:
        case Provider.ProviderChoices.AWS.value:
            prowler_provider = AwsProvider
        case Provider.ProviderChoices.GCP.value:
            prowler_provider = GcpProvider
        case Provider.ProviderChoices.AZURE.value:
            prowler_provider = AzureProvider
        case Provider.ProviderChoices.KUBERNETES.value:
            prowler_provider = KubernetesProvider
        case _:
            raise ValueError(f"Provider type {provider.provider} not supported")
    return prowler_provider


def initialize_prowler_provider(
    provider: Provider,
) -> AwsProvider | AzureProvider | GcpProvider | KubernetesProvider:
    """Initialize a Prowler provider instance based on the given provider type.

    Args:
        provider (Provider): The provider object containing the provider type and associated secrets.

    Returns:
        AwsProvider | AzureProvider | GcpProvider | KubernetesProvider: An instance of the corresponding provider class
            (`AwsProvider`, `AzureProvider`, `GcpProvider`, or `KubernetesProvider`) initialized with the
            provider's secrets.
    """
    prowler_provider = return_prowler_provider(provider)
    prowler_provider_kwargs = provider.secret.secret
    return prowler_provider(**prowler_provider_kwargs)


def prowler_provider_connection_test(provider: Provider) -> Connection:
    """Test the connection to a Prowler provider based on the given provider type.

    Args:
        provider (Provider): The provider object containing the provider type and associated secrets.

    Returns:
        Connection: A connection object representing the result of the connection test for the specified provider.
    """
    prowler_provider = return_prowler_provider(provider)
    prowler_provider_kwargs = provider.secret.secret
    return prowler_provider.test_connection(
        **prowler_provider_kwargs, provider_id=provider.uid, raise_on_exception=False
    )
