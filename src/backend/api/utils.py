from datetime import datetime, timezone

from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.common.models import Connection
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from rest_framework.exceptions import ValidationError, NotFound

from api.db_router import MainRouter
from api.exceptions import InvitationTokenExpiredException
from api.models import Provider, Invitation


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


def get_prowler_provider_kwargs(provider: Provider) -> dict:
    """Get the Prowler provider kwargs based on the given provider type.

    Args:
        provider (Provider): The provider object containing the provider type and associated secret.

    Returns:
        dict: The provider kwargs for the corresponding provider class.
    """
    prowler_provider_kwargs = provider.secret.secret
    if provider.provider == Provider.ProviderChoices.AZURE.value:
        prowler_provider_kwargs = {
            **prowler_provider_kwargs,
            "subscription_ids": [provider.uid],
        }
    elif provider.provider == Provider.ProviderChoices.GCP.value:
        prowler_provider_kwargs = {
            **prowler_provider_kwargs,
            "project_ids": [provider.uid],
        }
    elif provider.provider == Provider.ProviderChoices.KUBERNETES.value:
        prowler_provider_kwargs = {**prowler_provider_kwargs, "context": provider.uid}
    return prowler_provider_kwargs


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
    prowler_provider_kwargs = get_prowler_provider_kwargs(provider)
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


def validate_invitation(
    invitation_token: str, email: str, raise_not_found=False
) -> Invitation:
    """
    Validates an invitation based on the provided token and email.

    This function attempts to retrieve an Invitation object using the given
    `invitation_token` and `email`. It performs several checks to ensure that
    the invitation is valid, not expired, and in the correct state for acceptance.

    Args:
        invitation_token (str): The token associated with the invitation.
        email (str): The email address associated with the invitation.
        raise_not_found (bool, optional): If True, raises a `NotFound` exception
            when the invitation is not found. If False, raises a `ValidationError`.
            Defaults to False.

    Returns:
        Invitation: The validated Invitation object.

    Raises:
        NotFound: If `raise_not_found` is True and the invitation does not exist.
        ValidationError: If the invitation does not exist and `raise_not_found`
            is False, or if the invitation is invalid or in an incorrect state.
        InvitationTokenExpiredException: If the invitation has expired.

    Notes:
        - This function uses the admin database connector to bypass RLS protection
          since the invitation may belong to a tenant the user is not a member of yet.
        - If the invitation has expired, its state is updated to EXPIRED, and an
          `InvitationTokenExpiredException` is raised.
        - Only invitations in the PENDING state can be accepted.

    Examples:
        invitation = validate_invitation("TOKEN123", "user@example.com")
    """
    try:
        # Admin DB connector is used to bypass RLS protection since the invitation belongs to a tenant the user
        # is not a member of yet
        invitation = Invitation.objects.using(MainRouter.admin_db).get(
            token=invitation_token, email=email
        )
    except Invitation.DoesNotExist:
        if raise_not_found:
            raise NotFound(detail="Invitation is not valid.")
        else:
            raise ValidationError({"invitation_token": "Invalid invitation code."})

    # Check if the invitation has expired
    if invitation.expires_at < datetime.now(timezone.utc):
        invitation.state = Invitation.State.EXPIRED
        invitation.save(using=MainRouter.admin_db)
        raise InvitationTokenExpiredException()

    # Check the state of the invitation
    if invitation.state != Invitation.State.PENDING:
        raise ValidationError(
            {"invitation_token": "This invitation is no longer valid."}
        )

    return invitation
